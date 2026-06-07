//! replicorectl — operator CLI over the daemon's Unix domain socket.
//!
//! Each invocation opens the socket, sends one request, prints the reply, and
//! exits. Membership mutations are signed CLIENT-side with the admin secret
//! (`--admin-key`) — the daemon never holds it (FR-1305): the CLI first asks the
//! daemon to `PrepareEntry` (next epoch; current addr/fingerprint for a remove),
//! signs locally, then submits the signed entry.
//!
//! Usage:
//!   replicorectl [--socket PATH | --config FILE] <command> [--json]
//!
//!   status [--all]                 members | peers | lag | conflicts
//!   transfers | version
//!   config validate <file> | config diff <file> | config reload <file>
//!   member add <node_id> <addr> <fingerprint> --admin-key <path>
//!   member remove <node_id> --admin-key <path>
//!   resync [<node_id>] | pause | resume | bandwidth ...

use std::path::PathBuf;
use std::process::ExitCode;

use replicore::admin::{sign_entry, AdminSecret, EntryKind};
use replicore::config::Config;
use replicore::control::{CtlRequest, CtlResponse};
use replicore::membership::SignedEntry;
use replicore::proto::{read_msg, write_msg};
use replicore::vv::NodeId;
use tokio::net::UnixStream;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode, String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let json = take_flag(&mut args, "--json");
    let socket = resolve_socket(&mut args)?;

    let mut pos = args.into_iter();
    let cmd = pos.next().ok_or_else(usage)?;
    let rest: Vec<String> = pos.collect();

    // Commands that issue a single request:
    let single: Option<CtlRequest> = match (cmd.as_str(), rest.as_slice()) {
        ("status", r) => Some(CtlRequest::Status {
            all: r.iter().any(|a| a == "--all"),
        }),
        ("members", _) => Some(CtlRequest::Members),
        ("peers", _) => Some(CtlRequest::Peers),
        ("lag", _) => Some(CtlRequest::Lag),
        ("conflicts", _) => Some(CtlRequest::Conflicts),
        ("transfers", _) => Some(CtlRequest::Transfers),
        ("version", _) => Some(CtlRequest::Version),
        ("pause", _) => Some(CtlRequest::Pause),
        ("resume", _) => Some(CtlRequest::Resume),
        ("bandwidth", []) => Some(CtlRequest::Bandwidth { set: None }),
        ("bandwidth", r) if r.len() == 3 && r[0] == "set" => Some(CtlRequest::Bandwidth {
            set: Some((parse_bps(&r[1])?, parse_bps(&r[2])?)),
        }),
        ("resync", r) => Some(CtlRequest::Resync {
            node: r.first().map(|s| parse_node_id(s)).transpose()?,
        }),
        ("config", r) => Some(config_request(r)?),
        _ => None,
    };

    if let Some(req) = single {
        let resp = roundtrip(&socket, &req).await?;
        return Ok(render(&resp, json));
    }

    // member add/remove: prepare (server) -> sign (client) -> submit.
    if cmd == "member" {
        let resp = member_command(&socket, &rest).await?;
        return Ok(render(&resp, json));
    }

    Err(usage())
}

fn usage() -> String {
    "usage: replicorectl [--socket PATH | --config FILE] <command> [--json]\n  \
     status [--all] | members | peers | lag | conflicts | transfers | version\n  \
     config validate|diff|reload <file>\n  \
     member add <node_id> <addr> <fingerprint> --admin-key <path>\n  \
     member remove <node_id> --admin-key <path>\n  \
     resync [<node_id>] | pause | resume
  \
     bandwidth [set <global_bps> <per_peer_bps>]   (0 = unlimited)"
        .to_string()
}

/// Bytes/sec with optional k/m/g suffix (decimal); 0 = unlimited.
fn parse_bps(s: &str) -> Result<u64, String> {
    let (num, mult) = match s.to_ascii_lowercase() {
        ref v if v.ends_with('k') => (v[..v.len() - 1].to_string(), 1_000),
        ref v if v.ends_with('m') => (v[..v.len() - 1].to_string(), 1_000_000),
        ref v if v.ends_with('g') => (v[..v.len() - 1].to_string(), 1_000_000_000),
        v => (v, 1),
    };
    num.parse::<u64>()
        .map(|n| n * mult)
        .map_err(|_| format!("not a rate: {s} (use bytes/sec, k/m/g suffixes, 0 = unlimited)"))
}

fn config_request(r: &[String]) -> Result<CtlRequest, String> {
    let sub = r
        .first()
        .ok_or("config needs validate|diff|reload <file>")?;
    let file = r.get(1).ok_or("config needs a file path")?.clone();
    match sub.as_str() {
        "validate" => Ok(CtlRequest::ConfigValidate { path: file }),
        "diff" => Ok(CtlRequest::ConfigDiff { path: file }),
        "reload" => Ok(CtlRequest::ConfigReload { path: file }),
        other => Err(format!("unknown config subcommand: {other}")),
    }
}

async fn member_command(socket: &PathBuf, rest: &[String]) -> Result<CtlResponse, String> {
    let sub = rest.first().ok_or("member needs add|remove")?.as_str();
    let mut rest: Vec<String> = rest[1..].to_vec();
    let admin_key =
        take_value(&mut rest, "--admin-key").ok_or("member add/remove needs --admin-key <path>")?;
    let sk = AdminSecret::load(std::path::Path::new(&admin_key))
        .map_err(|e| format!("load admin key: {e}"))?;

    let node = parse_node_id(rest.first().ok_or("member needs <node_id>")?)?;
    let prepared = roundtrip(socket, &CtlRequest::PrepareEntry { node }).await?;
    let CtlResponse::Prepared {
        epoch,
        addr,
        fingerprint,
    } = prepared
    else {
        return Err(format!("unexpected reply to PrepareEntry: {prepared:?}"));
    };

    let (addr, fp, kind, req_kind): (std::net::SocketAddr, [u8; 32], EntryKind, bool) = match sub {
        "add" => {
            // add <node_id> <addr> <fingerprint>
            let addr = rest
                .get(1)
                .ok_or("member add needs <addr>")?
                .parse()
                .map_err(|_| "bad addr".to_string())?;
            let fp = parse_fingerprint(rest.get(2).ok_or("member add needs <fingerprint>")?)?;
            (addr, fp, EntryKind::Add, true)
        }
        "remove" => {
            // The daemon supplies the current addr/fingerprint to sign over.
            let addr = addr
                .ok_or("unknown member (nothing to remove)")?
                .parse()
                .map_err(|_| "daemon returned bad addr".to_string())?;
            let fp = parse_fingerprint(&fingerprint.ok_or("unknown member (nothing to remove)")?)?;
            (addr, fp, EntryKind::Remove, false)
        }
        other => return Err(format!("unknown member subcommand: {other}")),
    };

    let sig = sign_entry(&sk, &node, &addr, &fp, epoch, kind);
    let entry = SignedEntry {
        node_id: node,
        addr,
        fingerprint: fp,
        epoch,
        kind,
        sig,
    };
    let req = if req_kind {
        CtlRequest::MemberAdd(entry)
    } else {
        CtlRequest::MemberRemove(entry)
    };
    roundtrip(socket, &req).await
}

async fn roundtrip(socket: &PathBuf, req: &CtlRequest) -> Result<CtlResponse, String> {
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|e| format!("connect {}: {e}", socket.display()))?;
    write_msg(&mut stream, req)
        .await
        .map_err(|e| format!("send: {e}"))?;
    read_msg(&mut stream)
        .await
        .map_err(|e| format!("recv: {e}"))
}

// -- rendering --------------------------------------------------------------

fn render(resp: &CtlResponse, json: bool) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(resp) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("json: {e}");
                return ExitCode::FAILURE;
            }
        }
        return exit_code(resp);
    }
    match resp {
        CtlResponse::Status(s) => {
            print_status(&s.local, "");
            for p in &s.peers {
                if let Some(st) = &p.status {
                    print_status(st, "  ");
                } else {
                    println!("  peer {}  UNREACHABLE", short(&p.node_id));
                }
            }
        }
        CtlResponse::Members(ms) => {
            println!("{:<12} {:<22} {:<8} {:<6}", "NODE", "ADDR", "EPOCH", "KIND");
            for m in ms {
                println!(
                    "{:<12} {:<22} {:<8} {}",
                    short(&m.node_id),
                    m.addr,
                    m.epoch,
                    m.kind
                );
            }
        }
        CtlResponse::Peers(ps) => {
            println!("{:<12} {:<14} {:<9}", "NODE", "STATE", "CONNECTED");
            for p in ps {
                println!("{:<12} {:<14} {}", short(&p.node_id), p.state, p.connected);
            }
        }
        CtlResponse::Lag(ls) => {
            println!(
                "{:<12} {:<12} {:<12} {:<8}",
                "NODE", "RECV_CUR", "THEY_ACK", "OUR_SEQ"
            );
            for l in ls {
                println!(
                    "{:<12} {:<12} {:<12} {}",
                    short(&l.node_id),
                    l.recv_cursor,
                    l.last_acked,
                    l.our_latest
                );
            }
        }
        CtlResponse::Conflicts(n) => println!("conflicts: {n}"),
        CtlResponse::Bandwidth {
            global_bps,
            per_peer_bps,
        } => {
            let show = |v: &u64| {
                if *v == 0 {
                    "unlimited".to_string()
                } else {
                    format!("{v} B/s")
                }
            };
            println!(
                "global={} per_peer={}",
                show(global_bps),
                show(per_peer_bps)
            );
        }
        CtlResponse::Transfers(t) => {
            println!(
                "inflight={} chunks_fetched={} chunks_served={} bytes_in={} bytes_out={}",
                t.inflight, t.chunks_fetched, t.chunks_served, t.bytes_in, t.bytes_out
            );
        }
        CtlResponse::Version(v) => {
            println!(
                "node={} proto=v{} replicore {}",
                short(&v.node_id),
                v.proto_version,
                v.pkg_version
            );
        }
        CtlResponse::Diff(changes) => {
            if changes.is_empty() {
                println!("no differences");
            }
            for c in changes {
                let tag = if c.hot { "HOT" } else { "RESTART" };
                println!("[{}] {}: {:?} -> {:?}", tag, c.field, c.old, c.new);
            }
        }
        CtlResponse::Prepared { .. } => println!("{resp:?}"),
        CtlResponse::Ok(m) => println!("{m}"),
        CtlResponse::Error(m) => eprintln!("error: {m}"),
    }
    exit_code(resp)
}

fn print_status(s: &replicore::control::NodeStatus, indent: &str) {
    println!(
        "{indent}node={} lifecycle={} members={} live_peers={} conflicts={} inflight={} paused={} proto=v{} roster={}",
        short(&s.node_id),
        s.lifecycle,
        s.effective_members,
        s.live_peers,
        s.conflicts,
        s.inflight_transfers,
        s.paused,
        s.proto_version,
        short(&s.roster_digest),
    );
}

fn exit_code(resp: &CtlResponse) -> ExitCode {
    match resp {
        CtlResponse::Error(_) => ExitCode::FAILURE,
        _ => ExitCode::SUCCESS,
    }
}

fn short(hex: &str) -> String {
    hex.chars().take(8).collect()
}

// -- arg helpers ------------------------------------------------------------

fn resolve_socket(args: &mut Vec<String>) -> Result<PathBuf, String> {
    if let Some(s) = take_value(args, "--socket") {
        return Ok(PathBuf::from(s));
    }
    if let Some(c) = take_value(args, "--config") {
        let cfg =
            Config::load(std::path::Path::new(&c)).map_err(|e| format!("load config: {e}"))?;
        return Ok(cfg.control_socket);
    }
    Err("need --socket PATH or --config FILE to locate the control socket".into())
}

fn take_flag(args: &mut Vec<String>, name: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == name) {
        args.remove(i);
        true
    } else {
        false
    }
}

fn take_value(args: &mut Vec<String>, name: &str) -> Option<String> {
    let i = args.iter().position(|a| a == name)?;
    if i + 1 >= args.len() {
        return None;
    }
    let val = args.remove(i + 1);
    args.remove(i);
    Some(val)
}

fn parse_node_id(s: &str) -> Result<NodeId, String> {
    let b = hex::decode(s).map_err(|_| format!("bad node_id (not hex): {s}"))?;
    b.try_into()
        .map_err(|_| format!("node_id must be 16 bytes: {s}"))
}

fn parse_fingerprint(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s).map_err(|_| format!("bad fingerprint (not hex): {s}"))?;
    b.try_into()
        .map_err(|_| format!("fingerprint must be 32 bytes: {s}"))
}
