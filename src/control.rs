//! control.rs — operator control plane over a Unix domain socket (FR-1401–1409).
//!
//! `replicorectl` connects to `control_socket`, sends one [`CtlRequest`], reads
//! one [`CtlResponse`], and closes. Framing reuses the wire codec
//! (`proto::read_msg`/`write_msg`); the payloads are serde enums shared by the
//! daemon and the CLI binary.
//!
//! ## Auth (NFR-CP2)
//!
//! The socket lives at `<db>.sock` (0700 parent dir, 0600 socket) and every
//! accepted connection is checked with `SO_PEERCRED`: only the daemon's own uid
//! (or root) may issue commands. Filesystem perms are the first gate;
//! `SO_PEERCRED` is the authoritative one (perms can be widened by an admin).
//!
//! ## Trust split (FR-1305)
//!
//! `member add/remove` entries are signed CLIENT-side by `replicorectl` using
//! the admin secret — **the daemon never sees it**. The daemon only verifies
//! (via [`Membership::merge_signed`]) and persists/gossips. To sign, the CLI
//! first asks the daemon to `PrepareEntry` (next epoch, and the current
//! addr/fingerprint for a remove), then submits the signed entry.
//!
//! Remote CONTROL (mutating another node over the mesh) is a deferred SEAM
//! (FR-1409); only the read-side `status --all` fans out today.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::{UnixListener, UnixStream};

use crate::membership::{MembershipError, MergeOutcome, SignedEntry};
use crate::net::Engine;
use crate::proto::{read_msg, write_msg, ProtoError};
use crate::vv::NodeId;

#[derive(thiserror::Error, Debug)]
pub enum ControlError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("transport: {0}")]
    Proto(#[from] ProtoError),
}

// ---------------------------------------------------------------------------
// Wire protocol (shared daemon <-> replicorectl)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CtlRequest {
    Status {
        all: bool,
    },
    Members,
    Peers,
    Lag,
    Conflicts,
    Transfers,
    Version,
    ConfigValidate {
        path: String,
    },
    ConfigDiff {
        path: String,
    },
    ConfigReload {
        path: String,
    },
    /// Ask the daemon for the fields the CLI needs to sign a membership entry:
    /// the next epoch, and (if the node is known) its current addr/fingerprint.
    PrepareEntry {
        node: NodeId,
    },
    MemberAdd(SignedEntry),
    MemberRemove(SignedEntry),
    Resync {
        node: Option<NodeId>,
    },
    Pause,
    Resume,
    /// `None` = show the live rates; `Some` = retune at runtime (FR-1105).
    /// Runtime overrides last until the next schedule tick or reload — the
    /// intent file stays the durable source of policy (FR-1302 discipline).
    Bandwidth {
        set: Option<(u64, u64)>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CtlResponse {
    Status(StatusReport),
    Members(Vec<MemberView>),
    Peers(Vec<PeerView>),
    Lag(Vec<LagView>),
    Conflicts(u64),
    Transfers(TransfersView),
    Version(VersionView),
    Diff(Vec<ConfigChangeView>),
    Prepared {
        epoch: u64,
        addr: Option<String>,
        fingerprint: Option<String>,
    },
    Ok(String),
    Error(String),
    Bandwidth {
        global_bps: u64,
        per_peer_bps: u64,
    },
}

/// A single node's self-reported status (also the CTLQUERY mesh reply).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeStatus {
    pub node_id: String,
    pub lifecycle: String,
    pub effective_members: usize,
    pub live_peers: usize,
    pub conflicts: u64,
    pub inflight_transfers: i64,
    pub paused: bool,
    pub roster_digest: String,
    pub proto_version: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct StatusReport {
    pub local: NodeStatus,
    /// Populated only for `status --all` (FR-1407): one entry per effective
    /// peer, `reachable=false` (status=None) if it did not answer in time.
    pub peers: Vec<PeerStatusEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerStatusEntry {
    pub node_id: String,
    pub reachable: bool,
    pub status: Option<NodeStatus>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MemberView {
    pub node_id: String,
    pub addr: String,
    pub fingerprint: String,
    pub epoch: u64,
    /// "add" (live member) or "remove" (tombstone).
    pub kind: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PeerView {
    pub node_id: String,
    pub state: String,
    pub connected: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LagView {
    pub node_id: String,
    /// Their ops we have durably handled (recv cursor).
    pub recv_cursor: i64,
    /// Our ops they have acked.
    pub last_acked: i64,
    /// Our latest local op seq (acked vs this = our send lag to them).
    pub our_latest: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransfersView {
    pub inflight: i64,
    pub chunks_fetched: u64,
    pub chunks_served: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VersionView {
    pub node_id: String,
    pub proto_version: u16,
    pub pkg_version: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ConfigChangeView {
    pub field: String,
    pub hot: bool,
    pub old: String,
    pub new: String,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Bind the control socket (0700 dir / 0600 sock) and serve requests until the
/// process exits. Each connection carries exactly one request/response.
pub async fn serve(engine: Arc<Engine>, path: PathBuf) -> Result<(), ControlError> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    // A stale socket from a previous run would block bind; remove it. (We never
    // remove a non-socket — bind would fail loudly on a real file.)
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let our_uid = unsafe { libc::geteuid() };
    tracing::info!(socket = %path.display(), "control plane listening");

    loop {
        let (stream, _) = listener.accept().await?;
        // SO_PEERCRED authoritative uid check (perms are only the first gate).
        match peer_uid(&stream) {
            Ok(uid) if uid == our_uid || uid == 0 => {}
            Ok(uid) => {
                tracing::warn!(uid, "control connection from another uid; rejected");
                continue;
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not read peer credentials; rejected");
                continue;
            }
        }
        let engine = engine.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(engine, stream).await {
                tracing::debug!(error = %e, "control connection ended");
            }
        });
    }
}

fn peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: getsockopt on a valid connected AF_UNIX fd; ucred is zeroed and
    // its size passed by reference per the contract. The fd outlives the call.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

async fn handle_conn(engine: Arc<Engine>, mut stream: UnixStream) -> Result<(), ControlError> {
    let req: CtlRequest = read_msg(&mut stream).await?;
    let resp = dispatch(&engine, req).await;
    write_msg(&mut stream, &resp).await?;
    Ok(())
}

async fn dispatch(engine: &Arc<Engine>, req: CtlRequest) -> CtlResponse {
    match req {
        CtlRequest::Status { all } => CtlResponse::Status(engine.status_report(all).await),
        CtlRequest::Members => CtlResponse::Members(engine.member_views()),
        CtlRequest::Peers => CtlResponse::Peers(engine.peer_views()),
        CtlRequest::Lag => CtlResponse::Lag(engine.lag_views().await),
        CtlRequest::Conflicts => CtlResponse::Conflicts(engine.conflicts()),
        CtlRequest::Transfers => CtlResponse::Transfers(engine.transfers_view()),
        CtlRequest::Version => CtlResponse::Version(engine.version_view()),
        CtlRequest::ConfigValidate { path } => {
            match crate::config::Config::load(Path::new(&path)) {
                Ok(_) => CtlResponse::Ok(format!("{path}: valid")),
                Err(e) => CtlResponse::Error(format!("{path}: {e}")),
            }
        }
        CtlRequest::ConfigDiff { path } => match crate::config::Config::load(Path::new(&path)) {
            Ok(cand) => CtlResponse::Diff(
                engine
                    .config_diff(&cand)
                    .into_iter()
                    .map(|c| ConfigChangeView {
                        field: c.field.to_string(),
                        hot: c.hot,
                        old: c.old,
                        new: c.new,
                    })
                    .collect(),
            ),
            Err(e) => CtlResponse::Error(format!("{path}: {e}")),
        },
        CtlRequest::ConfigReload { path } => match crate::config::Config::load(Path::new(&path)) {
            // Invalid candidate → reject; running config untouched (FR-1406).
            Err(e) => CtlResponse::Error(format!("{path}: {e} (running config untouched)")),
            Ok(cand) => match engine.reload(&cand) {
                Err(e) => {
                    CtlResponse::Error(format!("reload failed: {e} (running config untouched)"))
                }
                Ok(changes) => {
                    let hot: Vec<&str> =
                        changes.iter().filter(|c| c.hot).map(|c| c.field).collect();
                    let cold: Vec<&str> =
                        changes.iter().filter(|c| !c.hot).map(|c| c.field).collect();
                    CtlResponse::Ok(format!(
                        "reloaded; applied hot: [{}]; restart-required (ignored): [{}]",
                        hot.join(", "),
                        cold.join(", ")
                    ))
                }
            },
        },
        CtlRequest::PrepareEntry { node } => {
            let (addr, fingerprint) = engine.member_addr_fp(&node);
            CtlResponse::Prepared {
                epoch: engine.membership().next_epoch_for(&node),
                addr,
                fingerprint,
            }
        }
        CtlRequest::MemberAdd(entry) | CtlRequest::MemberRemove(entry) => {
            match engine.membership().merge_signed(entry) {
                Ok(MergeOutcome::Applied) => {
                    CtlResponse::Ok("membership change applied and gossiped".into())
                }
                Ok(MergeOutcome::Superseded) => {
                    CtlResponse::Ok("no change (entry superseded by a newer one)".into())
                }
                Ok(MergeOutcome::Rejected) => {
                    CtlResponse::Error("signature rejected: not signed by the admin key".into())
                }
                Err(MembershipError::NoAdminKey) => {
                    CtlResponse::Error("this node has no [trust] admin_pubkey configured".into())
                }
                Err(e) => CtlResponse::Error(format!("membership change failed: {e}")),
            }
        }
        CtlRequest::Resync { node } => {
            let n = engine.resync(node).await;
            CtlResponse::Ok(format!("resync triggered on {n} link(s)"))
        }
        CtlRequest::Pause => {
            engine.pause();
            CtlResponse::Ok("replication paused (in-flight transfers finish)".into())
        }
        CtlRequest::Resume => {
            engine.resume();
            CtlResponse::Ok("replication resumed".into())
        }
        CtlRequest::Bandwidth { set } => {
            if let Some((global, per_peer)) = set {
                engine.set_bandwidth(global, per_peer);
            }
            let (global_bps, per_peer_bps) = engine.bandwidth_rates();
            CtlResponse::Bandwidth {
                global_bps,
                per_peer_bps,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn peer_uid_matches_our_own() {
        // A connected socketpair's peer cred is this process — the auth check
        // accepts it; a different uid would be rejected by `serve`.
        let (a, _b) = UnixStream::pair().unwrap();
        let uid = peer_uid(&a).unwrap();
        assert_eq!(uid, unsafe { libc::geteuid() });
    }

    #[test]
    fn requests_and_responses_are_serde_round_trippable() {
        // The CLI and daemon must agree on the wire encoding.
        let reqs = vec![
            CtlRequest::Status { all: true },
            CtlRequest::Members,
            CtlRequest::Resync {
                node: Some([7; 16]),
            },
            CtlRequest::Pause,
        ];
        for r in reqs {
            let bytes = serde_json::to_vec(&r).unwrap();
            let _back: CtlRequest = serde_json::from_slice(&bytes).unwrap();
        }
        let resp = CtlResponse::Ok("done".into());
        let bytes = serde_json::to_vec(&resp).unwrap();
        let _back: CtlResponse = serde_json::from_slice(&bytes).unwrap();
    }
}
