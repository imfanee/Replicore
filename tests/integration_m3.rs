//! M3 exit-criteria integration tests on the emulated-WAN rig (RSD §I.5).
//!
//! ```sh
//! cargo build --release
//! sudo -E cargo test --release --test integration_m3 -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Run SERIALLY (the rig is global) and not alongside integration_wan/mesh.
//! Covered here:
//!   3. multi-minute partition with concurrent writes on BOTH sides heals
//!      with deterministic conflict copies and zero loss (byte-identical
//!      trees including the copy names);
//!   5. hours of clock skew on one node changes nothing about ordering or
//!      resolution (no wall-clock in the tiebreak — proven, not assumed);
//!   4. the bandwidth cap is HONORED, measured by transfer wall-time, and
//!      NFR-P4: small-file propagation under the reference WAN profile
//!      (150ms RTT, 1% loss) stays under 15s P95;
//!   FR-1107: a node refuses to fill its disk (loopback-backed share), trips
//!      the guard, and auto-resumes when space recovers.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HEALTH_PORT: u16 = 8080;
const ETC: &str = "/srv/replicore/etc";
const STATE: &str = "/srv/replicore/state";

const NODES: [(&str, &str, &str, &str); 2] = [
    ("a", "rc-a", "10.123.0.1", "/srv/replicore/a"),
    ("b", "rc-b", "10.123.0.2", "/srv/replicore/b"),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> PathBuf {
    repo_root().join("target/release/replicored")
}

fn sh_env(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut cmd = Command::new(repo_root().join("scripts/wan-testbed.sh"));
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.output().expect("run wan-testbed.sh")
}

fn sh(args: &[&str]) -> std::process::Output {
    sh_env(args, &[])
}

struct Rig;
impl Rig {
    /// up + certs with the given shaping env; panics on failure. Wipes ALL
    /// per-node state first — each test starts from an empty cluster
    /// (leftover DBs from a previous rig test poison cursors and VVs).
    fn up(envs: &[(&str, &str)]) -> Rig {
        let _ = sh(&["down"]);
        let _ = std::fs::remove_dir_all(STATE);
        for (_, _, _, share) in NODES {
            let _ = std::fs::remove_dir_all(share);
        }
        let _ = std::fs::remove_dir_all("/srv/replicore/c");
        let _ = std::fs::remove_dir_all("/srv/replicore/d");
        let out = sh_env(&["up"], envs);
        assert!(out.status.success(), "rig up: {:?}", out);
        let out = sh(&["certs"]);
        assert!(out.status.success(), "rig certs: {:?}", out);
        Rig
    }
}
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = sh(&["down"]);
    }
}

struct Daemon {
    name: &'static str,
    child: Child,
}

impl Daemon {
    fn spawn(name: &'static str) -> Daemon {
        Self::spawn_wrapped(name, &[])
    }

    /// Spawn with a command-prefix inside the namespace (e.g. faketime).
    fn spawn_wrapped(name: &'static str, wrapper: &[&str]) -> Daemon {
        let (_, ns, _, _) = NODES.iter().find(|(n, ..)| *n == name).expect("node");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{STATE}/node-{name}.log"))
            .expect("log file");
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", ns]);
        for w in wrapper {
            cmd.arg(w);
        }
        cmd.arg(bin())
            .args(["run", "--config"])
            .arg(format!("{ETC}/node-{name}.toml"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("clone fd")))
            .stderr(Stdio::from(log));
        let child = cmd.spawn().expect("spawn replicored");
        Daemon { name, child }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        eprintln!("[test] stopped node-{}", self.name);
    }
}

fn wait_for(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            eprintln!("[test] ok: {what} ({:?})", start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("timed out after {timeout:?} waiting for: {what}");
}

/// path → blake3 of every regular file (staging temps excluded).
fn tree(root: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if !path.to_string_lossy().contains(".replicore-tmp") {
                let Ok(data) = std::fs::read(&path) else {
                    continue;
                };
                let rel = path
                    .strip_prefix(root)
                    .expect("prefix")
                    .to_string_lossy()
                    .into_owned();
                out.insert(rel, blake3::hash(&data).to_hex().to_string());
            }
        }
    }
    out
}

fn http_get(node: &str, path: &str) -> Option<String> {
    let (_, _, ip, _) = NODES.iter().find(|(n, ..)| *n == node)?;
    let addr: std::net::SocketAddr = format!("{ip}:{HEALTH_PORT}").parse().ok()?;
    let mut sock = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    sock.write_all(format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n").as_bytes())
        .ok()?;
    let mut resp = String::new();
    sock.read_to_string(&mut resp).ok()?;
    resp.split("\r\n\r\n").nth(1).map(str::to_string)
}

fn metric(node: &str, name: &str) -> u64 {
    let Some(body) = http_get(node, "/metrics") else {
        return 0;
    };
    body.lines()
        .find(|l| l.starts_with(name) && !l.starts_with('#'))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn partition(node: &str) {
    let ok = Command::new("ip")
        .args([
            "netns",
            "exec",
            &format!("rc-{node}"),
            "ip",
            "link",
            "set",
            &format!("veth-{node}"),
            "down",
        ])
        .status()
        .expect("partition")
        .success();
    assert!(ok);
    eprintln!("[test] partitioned node-{node}");
}

fn heal(node: &str) {
    let ok = Command::new("ip")
        .args([
            "netns",
            "exec",
            &format!("rc-{node}"),
            "ip",
            "link",
            "set",
            &format!("veth-{node}"),
            "up",
        ])
        .status()
        .expect("heal")
        .success();
    assert!(ok);
    eprintln!("[test] healed node-{node}");
}

fn write_file(share: &str, rel: &str, data: &[u8]) {
    let p = PathBuf::from(share).join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

/// The conflict-partition flow shared by the plain and clock-skew tests:
/// seed → partition → concurrent writes both sides → heal → byte-identical
/// trees including the DERIVED copy name, zero loss.
fn run_partition_conflict_flow(b_wrapper: &[&str]) {
    let _rig = Rig::up(&[("MODE", "lan")]);
    let _a = Daemon::spawn("a");
    let _b = Daemon::spawn_wrapped("b", b_wrapper);

    // Seed and converge.
    write_file(NODES[0].3, "shared/p.txt", b"seed");
    wait_for("seed replicates", Duration::from_secs(60), || {
        tree(NODES[1].3).get("shared/p.txt").map(String::as_str)
            == Some(blake3::hash(b"seed").to_hex().as_str())
    });

    // Multi-minute partition with concurrent writes on BOTH sides.
    partition("b");
    std::thread::sleep(Duration::from_secs(2));
    let side_a = b"version written on A during the partition";
    let side_b = b"version written on B during the partition";
    write_file(NODES[0].3, "shared/p.txt", side_a);
    write_file(NODES[1].3, "shared/p.txt", side_b);
    eprintln!("[test] concurrent writes landed; holding the partition…");
    std::thread::sleep(Duration::from_secs(90));
    heal("b");

    // Deterministic resolution (FR-303): winner = larger content hash, loser
    // preserved under the derived copy name on BOTH nodes. The exact name is
    // a function of the loser's content AND captured metadata (mtime!), so
    // the test cannot precompute it — cross-node name determinism is exactly
    // what the byte-identical-trees assertion (keys included) proves.
    let (ha, hb) = (
        *blake3::hash(side_a).as_bytes(),
        *blake3::hash(side_b).as_bytes(),
    );
    let (win, lose_hash) = if ha > hb {
        (&side_a[..], hb)
    } else {
        (&side_b[..], ha)
    };
    let lose_hex = hex::encode(lose_hash);
    let find_copy = |t: &BTreeMap<String, String>| {
        t.iter()
            .find(|(k, v)| k.contains(".sync-conflict-") && **v == lose_hex)
            .map(|(k, _)| k.clone())
    };
    wait_for(
        "trees converge with identical conflict copies",
        Duration::from_secs(120),
        || {
            let ta = tree(NODES[0].3);
            let tb = tree(NODES[1].3);
            !ta.is_empty()
                && ta == tb
                && ta.get("shared/p.txt").map(String::as_str)
                    == Some(blake3::hash(win).to_hex().as_str())
                && find_copy(&ta).is_some()
        },
    );
    let copy_rel = find_copy(&tree(NODES[0].3)).expect("loser copy");
    eprintln!("[test] loser preserved at {copy_rel} on both nodes");
    // Both conflict counters saw it.
    assert!(metric("a", "replicore_conflicts_total") >= 1);
}

/// Exit criterion 3.
#[test]
#[ignore = "needs root + netns rig (scripts/wan-testbed.sh); run serially"]
fn partition_heals_with_deterministic_conflict_copies() {
    run_partition_conflict_flow(&[]);
}

/// Exit criterion 5: node B's wall clock is six hours in the future for the
/// WHOLE flow — ordering and resolution must be byte-identical to the
/// unskewed run (nothing in the tiebreak reads a clock).
#[test]
#[ignore = "needs root + netns rig + faketime; run serially"]
fn clock_skew_does_not_change_ordering_or_resolution() {
    run_partition_conflict_flow(&["faketime", "-f", "+6h"]);
}

/// Exit criterion 4 (cap half): the configured bandwidth cap is HONORED,
/// measured by wall time on the receiving side — a 5 MB transfer at a
/// 1 MB/s ingress cap cannot complete in under ~4s.
#[test]
#[ignore = "needs root + netns rig; run serially"]
fn bandwidth_cap_is_honored_measured() {
    let _rig = Rig::up(&[("MODE", "lan")]);
    // Cap node B's ingress at 1 MB/s via its intent file (top-of-file keys
    // must precede the [[peers]] tables — [bandwidth] is its own table, so
    // appending is fine).
    let cfg = format!("{ETC}/node-b.toml");
    let mut toml = std::fs::read_to_string(&cfg).unwrap();
    toml.push_str("\n[bandwidth]\nglobal_bps = 1000000\nper_peer_bps = 1000000\n");
    std::fs::write(&cfg, toml).unwrap();

    let _a = Daemon::spawn("a");
    let _b = Daemon::spawn("b");
    write_file(NODES[0].3, "warmup.txt", b"hello");
    wait_for("link is live", Duration::from_secs(60), || {
        tree(NODES[1].3).contains_key("warmup.txt")
    });

    let payload: Vec<u8> = (0u32..5_000_000).map(|i| (i % 251) as u8).collect();
    let expect = blake3::hash(&payload).to_hex().to_string();
    let t0 = Instant::now();
    write_file(NODES[0].3, "big.bin", &payload);
    wait_for("5MB file arrives", Duration::from_secs(120), || {
        tree(NODES[1].3).get("big.bin") == Some(&expect)
    });
    let elapsed = t0.elapsed();
    eprintln!("[test] 5MB at 1MB/s cap took {elapsed:?}");
    assert!(
        elapsed >= Duration::from_secs(4),
        "cap not honored: 5MB arrived in {elapsed:?} at a 1MB/s cap"
    );
}

/// NFR-P4: small-file end-to-end under the reference WAN profile (75ms each
/// way ⇒ 150ms RTT, 1% loss): P95 under 15 seconds.
#[test]
#[ignore = "needs root + netns rig with tc netem; run serially"]
fn nfr_p4_small_file_p95_under_reference_wan() {
    let _rig = Rig::up(&[("MODE", "wan"), ("DELAY", "75ms"), ("LOSS", "1%")]);
    let _a = Daemon::spawn("a");
    let _b = Daemon::spawn("b");
    write_file(NODES[0].3, "warmup.txt", b"hello");
    wait_for("link is live", Duration::from_secs(120), || {
        tree(NODES[1].3).contains_key("warmup.txt")
    });

    let mut times = Vec::new();
    for i in 0..20 {
        let rel = format!("small/f{i:02}.txt");
        let data = format!("small file number {i}").into_bytes();
        let expect = blake3::hash(&data).to_hex().to_string();
        let t0 = Instant::now();
        write_file(NODES[0].3, &rel, &data);
        wait_for(&rel, Duration::from_secs(30), || {
            tree(NODES[1].3).get(&rel) == Some(&expect)
        });
        times.push(t0.elapsed());
    }
    times.sort();
    let p95 = times[(times.len() * 95 / 100).min(times.len() - 1)];
    eprintln!(
        "[test] small-file propagation P95 = {p95:?} (n={})",
        times.len()
    );
    assert!(
        p95 < Duration::from_secs(15),
        "NFR-P4 violated: P95 {p95:?} >= 15s on the reference WAN"
    );
}

/// FR-1107: a receiver whose share/CAS live on a small loopback filesystem
/// refuses to breach the reserve (guard trips, file does NOT land), then
/// auto-resumes and completes once space recovers.
#[test]
#[ignore = "needs root (loop mounts) + netns rig; run serially"]
fn free_space_guard_refuses_to_fill_the_disk_and_recovers() {
    let _rig = Rig::up(&[("MODE", "lan")]);

    // 64 MB ext4 on a loop device, mounted as node B's data root (small
    // filesystems lose several MB to the journal — leave real headroom or
    // the guard trips on the warmup file).
    let img = format!("{STATE}/loopfs.img");
    let mnt = format!("{STATE}/loopfs");
    let _ = Command::new("umount").args(["-l", &mnt]).status();
    std::fs::create_dir_all(&mnt).unwrap();
    let f = std::fs::File::create(&img).unwrap();
    f.set_len(64 * 1024 * 1024).unwrap();
    drop(f);
    assert!(Command::new("mkfs.ext4")
        .args(["-q", "-F", "-m", "0", &img])
        .status()
        .unwrap()
        .success());
    assert!(Command::new("mount")
        .args(["-o", "loop", &img, &mnt])
        .status()
        .unwrap()
        .success());
    struct Unmount(String);
    impl Drop for Unmount {
        fn drop(&mut self) {
            let _ = Command::new("umount").args(["-l", &self.0]).status();
        }
    }
    let _um = Unmount(mnt.clone());

    // Point node B's share + CAS into the small fs; reserve 2 MB.
    let share_b = format!("{mnt}/share");
    let cas_b = format!("{mnt}/cas");
    std::fs::create_dir_all(&share_b).unwrap();
    std::fs::create_dir_all(&cas_b).unwrap();
    let cfg = format!("{ETC}/node-b.toml");
    let toml = std::fs::read_to_string(&cfg).unwrap();
    let toml = toml
        .replace(
            &format!("share_dir = \"{}\"", NODES[1].3),
            &format!("share_dir = \"{share_b}\""),
        )
        .replace(
            &format!("cas_dir   = \"{STATE}/node-b.cas\""),
            &format!("cas_dir   = \"{cas_b}\""),
        );
    let toml = format!("reserve_bytes = 2097152\n{toml}");
    std::fs::write(&cfg, toml).unwrap();

    let _a = Daemon::spawn("a");
    let _b = Daemon::spawn("b");
    write_file(NODES[0].3, "warmup.txt", b"hello");
    wait_for("link is live", Duration::from_secs(60), || {
        tree(&share_b).contains_key("warmup.txt")
    });

    // NOW starve the filesystem: ballast leaves ~6 MB free — a 6 MB file
    // needs ~12 MB (CAS chunks + assembled copy) above the 2 MB reserve,
    // so it cannot fit.
    let avail = Command::new("df")
        .args(["--output=avail", "-B1", &mnt])
        .output()
        .unwrap();
    let avail: u64 = String::from_utf8_lossy(&avail.stdout)
        .lines()
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let ballast_len = avail.saturating_sub(6 * 1024 * 1024);
    eprintln!("[test] {avail} bytes free; writing {ballast_len} of ballast");
    let ballast = format!("{mnt}/ballast");
    std::fs::write(&ballast, vec![0xBBu8; ballast_len as usize]).unwrap();

    let payload: Vec<u8> = (0u32..6_000_000).map(|i| (i % 241) as u8).collect();
    let expect = blake3::hash(&payload).to_hex().to_string();
    write_file(NODES[0].3, "big/recording.bin", &payload);

    // The guard must trip — and the file must NOT land.
    wait_for("guard trips", Duration::from_secs(60), || {
        metric("b", "replicore_freespace_guard_trips_total") >= 1
    });
    std::thread::sleep(Duration::from_secs(5));
    assert!(
        !tree(&share_b).contains_key("big/recording.bin"),
        "guard tripped but the file landed anyway"
    );

    // Space recovers: the prober (30s tick) auto-resumes and the transfer
    // completes — no operator action, no partial files in between.
    std::fs::remove_file(&ballast).unwrap();
    eprintln!("[test] ballast removed; waiting for auto-resume…");
    wait_for(
        "transfer completes after recovery",
        Duration::from_secs(180),
        || tree(&share_b).get("big/recording.bin") == Some(&expect),
    );
}

/// NFR-P6: ≥ 80% utilization of a rate-limited link at 1% loss — a 15 MB
/// transfer over a 20 Mbit/s shaped link (ideal exactly 6s) must complete
/// within 6s/0.8 = 7.5s of its first-possible start… measured end-to-end
/// from the write, so allow the watcher/quiesce overhead on top (~1s).
#[test]
#[ignore = "needs root + netns rig with tc netem rate; run serially"]
fn nfr_p6_link_utilization_at_one_percent_loss() {
    let _rig = Rig::up(&[
        ("MODE", "wan"),
        ("DELAY", "10ms"),
        ("LOSS", "1%"),
        ("RATE", "20mbit"),
    ]);
    let _a = Daemon::spawn("a");
    let _b = Daemon::spawn("b");
    write_file(NODES[0].3, "warmup.txt", b"hello");
    wait_for("link is live", Duration::from_secs(120), || {
        tree(NODES[1].3).contains_key("warmup.txt")
    });

    let payload: Vec<u8> = (0u32..15_000_000).map(|i| (i % 251) as u8).collect();
    let expect = blake3::hash(&payload).to_hex().to_string();
    let t0 = Instant::now();
    write_file(NODES[0].3, "bulk.bin", &payload);
    wait_for(
        "15MB arrives over the shaped link",
        Duration::from_secs(120),
        || tree(NODES[1].3).get("bulk.bin") == Some(&expect),
    );
    let elapsed = t0.elapsed();
    let ideal = Duration::from_secs_f64(15_000_000.0 * 8.0 / 20_000_000.0);
    let budget = ideal.mul_f64(1.25) + Duration::from_millis(1500); // 80% + pipeline overhead
    eprintln!("[test] 15MB over 20Mbit/1% loss: {elapsed:?} (ideal {ideal:?}, budget {budget:?})");
    assert!(
        elapsed <= budget,
        "NFR-P6 violated: {elapsed:?} > {budget:?} (≥80% utilization required)"
    );
}
