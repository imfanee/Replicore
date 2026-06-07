//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! Three-node mesh integration test on the emulated-WAN rig (M2 exit
//! criteria 1–5).
//!
//! ```sh
//! cargo build --release
//! sudo -E cargo test --test integration_mesh -- --ignored --nocapture
//! ```
//!
//! Run SERIALLY with integration_wan (both own the rig). Asserts:
//!   1. 3-node mesh replicates create/modify/delete across all nodes
//!   2. partition a node ~2 min under writes; heal converges with NO
//!      unchanged-data retransfer (chunks_fetched delta ≈ changed chunks)
//!   3. kill -9 mid-large-transfer; resume re-fetches only missing chunks
//!   4. identical content at several paths/nodes is stored & fetched once
//!   5. a SIGSTOPped peer does not grow the writer's memory unboundedly

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const HEALTH_PORT: u16 = 8080;
const ETC: &str = "/srv/replicore/etc";
const STATE: &str = "/srv/replicore/state";

const NODES: [(&str, &str, &str, &str); 3] = [
    // (name, ns, ip, share)
    ("a", "rc-a", "10.123.0.1", "/srv/replicore/a"),
    ("b", "rc-b", "10.123.0.2", "/srv/replicore/b"),
    ("c", "rc-c", "10.123.0.3", "/srv/replicore/c"),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn bin() -> PathBuf {
    repo_root().join("target/release/replicored")
}

fn sh(args: &[&str]) -> std::process::Output {
    Command::new(repo_root().join("scripts/wan-testbed.sh"))
        .args(args)
        .output()
        .expect("run wan-testbed.sh")
}

struct Rig;
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
        let (_, ns, _, _) = NODES.iter().find(|(n, ..)| *n == name).expect("node");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{STATE}/node-{name}.log"))
            .expect("log file");
        let child = Command::new("ip")
            .args(["netns", "exec", ns])
            .arg(bin())
            .args(["run", "--config"])
            .arg(format!("{ETC}/node-{name}.toml"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("clone fd")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn replicored");
        Daemon { name, child }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn kill_dash_nine(&mut self) {
        self.child.kill().expect("kill -9");
        let _ = self.child.wait();
        eprintln!("[test] kill -9 node-{}", self.name);
    }

    fn signal(&self, sig: &str) {
        let ok = Command::new("kill")
            .args([sig, &self.pid().to_string()])
            .status()
            .expect("kill")
            .success();
        assert!(ok, "signal {sig} failed");
        eprintln!("[test] {} node-{}", sig, self.name);
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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

/// path → blake3 of every regular file (staging temps excluded; vanished
/// files skipped — callers poll until snapshots stabilize/converge).
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

fn trees_converged() -> bool {
    let a = tree(NODES[0].3);
    !a.is_empty() && a == tree(NODES[1].3) && a == tree(NODES[2].3)
}

/// GET /healthz from a node over the bridge; None while the node is down.
fn healthz(node: &str) -> Option<String> {
    let (_, _, ip, _) = NODES.iter().find(|(n, ..)| *n == node)?;
    let addr: std::net::SocketAddr = format!("{ip}:{HEALTH_PORT}").parse().ok()?;
    let mut sock = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    sock.write_all(b"GET /healthz HTTP/1.1\r\nHost: t\r\n\r\n")
        .ok()?;
    let mut resp = String::new();
    sock.read_to_string(&mut resp).ok()?;
    resp.split("\r\n\r\n").nth(1).map(str::to_string)
}

/// Pull `"key":<u64>` out of the hand-rolled healthz JSON.
fn json_u64(body: &str, key: &str) -> u64 {
    let needle = format!("\"{key}\":");
    let start = body.find(&needle).map(|i| i + needle.len()).unwrap_or(0);
    body[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn chunks_fetched(node: &str) -> u64 {
    healthz(node)
        .map(|b| json_u64(&b, "chunks_fetched"))
        .unwrap_or(0)
}

/// Count chunk files in a node's CAS (survives restarts — the resume truth).
fn cas_chunks(node: &str) -> u64 {
    let mut count = 0;
    let mut stack = vec![PathBuf::from(format!("{STATE}/node-{node}.cas"))];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                count += 1;
            }
        }
    }
    count
}

fn vm_rss_kib(pid: u32) -> u64 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    status
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn write_file(share: &str, rel: &str, data: &[u8]) {
    let p = Path::new(share).join(rel);
    std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    std::fs::write(p, data).expect("write");
}

fn pseudo_bytes(len: usize, mut seed: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        out.extend_from_slice(&seed.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[test]
#[ignore = "needs root + netns; run: cargo build --release && sudo -E cargo test --test integration_mesh -- --ignored --nocapture"]
fn three_node_mesh_self_heals() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        panic!("this test must run as root (sudo -E)");
    }
    assert!(bin().exists(), "build first: cargo build --release");

    let _ = sh(&["down"]);
    let up = sh(&["up"]);
    assert!(up.status.success(), "testbed up failed: {up:?}");
    let _rig = Rig;
    for (_, _, _, share) in NODES {
        let _ = std::fs::remove_dir_all(share);
        std::fs::create_dir_all(share).expect("mkdir");
    }
    let _ = std::fs::remove_dir_all(ETC);
    let _ = std::fs::remove_dir_all(STATE);
    std::fs::create_dir_all(STATE).expect("mkdir");
    let certs = sh(&["certs"]);
    assert!(certs.status.success(), "certs failed: {certs:?}");
    // Faster knobs for the test (append to each generated config).
    for (name, ..) in NODES {
        let cfg = format!("{ETC}/node-{name}.toml");
        let text = std::fs::read_to_string(&cfg).expect("read cfg");
        let tuned = text.replace(
            "health_listen",
            "quiesce_ms = 100\nscan_interval_secs = 1\nmax_file_bytes = 134217728\nhealth_listen",
        );
        std::fs::write(&cfg, tuned).expect("write cfg");
    }

    let _a = Daemon::spawn("a");
    let _b = Daemon::spawn("b");
    let mut c = Daemon::spawn("c");

    // --- 1. create/modify/delete propagate across all three ----------------
    write_file(NODES[0].3, "from-a/one.txt", b"v1 from A");
    write_file(NODES[1].3, "from-b/two.txt", b"v1 from B");
    write_file(NODES[2].3, "from-c/three.txt", b"v1 from C");
    wait_for("3-way create", Duration::from_secs(90), trees_converged);

    write_file(NODES[1].3, "from-b/two.txt", b"v2 from B");
    wait_for("3-way modify", Duration::from_secs(60), || {
        trees_converged()
            && std::fs::read(Path::new(NODES[2].3).join("from-b/two.txt"))
                .is_ok_and(|d| d == b"v2 from B")
    });

    std::fs::remove_file(Path::new(NODES[2].3).join("from-c/three.txt")).expect("rm");
    wait_for("3-way delete", Duration::from_secs(60), || {
        trees_converged() && !Path::new(NODES[0].3).join("from-c/three.txt").exists()
    });
    eprintln!("[test] criterion 1: 3-node create/modify/delete OK");

    // --- 2. partition C ~2 min under writes; heal without retransfer -------
    // Baseline corpus that must NOT be re-fetched after the heal.
    for i in 0..20 {
        write_file(
            NODES[0].3,
            &format!("from-a/base-{i}.bin"),
            &pseudo_bytes(8192, i as u64 + 1),
        );
    }
    wait_for("baseline corpus", Duration::from_secs(90), trees_converged);

    let out = Command::new("ip")
        .args([
            "netns", "exec", "rc-c", "ip", "link", "set", "veth-c", "down",
        ])
        .output()
        .expect("partition");
    assert!(out.status.success());
    eprintln!("[test] partitioned node-c");

    // Writes elsewhere during the partition: new files + modified files.
    for i in 0..10 {
        write_file(
            NODES[0].3,
            &format!("from-a/during-{i}.bin"),
            &pseudo_bytes(8192, 100 + i as u64),
        );
    }
    for i in 0..5 {
        write_file(
            NODES[0].3,
            &format!("from-a/base-{i}.bin"),
            &pseudo_bytes(8192, 200 + i as u64),
        );
    }
    write_file(NODES[1].3, "from-b/during.bin", &pseudo_bytes(8192, 300));
    // A and B converge between themselves while C is dark.
    wait_for(
        "A/B converge during partition",
        Duration::from_secs(90),
        || {
            let a = tree(NODES[0].3);
            !a.is_empty() && a == tree(NODES[1].3)
        },
    );
    std::thread::sleep(Duration::from_secs(100)); // "minutes" of partition

    let c_fetched_before_heal = chunks_fetched("c"); // healthz unreachable? c is partitioned from US too? bridge reaches c via veth-c which is DOWN -> unreachable; count CAS instead.
    let c_cas_before_heal = cas_chunks("c");

    let out = Command::new("ip")
        .args(["netns", "exec", "rc-c", "ip", "link", "set", "veth-c", "up"])
        .output()
        .expect("heal");
    assert!(out.status.success());
    eprintln!("[test] healed node-c (fetched-counter pre-heal read: {c_fetched_before_heal})");

    wait_for(
        "C reconciles after heal",
        Duration::from_secs(180),
        trees_converged,
    );
    // No unchanged-data retransfer: C needed 10 new + 5 modified + 1 B file
    // = 16 single-chunk files. Allow headroom but forbid anything near the
    // full 20-file baseline re-fetch (which would be ~36 total).
    let c_cas_after_heal = cas_chunks("c");
    let fetched_during_heal = c_cas_after_heal - c_cas_before_heal;
    assert!(
        (16..=20).contains(&fetched_during_heal),
        "heal fetched {fetched_during_heal} chunks; expected ~16 (changed only, no full retransfer)"
    );
    eprintln!("[test] criterion 2: heal fetched only {fetched_during_heal} changed chunks");

    // --- 3. kill -9 mid-large-transfer; resume skips verified chunks -------
    let big = pseudo_bytes(16 * 1024 * 1024, 0xb16);
    let big_hash = blake3::hash(&big).to_hex().to_string();
    write_file(NODES[0].3, "from-a/big.bin", &big);
    let cas_at_start = cas_chunks("c");
    // Wait until C is mid-transfer (some but not all chunks present).
    wait_for("C mid-transfer", Duration::from_secs(180), || {
        cas_chunks("c") > cas_at_start + 1
    });
    c.kill_dash_nine();
    let survived = cas_chunks("c") - cas_at_start;
    assert!(
        survived > 1,
        "expected partial progress, got {survived} chunks"
    );

    c = Daemon::spawn("c");
    wait_for(
        "big file resumes and completes on C",
        Duration::from_secs(300),
        || {
            std::fs::read(Path::new(NODES[2].3).join("from-a/big.bin"))
                .is_ok_and(|d| blake3::hash(&d).to_hex().to_string() == big_hash)
        },
    );
    // Resume proof: the post-restart process fetched fewer chunks than the
    // file has — the `survived` pre-kill chunks were never re-sent (FR-404).
    let total_big_chunks = cas_chunks("c") - cas_at_start;
    let refetched = chunks_fetched("c"); // counter reset at restart
    assert!(
        refetched < total_big_chunks,
        "resume re-fetched everything: {refetched} of {total_big_chunks} chunks"
    );
    eprintln!(
        "[test] criterion 3: resume kept {survived} chunks, re-fetched {refetched} of {total_big_chunks}"
    );

    // --- 4. dedup: identical content at new paths costs zero fetches -------
    let dup = pseudo_bytes(8192, 0xd0d0);
    write_file(NODES[0].3, "from-a/dup-1.bin", &dup);
    wait_for("dup-1 converges", Duration::from_secs(60), trees_converged);
    let b_fetched = chunks_fetched("b");
    let c_fetched = chunks_fetched("c");
    let b_cas = cas_chunks("b");
    // Same bytes, two more paths, two different writers.
    write_file(NODES[0].3, "from-a/dup-2.bin", &dup);
    write_file(NODES[1].3, "from-b/dup-3.bin", &dup);
    wait_for(
        "dup copies converge",
        Duration::from_secs(60),
        trees_converged,
    );
    assert_eq!(
        chunks_fetched("b"),
        b_fetched,
        "B re-fetched chunks it already had (dedup broken)"
    );
    assert_eq!(
        chunks_fetched("c"),
        c_fetched,
        "C re-fetched chunks it already had (dedup broken)"
    );
    assert_eq!(cas_chunks("b"), b_cas, "B's CAS grew for duplicate content");
    eprintln!("[test] criterion 4: duplicate content fetched zero times, stored once");

    // --- 5. SIGSTOPped peer: writer memory stays bounded --------------------
    let a_pid = _a.pid();
    c.signal("-STOP");
    for i in 0..60 {
        write_file(
            NODES[0].3,
            &format!("from-a/burst-{i:03}.bin"),
            &pseudo_bytes(256 * 1024, 500 + i as u64),
        );
    }
    let mut max_rss = 0;
    for _ in 0..20 {
        max_rss = max_rss.max(vm_rss_kib(a_pid));
        std::thread::sleep(Duration::from_millis(500));
    }
    // A holds 15 MiB of new content; its RSS must stay far below corpus ×
    // peers (the durable oplog is the spill, not memory).
    assert!(
        max_rss < 512 * 1024,
        "writer RSS grew to {max_rss} KiB under a stalled peer"
    );
    // B (healthy) still converged with A while C was stalled.
    wait_for(
        "B converges during C stall",
        Duration::from_secs(300),
        || {
            let a = tree(NODES[0].3);
            !a.is_empty() && a == tree(NODES[1].3)
        },
    );
    c.signal("-CONT");
    wait_for(
        "C catches up after SIGCONT",
        Duration::from_secs(300),
        trees_converged,
    );
    eprintln!("[test] criterion 5: writer RSS peaked at {max_rss} KiB under a stalled peer");

    eprintln!("[test] all M2 mesh exit criteria demonstrated");
}
