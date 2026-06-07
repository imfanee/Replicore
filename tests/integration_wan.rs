//! Two-node integration test on the emulated-WAN rig (exit criteria 1–3, 5).
//!
//! Needs root, iproute2, and `cargo build --release` first:
//!
//! ```sh
//! cargo build --release
//! sudo -E cargo test --test integration_wan -- --ignored --nocapture
//! ```
//!
//! Drives `scripts/wan-testbed.sh` for the namespaces/netem, then launches a
//! real `replicored run` per namespace and asserts:
//!   1. bidirectional create/modify/delete across partitioned namespaces
//!   2. op counts quiesce after a burst (no loops/storms)
//!   3. kill -9 mid-burst → restart resumes from the durable cursor with no
//!      duplication and no corruption (trees converge, content verified)
//!   5. a peer with an unlisted cert replicates nothing
//!
//! (Criterion 4 = convergence proptest; 6 = the clippy gate.)

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const IP_A: &str = "10.123.0.1";
const IP_B: &str = "10.123.0.2";
const PORT: u16 = 7000;
const DIR_A: &str = "/srv/replicore/a";
const DIR_B: &str = "/srv/replicore/b";
const ETC: &str = "/srv/replicore/etc";
const STATE: &str = "/srv/replicore/state";
const NODE_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NODE_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NODE_X: &str = "cccccccccccccccccccccccccccccccc";

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

/// Tear the rig down on scope exit, pass or fail.
struct Rig;
impl Drop for Rig {
    fn drop(&mut self) {
        let _ = sh(&["down"]);
    }
}

struct Node {
    name: &'static str,
    child: Child,
}

impl Node {
    fn spawn(ns: &str, config: &Path, name: &'static str) -> Node {
        let log = std::fs::File::create(format!("{STATE}/{name}.log")).expect("log file");
        let child = Command::new("ip")
            .args(["netns", "exec", ns])
            .arg(bin())
            .args(["run", "--config"])
            .arg(config)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(log.try_clone().expect("clone log fd")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("spawn replicored");
        Node { name, child }
    }

    /// The crash under test: SIGKILL, no shutdown path runs.
    fn kill_dash_nine(&mut self) {
        self.child.kill().expect("kill -9");
        let _ = self.child.wait();
        eprintln!("[test] kill -9 {}", self.name);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn gen_cert(name: &str) -> String {
    let out = Command::new(bin())
        .args(["gen-cert", "--out-dir", ETC, "--name", name])
        .output()
        .expect("gen-cert");
    assert!(out.status.success(), "gen-cert failed: {out:?}");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .lines()
        .find_map(|l| l.strip_prefix("fingerprint: ").map(str::to_string))
        .expect("fingerprint line")
}

#[allow(clippy::too_many_arguments)]
fn write_config(
    file: &str,
    node_id: &str,
    listen: &str,
    share: &str,
    db: &str,
    cert_name: &str,
    peer: (&str, &str, &str), // (node_id, addr, fingerprint)
) -> PathBuf {
    let text = format!(
        r#"
node_id   = "{node_id}"
listen    = "{listen}"
share_dir = "{share}"
db_path   = "{db}"
cert_path = "{ETC}/{cert_name}.cert.pem"
key_path  = "{ETC}/{cert_name}.key.pem"
quiesce_ms = 100
scan_interval_secs = 1

[[peers]]
node_id     = "{}"
addr        = "{}"
fingerprint = "{}"
"#,
        peer.0, peer.1, peer.2
    );
    let path = PathBuf::from(ETC).join(file);
    std::fs::write(&path, text).expect("write config");
    path
}

/// Wait for `cond` to hold, with WAN-sized patience.
fn wait_for(what: &str, timeout: Duration, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            eprintln!("[test] ok: {what} ({:?})", start.elapsed());
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("timed out after {timeout:?} waiting for: {what}");
}

/// path → blake3, for whole-tree comparison. Staging temps are excluded (a
/// poll can race an in-flight apply); files that vanish between listing and
/// reading are skipped — callers compare snapshots until they stabilize.
fn tree(root: &str) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if !path.to_string_lossy().contains(".replicore-tmp") {
                let rel = path
                    .strip_prefix(root)
                    .expect("prefix")
                    .to_string_lossy()
                    .into_owned();
                let Ok(data) = std::fs::read(&path) else {
                    continue; // renamed/unlinked mid-walk
                };
                out.insert(rel, blake3::hash(&data).to_hex().to_string());
            }
        }
    }
    out
}

/// Every staging temp currently under `root` (hygiene assertion input).
fn temps(root: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::from(root)];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.to_string_lossy().contains(".replicore-tmp") {
                out.push(path);
            }
        }
    }
    out
}

struct Bed {
    _rig: Rig,
    cfg_a: PathBuf,
    cfg_b: PathBuf,
    fp_a: String,
    addr_a: String,
    /// Declared last: drops after `_rig` runs `down`, releasing the rig to
    /// the other test only once the namespaces are gone.
    _lock: std::sync::MutexGuard<'static, ()>,
    /// CROSS-PROCESS rig lock (flock on /srv/replicore/.rig.lock). The
    /// in-process `RIG_LOCK` only serializes this binary's own tests; the
    /// soak runs in a SEPARATE process and used to be able to scribble the
    /// shared share dir mid-test (the source of the flaky integration_wan
    /// findings). Held for the Bed's life; released after `_rig` tears down.
    _flock: std::fs::File,
}

/// Both tests in this binary own the one host rig; cargo runs test fns in
/// parallel threads by default, so an unfiltered `--ignored` invocation
/// would have them tear down each other's namespaces mid-run. Serialize.
static RIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const RIG_LOCKFILE: &str = "/srv/replicore/.rig.lock";

/// Acquire the cross-process rig lock, NON-blocking: if another replicore
/// rig process (the soak) holds it, fail LOUD and immediately rather than
/// corrupting a shared run. `flock` contends across processes (and across
/// open descriptions), which is exactly the scope we need.
fn acquire_rig_flock() -> std::fs::File {
    use std::os::unix::io::AsRawFd;
    std::fs::create_dir_all("/srv/replicore").expect("mkdir /srv/replicore");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(RIG_LOCKFILE)
        .expect("open rig lockfile");
    // SAFETY: valid fd; LOCK_EX|LOCK_NB has no other preconditions.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        panic!(
            "rig is BUSY: another replicore rig process (the soak?) holds {RIG_LOCKFILE}. \
             Stop it before running the integration rig tests — they share one host rig."
        );
    }
    f
}

/// Tear down any stale rig, bring up a fresh one (netem per MODE), wipe state
/// dirs, generate identities, and write both configs.
fn setup() -> Bed {
    let lock = RIG_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        panic!("this test must run as root (sudo -E)");
    }
    assert!(bin().exists(), "build first: cargo build --release");
    let flock = acquire_rig_flock();

    let _ = sh(&["down"]); // stale rig from a previous failed run
    let up = sh(&["up"]);
    assert!(up.status.success(), "testbed up failed: {up:?}");
    let rig = Rig;

    for d in [DIR_A, DIR_B, ETC, STATE] {
        let _ = std::fs::remove_dir_all(d);
        std::fs::create_dir_all(d).expect("mkdir");
    }

    let fp_a = gen_cert("node-a");
    let fp_b = gen_cert("node-b");
    let addr_a = format!("{IP_A}:{PORT}");
    let addr_b = format!("{IP_B}:{PORT}");
    let cfg_a = write_config(
        "node-a.toml",
        NODE_A,
        &addr_a,
        DIR_A,
        &format!("{STATE}/node-a.db"),
        "node-a",
        (NODE_B, &addr_b, &fp_b),
    );
    let cfg_b = write_config(
        "node-b.toml",
        NODE_B,
        &addr_b,
        DIR_B,
        &format!("{STATE}/node-b.db"),
        "node-b",
        (NODE_A, &addr_a, &fp_a),
    );
    Bed {
        _rig: rig,
        cfg_a,
        cfg_b,
        fp_a,
        addr_a,
        _lock: lock,
        _flock: flock,
    }
}

fn oplog_rows(db: &str) -> i64 {
    let conn =
        rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open db read-only");
    conn.query_row("SELECT COUNT(*) FROM oplog", [], |r| r.get(0))
        .expect("count oplog")
}

/// The true no-storm invariant is "op counts reach a FIXED POINT", not "they
/// are identical at two arbitrary instants 8 s apart" — a crash-recovery
/// re-attribution op (a correct-but-orphaned file observed by the scanner
/// before its op redelivers) can still be settling at any single instant,
/// and is bounded, not a storm. Poll until both nodes' counts hold steady
/// across several reads; a genuine loop never stabilizes and trips the
/// timeout. (This is also what made the suite fragile to rig contention: an
/// external writer adding files looks like unbounded growth — correctly — so
/// the rig lock below keeps the rig single-tenant.)
fn await_oplog_fixed_point(db_a: &str, db_b: &str) -> (i64, i64) {
    let mut last = (-1, -1);
    let mut stable = 0;
    for _ in 0..120 {
        let now = (oplog_rows(db_a), oplog_rows(db_b));
        if now == last {
            stable += 1;
            if stable >= 4 {
                return now;
            }
        } else {
            stable = 0;
            last = now;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("op counts never reached a fixed point (last={last:?}): storm/loop");
}

#[test]
#[ignore = "needs root + netns; run: cargo build --release && sudo -E cargo test --test integration_wan -- --ignored --nocapture"]
fn two_node_wan_end_to_end() {
    let bed = setup();
    let (cfg_a, cfg_b) = (bed.cfg_a.clone(), bed.cfg_b.clone());
    let (fp_a, addr_a) = (bed.fp_a.clone(), bed.addr_a.clone());

    let _a = Node::spawn("rc-a", &cfg_a, "node-a");
    let mut b = Node::spawn("rc-b", &cfg_b, "node-b");

    // --- 1. bidirectional create/modify/delete (partitioned namespaces) ----
    std::fs::create_dir_all(format!("{DIR_A}/from-a")).expect("mkdir");
    std::fs::create_dir_all(format!("{DIR_B}/from-b")).expect("mkdir");
    std::fs::write(format!("{DIR_A}/from-a/one.txt"), b"v1 from A").expect("write");
    std::fs::write(format!("{DIR_B}/from-b/two.txt"), b"v1 from B").expect("write");

    wait_for("A->B create", Duration::from_secs(60), || {
        std::fs::read(format!("{DIR_B}/from-a/one.txt")).is_ok_and(|d| d == b"v1 from A")
    });
    wait_for("B->A create", Duration::from_secs(60), || {
        std::fs::read(format!("{DIR_A}/from-b/two.txt")).is_ok_and(|d| d == b"v1 from B")
    });

    std::fs::write(format!("{DIR_A}/from-a/one.txt"), b"v2 from A").expect("write");
    wait_for("A->B modify", Duration::from_secs(60), || {
        std::fs::read(format!("{DIR_B}/from-a/one.txt")).is_ok_and(|d| d == b"v2 from A")
    });

    std::fs::remove_file(format!("{DIR_A}/from-a/one.txt")).expect("rm");
    wait_for("A->B delete", Duration::from_secs(60), || {
        !Path::new(&format!("{DIR_B}/from-a/one.txt")).exists()
    });

    // --- 2. burst, then op counts quiesce (no loops/storms) ----------------
    for i in 0..25 {
        std::fs::write(format!("{DIR_A}/from-a/burst-{i}.bin"), [i as u8; 1024])
            .expect("write burst");
    }
    wait_for("burst replicated", Duration::from_secs(90), || {
        tree(DIR_A) == tree(DIR_B)
    });
    // No loop/storm: op counts must reach a FIXED POINT across several
    // scanner cycles (a real loop never stabilizes; a bounded crash-recovery
    // re-attribution does).
    await_oplog_fixed_point(&format!("{STATE}/node-a.db"), &format!("{STATE}/node-b.db"));

    // --- 3. kill -9 mid-burst; restart resumes, no dup, no corruption ------
    b.kill_dash_nine();
    for i in 25..50 {
        std::fs::write(format!("{DIR_A}/from-a/burst-{i}.bin"), [i as u8; 1024])
            .expect("write burst");
    }
    std::thread::sleep(Duration::from_secs(3)); // ops durably queued on A only
    drop(b); // ensure the old process is fully gone before rebinding the port
    let _b = Node::spawn("rc-b", &cfg_b, "node-b");
    wait_for(
        "resume after kill -9 converges trees",
        Duration::from_secs(120),
        || tree(DIR_A) == tree(DIR_B),
    );
    // No duplication: every op id is unique (UNIQUE constraint would have
    // failed the apply) — assert the burst file contents survived intact.
    let t = tree(DIR_B);
    assert_eq!(
        t.iter()
            .filter(|(p, _)| p.starts_with("from-a/burst-"))
            .count(),
        50
    );

    // --- 5. unlisted cert replicates nothing --------------------------------
    let _fp_x = gen_cert("node-x");
    let dir_x = "/srv/replicore/x";
    let _ = std::fs::remove_dir_all(dir_x);
    std::fs::create_dir_all(dir_x).expect("mkdir");
    // X pins A, but A does NOT pin X. Runs in rc-b's namespace on its own port.
    let cfg_x = write_config(
        "node-x.toml",
        NODE_X,
        &format!("{IP_B}:7100"),
        dir_x,
        &format!("{STATE}/node-x.db"),
        "node-x",
        (NODE_A, &addr_a, &fp_a),
    );
    let _x = Node::spawn("rc-b", &cfg_x, "node-x");
    std::fs::write(format!("{DIR_A}/from-a/secret.txt"), b"not for x").expect("write");
    wait_for("B still receives", Duration::from_secs(60), || {
        Path::new(&format!("{DIR_B}/from-a/secret.txt")).exists()
    });
    std::thread::sleep(Duration::from_secs(5)); // ample time to (not) leak
    assert!(
        tree(dir_x).is_empty(),
        "unlisted-cert node received data: {:?}",
        tree(dir_x)
    );

    eprintln!("[test] all WAN exit criteria demonstrated");
}

/// Crash-during-apply stress: kill -9 the receiver WHILE it is materializing
/// inbound ops, with the scanner running at a 1 s interval, ~20 times with the
/// kill swept across the apply window (mid-push, mid-fetch, mid-stage/rename,
/// post-commit-pre-ack). This is the regime where review finding #1 lived
/// (scanner walk racing recovery applies → false deletes): if a regression
/// reappears, files vanish from A or trees flap instead of converging.
///
/// Run SERIALLY (it owns the same rig as the other test):
///   sudo -E cargo test --test integration_wan kill_during -- --ignored --nocapture
#[test]
#[ignore = "needs root + netns; run: cargo build --release && sudo -E cargo test --test integration_wan kill_during -- --ignored --nocapture"]
fn kill_during_inbound_apply_loop() {
    const ITERATIONS: usize = 20;
    const FILES_PER_ITER: usize = 6;

    let bed = setup();
    let _a = Node::spawn("rc-a", &bed.cfg_a, "node-a");
    let mut b = Node::spawn("rc-b", &bed.cfg_b, "node-b");

    // Establish the link before the abuse starts.
    std::fs::create_dir_all(format!("{DIR_A}/from-a")).expect("mkdir");
    std::fs::write(format!("{DIR_A}/from-a/probe.txt"), b"probe").expect("write");
    wait_for("initial replication", Duration::from_secs(60), || {
        Path::new(&format!("{DIR_B}/from-a/probe.txt")).exists()
    });

    let mut expected = tree(DIR_A);
    for i in 0..ITERATIONS {
        // 64 KiB files: big enough that fetch+stage spans several shaped RTTs.
        for j in 0..FILES_PER_ITER {
            let body = vec![(i * 31 + j) as u8; 64 * 1024];
            std::fs::write(format!("{DIR_A}/from-a/r{i:02}-{j}.bin"), &body).expect("write");
        }
        // Sweep the kill point across the receive pipeline (200ms..2.1s).
        std::thread::sleep(Duration::from_millis(200 + (i as u64) * 100));
        b.kill_dash_nine();
        b = Node::spawn("rc-b", &bed.cfg_b, "node-b");

        wait_for(
            &format!("iteration {i} converges after kill -9"),
            Duration::from_secs(90),
            || {
                let ta = tree(DIR_A);
                !ta.is_empty() && ta == tree(DIR_B)
            },
        );

        // Finding-#1 guard: nothing ever replicated may vanish or regress on
        // A — a false delete minted by B's scanner racing its recovery
        // applies would propagate here as a missing file.
        let ta = tree(DIR_A);
        for (path, hash) in &expected {
            assert_eq!(
                ta.get(path),
                Some(hash),
                "iteration {i}: {path} vanished or regressed on A (false delete propagated)"
            );
        }
        expected = ta;
    }

    // Hygiene: no orphaned staging temps survive the kill loop (startup
    // sweep) and none linger after quiescence (atomic apply cleanup).
    std::thread::sleep(Duration::from_secs(3));
    let (ta, tb) = (temps(DIR_A), temps(DIR_B));
    assert!(
        ta.is_empty() && tb.is_empty(),
        "orphaned staging temps: A={ta:?} B={tb:?}"
    );

    // No storm: op counts must reach a fixed point after the abuse (a kill
    // loop legitimately mints bounded re-attribution ops as orphaned-correct
    // files are re-observed before redelivery; a real loop never settles).
    await_oplog_fixed_point(&format!("{STATE}/node-a.db"), &format!("{STATE}/node-b.db"));

    // Exact final census: probe + every burst file, byte-identical trees.
    let final_a = tree(DIR_A);
    assert_eq!(final_a.len(), 1 + ITERATIONS * FILES_PER_ITER);
    assert_eq!(final_a, tree(DIR_B));
    eprintln!(
        "[test] {ITERATIONS} kill -9 mid-apply iterations converged; no temps, no storm, no losses"
    );
}
