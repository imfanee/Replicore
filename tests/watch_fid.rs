//! FID watcher end-to-end (FR-102): create / attrib / rename / delete events
//! against a real filesystem, through the real fanotify read loop.
//!
//! Needs CAP_SYS_ADMIN and a file-handle-capable filesystem; the test probes
//! first and SKIPS (passes vacuously, with a stderr note) where fanotify FID
//! mode is unavailable — the legacy tier plus the scanner backstop is the
//! supported degradation there, covered by the existing scanner tests.

use std::path::{Path, PathBuf};
use std::time::Duration;

use replicore::ingest::LocalEvent;

/// Mount a private tmpfs over `dir` (root only): the FILESYSTEM mark then
/// sees ONLY this test's events instead of the whole build's I/O storm —
/// keeps the watcher loop quiet and the parallel test binaries unskewed.
/// Falls back to the shared filesystem when mounting is not permitted.
struct QuietFs(Option<PathBuf>);

impl QuietFs {
    fn over(dir: &Path) -> QuietFs {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid NUL-terminated strings; tmpfs needs no data arg.
        let rc = unsafe {
            libc::mount(
                c"tmpfs".as_ptr(),
                c.as_ptr(),
                c"tmpfs".as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        QuietFs((rc == 0).then(|| dir.to_path_buf()))
    }
}

impl Drop for QuietFs {
    fn drop(&mut self) {
        if let Some(dir) = &self.0 {
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(dir.as_os_str().as_bytes()).unwrap();
            // SAFETY: lazy-detach the mount we created (tempdir cleanup needs it gone).
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
    }
}

fn fid_supported() -> bool {
    // SAFETY: plain probe; the fd is closed immediately.
    let fan = unsafe {
        libc::fanotify_init(
            libc::FAN_CLASS_NOTIF | libc::FAN_REPORT_DFID_NAME | libc::FAN_CLOEXEC,
            (libc::O_RDONLY | libc::O_LARGEFILE) as u32,
        )
    };
    if fan < 0 {
        return false;
    }
    // The FILESYSTEM mark is the part old kernels / weird mounts refuse.
    let cwd = std::ffi::CString::new("/tmp").unwrap();
    // SAFETY: valid fd and path.
    let rc = unsafe {
        libc::fanotify_mark(
            fan,
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            libc::FAN_CREATE | libc::FAN_DELETE,
            libc::AT_FDCWD,
            cwd.as_ptr(),
        )
    };
    // SAFETY: fan opened above.
    unsafe { libc::close(fan) };
    rc == 0
}

/// Receive events until `pred` matches or the timeout lapses.
async fn recv_matching(
    rx: &mut tokio::sync::mpsc::Receiver<LocalEvent>,
    what: &str,
    mut pred: impl FnMut(&LocalEvent) -> bool,
) -> LocalEvent {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("watcher channel closed");
        if pred(&ev) {
            return ev;
        }
        // Unrelated event (another file on the same filesystem, or a
        // duplicate notification): keep draining.
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fid_watcher_reports_create_attrib_rename_delete() {
    if !fid_supported() {
        eprintln!("SKIP: fanotify FID mode unavailable (capability or kernel)");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let _quiet = QuietFs::over(dir.path());
    let share = dir.path().join("share");
    std::fs::create_dir_all(&share).unwrap();
    let share_c = share.clone();

    let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
    let rescan = std::sync::Arc::new(tokio::sync::Notify::new());
    let rescan_c = rescan.clone();
    std::thread::spawn(move || {
        let _ = replicore::watch::run(&share_c, tx, rescan_c);
    });
    // Let the marks arm.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // CREATE + CLOSE_WRITE → Write(abs).
    let f1 = share.join("a.txt");
    std::fs::write(&f1, b"v1").unwrap();
    recv_matching(
        &mut rx,
        "create/write of a.txt",
        |ev| matches!(ev, LocalEvent::Write(p) if p == &f1),
    )
    .await;

    // ATTRIB (chmod, the xattr-only-change channel) → Write(abs).
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&f1, std::fs::Permissions::from_mode(0o600)).unwrap();
    recv_matching(
        &mut rx,
        "attrib of a.txt",
        |ev| matches!(ev, LocalEvent::Write(p) if p == &f1),
    )
    .await;

    // RENAME → one identity-preserving event (tier 1) or delete+write
    // (tier 2 kernels) — accept both shapes.
    let f2 = share.join("b.txt");
    std::fs::rename(&f1, &f2).unwrap();
    let got = recv_matching(&mut rx, "rename a.txt -> b.txt", |ev| match ev {
        LocalEvent::Rename { from, to } => from == "a.txt" && to == &f2,
        LocalEvent::Delete(p) => p == "a.txt",
        LocalEvent::Write(p) => p == &f2,
    })
    .await;
    if matches!(got, LocalEvent::Rename { .. }) {
        eprintln!("tier 1: FAN_RENAME delivered as an identity-preserving event");
    }

    // DELETE → Delete(rel).
    std::fs::remove_file(&f2).unwrap();
    recv_matching(
        &mut rx,
        "delete of b.txt",
        |ev| matches!(ev, LocalEvent::Delete(p) if p == "b.txt"),
    )
    .await;

    // Staging temps never surface (self-event hygiene).
    let tmp = share.join(format!(".x{}{}.1.2", replicore::TMP_SUFFIX, ""));
    std::fs::write(&tmp, b"staged").unwrap();
    std::fs::remove_file(&tmp).unwrap();
    let quiet = tokio::time::timeout(Duration::from_millis(700), async {
        loop {
            if let Some(ev) = rx.recv().await {
                let touches_tmp = match &ev {
                    LocalEvent::Write(p) => p == &tmp,
                    LocalEvent::Delete(r) => share.join(r) == tmp,
                    LocalEvent::Rename { from, to } => share.join(from) == tmp || to == &tmp,
                };
                if touches_tmp {
                    return ev;
                }
            }
        }
    })
    .await;
    assert!(quiet.is_err(), "staging temp surfaced: {:?}", quiet.ok());
}

/// The rename event feeds the real identity-preserving append: watcher →
/// ingest → ONE Rename op carrying the uuid (FR-205 end-to-end).
#[tokio::test(flavor = "multi_thread")]
async fn fid_rename_becomes_one_identity_preserving_op() {
    if !fid_supported() {
        eprintln!("SKIP: fanotify FID mode unavailable (capability or kernel)");
        return;
    }
    // Probe tier 1 (FAN_RENAME) — tier 2 kernels deliver delete+create,
    // which is the documented degradation, not this test's subject.
    // (Kernel >= 5.17.)
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let mut parts = release.split('.');
    let major: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let minor: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    if (major, minor) < (5, 17) {
        eprintln!("SKIP: kernel {release} has no FAN_RENAME");
        return;
    }

    use replicore::chunk::Cas;
    use replicore::config::Config;
    use replicore::ingest::Ingest;
    use replicore::oplog::Store;
    use replicore::suppress::Suppressor;
    use replicore::vv::NodeId;

    const NODE: NodeId = [0xaa; 16];
    let dir = tempfile::tempdir().unwrap();
    let _quiet = QuietFs::over(dir.path());
    let share = dir.path().join("share");
    std::fs::create_dir_all(&share).unwrap();
    let store = Store::open(std::path::Path::new(":memory:"), NODE).unwrap();
    let cfg = Config {
        node_id: NODE,
        listen: "127.0.0.1:0".parse().unwrap(),
        share_dir: share.clone(),
        db_path: dir.path().join("db"),
        cas_dir: dir.path().join("cas"),
        cert_path: dir.path().join("c"),
        key_path: dir.path().join("k"),
        health_listen: None,
        admin_pubkey: None,
        roster_path: dir.path().join("roster.json"),
        control_socket: dir.path().join("ctl.sock"),
        peers: vec![],
        quiesce_ms: 30,
        scan_interval_secs: 3600, // no scanner: the watcher must carry this
        reconcile_interval_secs: 300,
        max_file_bytes: 1 << 20,
        chunk_min_bytes: 4096,
        chunk_avg_bytes: 16 * 1024,
        chunk_max_bytes: 64 * 1024,
        per_file_chunk_concurrency: 4,
        max_concurrent_transfers: 4,
        serve_concurrency: 8,
        owner_policy: replicore::metadata::OwnerPolicy::Skip,
        bandwidth: Default::default(),
        reserve_bytes: 0,
        reserve_percent: 0.0,
    };
    let cas = Cas::open(&cfg.cas_dir).unwrap();
    let suppress = Suppressor::new();
    let (tx, rx) = tokio::sync::mpsc::channel(1024);
    tokio::spawn(Ingest::new(cfg, store.clone(), suppress, cas, rx).run());
    let rescan = std::sync::Arc::new(tokio::sync::Notify::new());
    {
        let share = share.clone();
        let rescan = rescan.clone();
        std::thread::spawn(move || {
            let _ = replicore::watch::run(&share, tx, rescan);
        });
    }
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Create, let it become an op, then rename.
    let f = share.join("rec.wav");
    std::fs::write(&f, b"payload").unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while store.op_count().await.unwrap() < 1 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "create never became an op"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    std::fs::rename(&f, share.join("renamed.wav")).unwrap();
    while store.op_count().await.unwrap() < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "rename never became an op"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let ops = store.ops_since(NODE, 0, 10).await.unwrap();
    assert_eq!(ops.len(), 2, "exactly create + rename, not delete+create");
    assert_eq!(ops[1].op_type, replicore::proto::OpType::Rename);
    assert_eq!(ops[1].path, "renamed.wav");
    assert_eq!(ops[1].path_old.as_deref(), Some("rec.wav"));
    assert_eq!(ops[1].uuid, ops[0].uuid, "identity travels with the move");
    let _ = PathBuf::new(); // keep the import used on skip paths
}
