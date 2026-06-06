//! scanner.rs — baseline scan + periodic rescan (FR-103; FR-104-lite).
//!
//! The watcher is best-effort; **the rescan is authoritative** (see
//! docs/DEPLOYMENT-NFS.md — never weaken this on the assumption that fanotify
//! catches everything). Each pass walks the share and diffs against the
//! materialized index:
//!
//! - every regular file on disk      → `LocalEvent::Write` (ingest hashes it;
//!   unchanged content dies in the no-op filter, so steady-state cost is the
//!   hashing, not spurious ops)
//! - live index path missing on disk → `LocalEvent::Delete`
//!
//! The first pass at startup is the FR-103 baseline. Hashing the whole share
//! per cycle is the M1 price of authority. // SEAM(M2): Merkle subtree hashes
//! + mtime/size short-circuit make this O(changes).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::ingest::LocalEvent;
use crate::oplog::{Store, StoreError};
use crate::TMP_SUFFIX;

#[derive(thiserror::Error, Debug)]
pub enum ScanError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("walk {path}: {source}")]
    Walk {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("event channel closed")]
    ChannelClosed,
    #[error("walker task died: {0}")]
    Join(#[from] tokio::task::JoinError),
}

/// Run forever: baseline scan immediately (FR-103), then periodic passes.
/// Per-pass errors are logged; the loop keeps going (the next pass retries).
pub async fn run(cfg: Config, store: Store, tx: mpsc::Sender<LocalEvent>) {
    let interval = Duration::from_secs(cfg.scan_interval_secs.max(1));
    loop {
        match scan_once(&cfg.share_dir, &store, &tx).await {
            Ok(stats) => tracing::debug!(
                files = stats.files_seen,
                deletes = stats.deletes_emitted,
                "scan pass complete"
            ),
            Err(ScanError::ChannelClosed) => return, // shutting down
            Err(e) => tracing::warn!(error = %e, "scan pass failed; will retry"),
        }
        tokio::time::sleep(interval).await;
    }
}

pub struct ScanStats {
    pub files_seen: usize,
    pub deletes_emitted: usize,
}

/// One diff pass. Public for tests and for a future `resync` admin verb.
pub async fn scan_once(
    share_dir: &Path,
    store: &Store,
    tx: &mpsc::Sender<LocalEvent>,
) -> Result<ScanStats, ScanError> {
    // Walk on a blocking thread: directory trees can be large and cold.
    let root = share_dir.to_path_buf();
    let on_disk = tokio::task::spawn_blocking(move || walk(&root)).await??;

    let mut stats = ScanStats {
        files_seen: on_disk.len(),
        deletes_emitted: 0,
    };

    // Disk → index direction: hand every file to ingest (it hashes, runs
    // suppression + no-op filters, and appends only real changes).
    let mut disk_rels = BTreeSet::new();
    for abs in &on_disk {
        if let Ok(rel) = abs.strip_prefix(share_dir) {
            if let Some(rel) = rel.to_str() {
                disk_rels.insert(rel.to_string());
            }
        }
        tx.send(LocalEvent::Write(abs.clone()))
            .await
            .map_err(|_| ScanError::ChannelClosed)?;
    }

    // Index → disk direction: live rows whose file is gone were deleted
    // locally (possibly while we were down — the watcher never sees those).
    for row in store.live_files().await? {
        if !disk_rels.contains(&row.path) {
            stats.deletes_emitted += 1;
            tx.send(LocalEvent::Delete(row.path))
                .await
                .map_err(|_| ScanError::ChannelClosed)?;
        }
    }
    Ok(stats)
}

/// Collect every regular file under `root`, skipping our own staging temps.
/// Symlinks are not followed (M3 fidelity, FR-106).
fn walk(root: &Path) -> Result<Vec<PathBuf>, ScanError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|source| ScanError::Walk {
            path: dir.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| ScanError::Walk {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let ftype = entry.file_type().map_err(|source| ScanError::Walk {
                path: path.clone(),
                source,
            })?;
            if ftype.is_dir() {
                stack.push(path);
            } else if ftype.is_file() && !is_tmp(&path) {
                out.push(path);
            }
            // Symlinks / special files: skipped until M3 (FR-106).
        }
    }
    Ok(out)
}

/// Unlink every staging temp under `root`.
///
/// A kill -9 between staging and rename leaves a `.replicore-tmp` orphan that
/// the watcher and scanner both (correctly) ignore — nothing else ever
/// deletes it. Any temp present at startup predates this process and cannot
/// be in flight (one daemon per share). MUST be called before the engine
/// spawns, so the sweep can never race a live staging file.
pub fn sweep_orphan_temps(root: &Path) -> Result<usize, ScanError> {
    let mut removed = 0;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|source| ScanError::Walk {
            path: dir.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| ScanError::Walk {
                path: dir.clone(),
                source,
            })?;
            let path = entry.path();
            let ftype = entry.file_type().map_err(|source| ScanError::Walk {
                path: path.clone(),
                source,
            })?;
            if ftype.is_dir() {
                stack.push(path);
            } else if ftype.is_file() && is_tmp(&path) && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

fn is_tmp(p: &Path) -> bool {
    p.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.contains(TMP_SUFFIX))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oplog::LocalChange;
    use crate::proto::OpType;
    use crate::vv::NodeId;

    const NODE: NodeId = [0xaa; 16];

    #[test]
    fn orphan_temp_sweep_removes_only_temps() {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path();
        std::fs::create_dir_all(share.join("sub")).unwrap();
        std::fs::write(share.join("real.txt"), b"keep").unwrap();
        std::fs::write(share.join(format!(".f{TMP_SUFFIX}.123.0")), b"orphan").unwrap();
        std::fs::write(share.join(format!("sub/.g{TMP_SUFFIX}.123.1")), b"orphan").unwrap();

        let removed = sweep_orphan_temps(share).unwrap();
        assert_eq!(removed, 2);
        assert!(share.join("real.txt").exists());
        assert!(!share.join(format!(".f{TMP_SUFFIX}.123.0")).exists());
        assert!(!share.join(format!("sub/.g{TMP_SUFFIX}.123.1")).exists());
    }

    #[tokio::test]
    async fn baseline_emits_writes_and_diff_emits_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().to_path_buf();
        std::fs::create_dir_all(share.join("sub")).unwrap();
        std::fs::write(share.join("a.txt"), b"a").unwrap();
        std::fs::write(share.join("sub/b.txt"), b"b").unwrap();
        std::fs::write(share.join(format!("x{TMP_SUFFIX}.1.2")), b"staged").unwrap();

        let store = Store::open(Path::new(":memory:"), NODE).unwrap();
        let (tx, mut rx) = mpsc::channel(64);

        // Baseline: both real files reported, the staging temp ignored.
        let stats = scan_once(&share, &store, &tx).await.unwrap();
        assert_eq!(stats.files_seen, 2);
        assert_eq!(stats.deletes_emitted, 0);
        let mut seen = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            match ev {
                LocalEvent::Write(p) => seen.push(p),
                LocalEvent::Delete(p) => panic!("unexpected delete {p}"),
            }
        }
        seen.sort();
        assert_eq!(seen, vec![share.join("a.txt"), share.join("sub/b.txt")]);

        // Index knows a path; remove it from disk -> delete emitted.
        store
            .append_local(LocalChange {
                path: "a.txt".into(),
                op_type: OpType::Write,
                mode: 0o644,
                size: 1,
                content_hash: Some(*blake3::hash(b"a").as_bytes()),
            })
            .await
            .unwrap();
        std::fs::remove_file(share.join("a.txt")).unwrap();

        let stats = scan_once(&share, &store, &tx).await.unwrap();
        assert_eq!(stats.deletes_emitted, 1);
        let mut got_delete = false;
        while let Ok(ev) = rx.try_recv() {
            if let LocalEvent::Delete(p) = ev {
                assert_eq!(p, "a.txt");
                got_delete = true;
            }
        }
        assert!(got_delete);

        // Tombstoned rows are NOT re-reported as deletes on later passes.
        store
            .append_local(LocalChange {
                path: "a.txt".into(),
                op_type: OpType::Delete,
                mode: 0,
                size: 0,
                content_hash: None,
            })
            .await
            .unwrap();
        let stats = scan_once(&share, &store, &tx).await.unwrap();
        assert_eq!(stats.deletes_emitted, 0);
    }
}
