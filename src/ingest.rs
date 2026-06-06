//! ingest.rs — the local-change pipeline (FR-101/105, FR-901/902).
//!
//! Watcher and scanner events funnel through one channel into this task,
//! which turns observed filesystem state into ops:
//!
//! ```text
//! event → debounce/quiesce (per path) → hash on disk
//!       → suppression check   (was this OUR remote apply?    FR-902)
//!       → store no-op filter  (is this content already known? FR-901)
//!       → append_local        (VV increment + oplog + index, one tx)
//! ```
//!
//! Both loop defenses run on every event, from either source; push loops wake
//! off the store's `watch_latest`, so nothing here talks to the network.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::config::Config;
use crate::oplog::{LocalChange, Store};
use crate::proto::OpType;
use crate::suppress::Suppressor;

/// A locally-observed mutation, from the watcher (writes, low latency) or the
/// scanner (writes + deletes, authoritative backstop).
#[derive(Clone, Debug)]
pub enum LocalEvent {
    /// Absolute path inside the share that was written/observed on disk.
    Write(PathBuf),
    /// Share-relative path that is live in the index but gone from disk.
    Delete(String),
}

pub struct Ingest {
    cfg: Config,
    store: Store,
    suppress: Suppressor,
    rx: mpsc::Receiver<LocalEvent>,
    /// rel path → (absolute path, quiescence deadline). Coalesces bursts:
    /// a thousand rapid writes to one file become one hash + one op (FR-105).
    pending: HashMap<String, (PathBuf, Instant)>,
}

impl Ingest {
    pub fn new(
        cfg: Config,
        store: Store,
        suppress: Suppressor,
        rx: mpsc::Receiver<LocalEvent>,
    ) -> Ingest {
        Ingest {
            cfg,
            store,
            suppress,
            rx,
            pending: HashMap::new(),
        }
    }

    /// Run until the event channel closes. Per-event failures are logged and
    /// skipped — the periodic scan re-observes anything missed.
    pub async fn run(mut self) {
        let quiesce = Duration::from_millis(self.cfg.quiesce_ms.max(1));
        // Suppression entries must outlive one full scanner cycle (the racing
        // walk that needs them), with margin.
        let sweep_ttl = Duration::from_secs(self.cfg.scan_interval_secs.max(1) * 2 + 30);
        let mut tick = tokio::time::interval(Duration::from_millis(
            (self.cfg.quiesce_ms / 2).clamp(10, 250),
        ));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = self.rx.recv() => match event {
                    None => return, // all producers gone: shutting down
                    Some(LocalEvent::Write(abs)) => {
                        if let Some(rel) = self.relativize(&abs) {
                            // (Re)arm the quiescence timer for this path.
                            self.pending.insert(rel, (abs, Instant::now() + quiesce));
                        }
                    }
                    Some(LocalEvent::Delete(rel)) => self.handle_delete(rel).await,
                },
                _ = tick.tick() => {
                    self.flush_ripe().await;
                    self.suppress.sweep(sweep_ttl);
                }
            }
        }
    }

    /// Convert a watcher/scanner absolute path to the share-relative String
    /// the protocol speaks. Non-UTF-8 names are skipped with a warning (full
    /// fidelity is M3, FR-106).
    fn relativize(&self, abs: &std::path::Path) -> Option<String> {
        let rel = abs.strip_prefix(&self.cfg.share_dir).ok()?;
        match rel.to_str() {
            Some(s) if !s.is_empty() => Some(s.to_string()),
            _ => {
                tracing::warn!(path = %abs.display(), "skipping non-UTF-8 or empty relative path");
                None
            }
        }
    }

    async fn flush_ripe(&mut self) {
        let now = Instant::now();
        let ripe: Vec<(String, PathBuf)> = self
            .pending
            .iter()
            .filter(|(_, (_, deadline))| *deadline <= now)
            .map(|(rel, (abs, _))| (rel.clone(), abs.clone()))
            .collect();
        for (rel, abs) in ripe {
            self.pending.remove(&rel);
            self.handle_write(rel, abs).await;
        }
    }

    async fn handle_write(&mut self, rel: String, abs: PathBuf) {
        let max = self.cfg.max_file_bytes;
        // Hash + metadata off the async runtime (whole-file read; chunked
        // streaming hash is M2).
        let observed = tokio::task::spawn_blocking(move || -> std::io::Result<Option<Observed>> {
            let meta = std::fs::symlink_metadata(&abs)?;
            if !meta.is_file() {
                return Ok(None); // symlinks/dirs/special: M3 fidelity (FR-106)
            }
            if meta.len() > max {
                return Ok(Some(Observed::TooBig(meta.len())));
            }
            let data = std::fs::read(&abs)?;
            use std::os::unix::fs::PermissionsExt;
            Ok(Some(Observed::File {
                hash: *blake3::hash(&data).as_bytes(),
                size: data.len() as u64,
                mode: meta.permissions().mode() & 0o7777,
            }))
        })
        .await;

        let observed = match observed {
            Ok(Ok(Some(o))) => o,
            Ok(Ok(None)) => return,
            // Vanished between event and read: the scanner's delete pass owns it.
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => return,
            Ok(Err(e)) => {
                tracing::warn!(path = %rel, error = %e, "cannot read changed file; skipping");
                return;
            }
            Err(join) => {
                tracing::error!(error = %join, "hashing task failed");
                return;
            }
        };
        let (hash, size, mode) = match observed {
            Observed::TooBig(len) => {
                tracing::warn!(path = %rel, len, "file exceeds max_file_bytes; not replicated");
                return;
            }
            Observed::File { hash, size, mode } => (hash, size, mode),
        };

        // Loop defense 1 (FR-902): our own remote apply observed back.
        if self.suppress.check_write(&rel, &hash) {
            tracing::debug!(path = %rel, "suppressed self-apply write event");
            return;
        }

        // Loop defense 2 (FR-901) lives in the store: append_local no-ops on
        // identical content, atomically with the VV increment.
        match self
            .store
            .append_local(LocalChange {
                path: rel.clone(),
                op_type: OpType::Write,
                mode,
                size,
                content_hash: Some(hash),
            })
            .await
        {
            Ok(Some(op)) => {
                tracing::info!(path = %rel, seq = op.origin_seq, "local write -> op")
            }
            Ok(None) => tracing::debug!(path = %rel, "unchanged content; no op"),
            Err(e) => tracing::error!(path = %rel, error = %e, "append_local failed"),
        }
    }

    async fn handle_delete(&mut self, rel: String) {
        // Authoritative last look: the scanner's delete observation is a
        // snapshot diff (disk walked, THEN index queried), so a remote write
        // applied mid-pass can surface here as a false delete for a file
        // that exists. Tombstoning is destructive and propagates — re-verify
        // absence at the choke point before emitting it.
        if tokio::fs::symlink_metadata(self.cfg.share_dir.join(&rel))
            .await
            .is_ok()
        {
            tracing::debug!(path = %rel, "delete observation stale (path exists); skipping");
            return;
        }

        // A pending write for a now-gone path is moot.
        self.pending.remove(&rel);

        // Loop defense 1 (FR-902): our own remote delete observed back.
        if self.suppress.check_delete(&rel) {
            tracing::debug!(path = %rel, "suppressed self-apply delete event");
            return;
        }

        match self
            .store
            .append_local(LocalChange {
                path: rel.clone(),
                op_type: OpType::Delete,
                mode: 0,
                size: 0,
                content_hash: None,
            })
            .await
        {
            Ok(Some(op)) => {
                tracing::info!(path = %rel, seq = op.origin_seq, "local delete -> tombstone op")
            }
            Ok(None) => tracing::debug!(path = %rel, "unknown/tombstoned path; no op"),
            Err(e) => tracing::error!(path = %rel, error = %e, "append_local failed"),
        }
    }
}

enum Observed {
    File {
        hash: [u8; 32],
        size: u64,
        mode: u32,
    },
    TooBig(u64),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vv::NodeId;
    use std::path::Path;

    const NODE: NodeId = [0xaa; 16];

    struct Rig {
        _dir: tempfile::TempDir,
        share: PathBuf,
        store: Store,
        suppress: Suppressor,
        tx: mpsc::Sender<LocalEvent>,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let store = Store::open(Path::new(":memory:"), NODE).unwrap();
        let suppress = Suppressor::new();
        let cfg = Config {
            node_id: NODE,
            listen: "127.0.0.1:0".parse().unwrap(),
            share_dir: share.clone(),
            db_path: dir.path().join("db"),
            cas_dir: dir.path().join("cas"),
            cert_path: dir.path().join("c"),
            key_path: dir.path().join("k"),
            health_listen: None,
            peers: vec![],
            quiesce_ms: 30,
            scan_interval_secs: 1,
            reconcile_interval_secs: 300,
            max_file_bytes: 1024,
            chunk_min_bytes: 4096,
            chunk_avg_bytes: 16 * 1024,
            chunk_max_bytes: 64 * 1024,
            per_file_chunk_concurrency: 4,
            max_concurrent_transfers: 4,
            serve_concurrency: 8,
        };
        let (tx, rx) = mpsc::channel(64);
        let ingest = Ingest::new(cfg, store.clone(), suppress.clone(), rx);
        tokio::spawn(ingest.run());
        Rig {
            _dir: dir,
            share,
            store,
            suppress,
            tx,
        }
    }

    async fn settle() {
        tokio::time::sleep(Duration::from_millis(120)).await;
    }

    #[tokio::test]
    async fn write_event_becomes_op_once() {
        let r = rig();
        let f = r.share.join("a/x.txt");
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, b"v1").unwrap();

        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        // Burst: several events for the same path coalesce (FR-105).
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 1);

        // Re-observation of unchanged content (scanner re-walk): no new op.
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 1);

        // Actual change: second op, VV bumped.
        std::fs::write(&f, b"v2").unwrap();
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 2);
        let ops = r.store.ops_since(NODE, 0, 10).await.unwrap();
        assert_eq!(ops[1].vv.get(&NODE), 2);
    }

    #[tokio::test]
    async fn suppressed_apply_event_emits_no_op() {
        let r = rig();
        let f = r.share.join("from-peer.bin");
        let data = b"remote bytes";
        let hash = *blake3::hash(data).as_bytes();
        // Simulate the remote-apply path: suppression registered, then the
        // file appears, then the watcher/scanner observes it.
        r.suppress.register_write("from-peer.bin", hash);
        std::fs::write(&f, data).unwrap();
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        settle().await;
        // FR-902: no outbound op for our own apply.
        assert_eq!(r.store.op_count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn delete_event_tombstones_known_path() {
        let r = rig();
        let f = r.share.join("gone.txt");
        std::fs::write(&f, b"data").unwrap();
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 1);

        std::fs::remove_file(&f).unwrap();
        r.tx.send(LocalEvent::Delete("gone.txt".into()))
            .await
            .unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 2);
        let local = r.store.load_file("gone.txt").await.unwrap().unwrap();
        assert!(local.tombstone);

        // Suppressed delete (our own remote apply): no op.
        r.suppress.register_delete("other");
        r.tx.send(LocalEvent::Delete("other".into())).await.unwrap();
        // Unknown path delete: also no op.
        r.tx.send(LocalEvent::Delete("never-seen".into()))
            .await
            .unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn stale_delete_for_existing_file_is_ignored() {
        // Race found in review: the scanner walks the disk BEFORE querying
        // the index, so a remote write applied mid-pass shows up as a live
        // index row with no walked file -> a false Delete observation. The
        // file exists; tombstoning it would propagate a transient deletion.
        let r = rig();
        let f = r.share.join("raced.bin");
        std::fs::write(&f, b"applied mid-scan").unwrap();
        r.tx.send(LocalEvent::Write(f.clone())).await.unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 1);

        // Stale observation arrives while the file is very much on disk.
        r.tx.send(LocalEvent::Delete("raced.bin".into()))
            .await
            .unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 1, "false delete emitted");
        let local = r.store.load_file("raced.bin").await.unwrap().unwrap();
        assert!(!local.tombstone);

        // A genuine delete afterwards still works.
        std::fs::remove_file(&f).unwrap();
        r.tx.send(LocalEvent::Delete("raced.bin".into()))
            .await
            .unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 2);
        assert!(
            r.store
                .load_file("raced.bin")
                .await
                .unwrap()
                .unwrap()
                .tombstone
        );
    }

    #[tokio::test]
    async fn oversized_and_vanished_files_are_skipped() {
        let r = rig();
        let big = r.share.join("big");
        std::fs::write(&big, vec![0u8; 2048]).unwrap(); // > max_file_bytes
        r.tx.send(LocalEvent::Write(big)).await.unwrap();
        r.tx.send(LocalEvent::Write(r.share.join("ghost")))
            .await
            .unwrap();
        settle().await;
        assert_eq!(r.store.op_count().await.unwrap(), 0);
    }
}
