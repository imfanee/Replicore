//! Crash-recovery scanner re-attribution — the deterministic pin for the bug
//! CLASS the integration_wan findings pointed at (false-delete /
//! stale-write-clobber under crash injection). The flaky integration
//! failures themselves were rig contention (a second process writing the
//! shared share dir — see docs/notes / the task report); this is the real
//! product interleaving, exercised without the rig.
//!
//! The interleaving: node B is killed -9 mid-apply AFTER the staged file was
//! renamed into place (content + metadata already correct on disk) but
//! BEFORE the committing transaction recorded it. On restart, B's scanner
//! observes a file the `files` index knows nothing about — indistinguishable
//! from a local create — before A redelivers the op. Two invariants must
//! hold:
//!   1. a fully-applied-and-committed file is a scanner NO-OP (the no-storm
//!      law for a cleanly-recovered node);
//!   2. the orphaned-but-correct file re-attributes to at most ONE bounded
//!      op, never clobbers content, and converges byte-identically with A's
//!      redelivered op — the op count reaches a fixed point (no storm), with
//!      ZERO content loss.

use std::path::{Path, PathBuf};
use std::time::Duration;

use replicore::apply::apply_version;
use replicore::chunk::{chunk_file_into_cas, Cas, ChunkParams};
use replicore::config::Config;
use replicore::decide::{decide, Decision};
use replicore::ingest::{Ingest, LocalEvent};
use replicore::metadata::{Meta, OwnerPolicy};
use replicore::oplog::Store;
use replicore::proto::{op_id, OpRecord, OpType};
use replicore::suppress::Suppressor;
use replicore::vv::NodeId;

const NODE_B: NodeId = [0xbb; 16]; // the crashing receiver (this node)
const NODE_A: NodeId = [0xaa; 16]; // the origin/owner of the file
const PARAMS: ChunkParams = ChunkParams {
    min: 4096,
    avg: 16 * 1024,
    max: 64 * 1024,
};

/// A real receiver: store + cas + share dir + the running ingest pipeline,
/// wired exactly as the daemon wires them.
struct Receiver {
    _dir: tempfile::TempDir,
    share: PathBuf,
    store: Store,
    cas: Cas,
    suppress: Suppressor,
    tx: tokio::sync::mpsc::Sender<LocalEvent>,
}

impl Receiver {
    fn new() -> Receiver {
        let dir = tempfile::tempdir().unwrap();
        let share = dir.path().join("share");
        std::fs::create_dir_all(&share).unwrap();
        let store = Store::open(Path::new(":memory:"), NODE_B).unwrap();
        let cas = Cas::open(&dir.path().join("cas")).unwrap();
        let suppress = Suppressor::new();
        let cfg = Config::from_toml_str(&format!(
            r#"
            node_id   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            listen    = "127.0.0.1:0"
            share_dir = "{}"
            db_path   = "{}"
            cert_path = "{}"
            key_path  = "{}"
            quiesce_ms = 20
            scan_interval_secs = 1
            "#,
            share.display(),
            dir.path().join("db").display(),
            dir.path().join("c").display(),
            dir.path().join("k").display(),
        ))
        .unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(Ingest::new(cfg, store.clone(), suppress.clone(), cas.clone(), rx).run());
        Receiver {
            _dir: dir,
            share,
            store,
            cas,
            suppress,
            tx,
        }
    }

    /// The full, committed apply of an A-origin write (file on disk + row).
    async fn apply_committed(&self, op: &OpRecord, data: &[u8]) {
        let hash = op.content_hash.unwrap();
        let manifest = {
            let p = self.share.join(format!(".stage-{}", op.origin_seq));
            std::fs::write(&p, data).unwrap();
            let m = chunk_file_into_cas(&p, &PARAMS, &self.cas).unwrap();
            std::fs::remove_file(&p).ok();
            m
        };
        self.store.put_manifest(manifest.clone()).await.unwrap();
        let local = self.store.load_file(&op.path).await.unwrap();
        let decision = decide(local.as_ref(), &op.vv);
        if decision == Decision::Apply {
            self.stage_to_disk(op, &hash, &manifest);
        }
        self.store.apply_remote(op.clone(), decision).await.unwrap();
    }

    /// The crash variant: stage the file onto disk + CAS + manifest exactly
    /// as a real apply would (content and metadata correct), but DO NOT run
    /// the committing transaction — the kill landed after rename, before
    /// commit. The `files` index has no row, `applied` has no entry.
    async fn apply_orphaned(&self, op: &OpRecord, data: &[u8]) {
        let hash = op.content_hash.unwrap();
        let p = self.share.join(format!(".stage-{}", op.origin_seq));
        std::fs::write(&p, data).unwrap();
        let manifest = chunk_file_into_cas(&p, &PARAMS, &self.cas).unwrap();
        std::fs::remove_file(&p).ok();
        self.store.put_manifest(manifest.clone()).await.unwrap();
        self.stage_to_disk(op, &hash, &manifest);
        // No apply_remote: the commit is exactly what the crash skipped.
        assert!(self.store.load_file(&op.path).await.unwrap().is_none());
        assert!(!self.store.has_applied(op.op_id).await.unwrap());
    }

    fn stage_to_disk(&self, op: &OpRecord, hash: &[u8; 32], manifest: &replicore::chunk::Manifest) {
        apply_version(
            &self.share,
            &op.path,
            op.mode,
            Some(hash),
            Some(manifest),
            &self.cas,
            op.meta.as_ref(),
            OwnerPolicy::Skip,
            &self.suppress,
        )
        .unwrap();
    }

    async fn op_count(&self) -> i64 {
        self.store.op_count().await.unwrap()
    }

    /// Poll until op_count is stable across `stable` consecutive reads (the
    /// TRUE no-storm invariant: a fixed point, not flatness at one instant).
    async fn wait_op_fixed_point(&self, stable: u32) -> i64 {
        let mut last = -1;
        let mut run = 0;
        for _ in 0..200 {
            let c = self.op_count().await;
            if c == last {
                run += 1;
                if run >= stable {
                    return c;
                }
            } else {
                run = 0;
                last = c;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("op count never reached a fixed point (last={last})");
    }
}

/// Build an A-origin write op carrying real metadata captured from `data`
/// written at `path` (so the receiver's re-capture can match it exactly).
fn a_write_op(seq: i64, path: &str, data: &[u8], meta: Meta) -> OpRecord {
    OpRecord {
        op_id: op_id(&NODE_A, seq),
        origin: NODE_A,
        origin_seq: seq,
        op_type: OpType::Write,
        path: path.into(),
        path_old: None,
        uuid: Some([0x11; 16]),
        mode: meta.mode,
        size: data.len() as u64,
        content_hash: Some(*blake3::hash(data).as_bytes()),
        meta: Some(meta),
        vv: [(NODE_A, seq as u64)].into_iter().collect(),
    }
}

/// A Meta whose mtime matches what the receiver's fs will report after
/// apply_meta sets it — captured from a probe file so the round trip is
/// byte-exact (mirrors what the daemon stores in the op).
fn meta_for(data: &[u8]) -> Meta {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("probe");
    std::fs::write(&p, data).unwrap();
    let mut m = Meta::capture(&p, OwnerPolicy::Skip).unwrap().unwrap();
    m.mode = 0o644;
    m.mtime_s = 1_700_000_000;
    m.mtime_ns = 0;
    m
}

/// Invariant 1: a cleanly-applied-and-committed file is a scanner no-op —
/// re-observation mints nothing (content AND meta match the committed row).
#[tokio::test(flavor = "multi_thread")]
async fn committed_file_reobserved_is_a_no_op() {
    let r = Receiver::new();
    let data = b"call recording bytes".to_vec();
    let op = a_write_op(1, "from-a/rec.wav", &data, meta_for(&data));
    r.apply_committed(&op, &data).await;
    assert_eq!(r.op_count().await, 1);

    // The scanner re-walks and re-observes the file (suppression has long
    // since been swept in a real run; force the worst case by sweeping now).
    r.suppress.sweep(Duration::from_millis(0));
    for _ in 0..4 {
        r.tx.send(LocalEvent::Write(r.share.join("from-a/rec.wav")))
            .await
            .unwrap();
    }
    let count = r.wait_op_fixed_point(3).await;
    assert_eq!(count, 1, "a recovered file must not re-emit (no-storm law)");
    // Content intact.
    assert_eq!(std::fs::read(r.share.join("from-a/rec.wav")).unwrap(), data);
}

/// Invariant 2: the orphaned-but-correct file (crash after rename, before
/// commit) re-attributes to a BOUNDED op, never clobbers content, and
/// converges byte-identically with A's redelivered op — op count reaches a
/// fixed point, zero content loss.
#[tokio::test(flavor = "multi_thread")]
async fn orphaned_file_reattributes_bounded_then_converges_with_redelivery() {
    let r = Receiver::new();
    let data = b"the correct bytes, staged then crash".to_vec();
    let op = a_write_op(7, "from-a/r07.bin", &data, meta_for(&data));

    // Crash variant: on disk, no row, no applied entry.
    r.apply_orphaned(&op, &data).await;
    assert_eq!(r.op_count().await, 0);

    // Restart: the scanner observes the orphan before A redelivers. Worst
    // case — suppression already swept.
    r.suppress.sweep(Duration::from_millis(0));
    r.tx.send(LocalEvent::Write(r.share.join("from-a/r07.bin")))
        .await
        .unwrap();
    let after_reattrib = r.wait_op_fixed_point(3).await;
    // BOUNDED: exactly one re-attribution op, not an unbounded storm.
    assert_eq!(
        after_reattrib, 1,
        "re-attribution must be bounded to one op"
    );
    // Content NOT clobbered — the bytes A staged survive.
    assert_eq!(std::fs::read(r.share.join("from-a/r07.bin")).unwrap(), data);

    // A redelivers its original op. decide sees B's re-attributed row
    // (concurrent), resolves; same content + meta ⇒ equal key ⇒ no copy,
    // VVs merge. Convergence with zero loss.
    let local = r.store.load_file("from-a/r07.bin").await.unwrap();
    let decision = decide(local.as_ref(), &op.vv);
    assert_eq!(
        decision,
        Decision::Concurrent,
        "A's op is concurrent with B's re-attribution"
    );
    // Drive the conflict resolution through the committing path, then record.
    resolve_then_record(&r, &op).await;

    // Fixed point, byte-identical content, zero copies (same bytes+meta).
    let final_count = r.wait_op_fixed_point(3).await;
    assert!(
        final_count <= 2,
        "op count must reach a small fixed point, got {final_count}"
    );
    let rows = r.store.all_files().await.unwrap();
    let winner = rows
        .iter()
        .find(|r| r.path == "from-a/r07.bin")
        .expect("file present");
    assert_eq!(winner.content_hash, Some(*blake3::hash(&data).as_bytes()));
    assert_eq!(winner.vv.get(&NODE_A), 7);
    assert_eq!(winner.vv.get(&NODE_B), 1, "both sides absorbed");
    assert!(
        !rows.iter().any(|r| r.path.contains(".sync-conflict-")),
        "identical bytes+meta must not mint a copy"
    );
    assert_eq!(std::fs::read(r.share.join("from-a/r07.bin")).unwrap(), data);

    // Re-observation after convergence is a pure no-op (true no-storm).
    r.suppress.sweep(Duration::from_millis(0));
    r.tx.send(LocalEvent::Write(r.share.join("from-a/r07.bin")))
        .await
        .unwrap();
    assert_eq!(r.wait_op_fixed_point(3).await, final_count);
}

/// Resolve a Concurrent op through resolve_rows (the committing path) the way
/// net.rs::resolve_concurrent_op does, then record the op — minus the network
/// fetch (B already holds the bytes).
async fn resolve_then_record(r: &Receiver, op: &OpRecord) {
    use replicore::conflict::{Version, META_NONE};
    use replicore::oplog::ResolveOutcome;
    let remote = Version {
        tombstone: false,
        content_hash: op.content_hash,
        meta_hash: op
            .meta
            .as_ref()
            .map(|m| Meta::hash_of(&Some(m.clone())))
            .unwrap_or(META_NONE),
        meta: op.meta.clone(),
        mode: op.mode,
        size: op.size,
        vv: op.vv.clone(),
        uuid: op.uuid,
    };
    let mut staged = Vec::new();
    for _ in 0..4 {
        match r
            .store
            .resolve_rows(&op.path, remote.clone(), std::mem::take(&mut staged))
            .await
            .unwrap()
        {
            ResolveOutcome::Resolved | ResolveOutcome::NotConcurrent(_) => break,
            ResolveOutcome::Stale { plan } => staged = plan,
            ResolveOutcome::Unresolvable => break,
        }
    }
    r.store
        .apply_remote(op.clone(), Decision::Concurrent)
        .await
        .unwrap();
}
