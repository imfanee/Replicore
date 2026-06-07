//! Crash-recovery test for the receive path (FR-801/802/803; exit criterion 3
//! at the unit level, no root or netns needed).
//!
//! The receive path's contract (plan §receive-path):
//!   fetch bytes → fs apply (stage/fsync/verify/rename) → ONE SQLite COMMIT
//!   (oplog + files + applied + recv_cursor) → ack.
//!
//! A `kill -9` between the RENAME and the COMMIT is the nasty window: the file
//! is on disk but the store knows nothing. The op was never acked, so the
//! sender redelivers; re-running the whole path must converge to exactly-once
//! semantics — same bytes, one oplog row, one VV merge, correct cursor.

use std::path::Path;

use replicore::apply::{apply_delete, apply_write};
use replicore::decide::{decide, Decision};
use replicore::oplog::Store;
use replicore::proto::{op_id, OpRecord, OpType};
use replicore::suppress::Suppressor;
use replicore::vv::NodeId;

const NODE_A: NodeId = [0xaa; 16]; // us (receiver)
const NODE_B: NodeId = [0xbb; 16]; // origin of the remote ops

fn remote_write(seq: i64, path: &str, data: &[u8], vv_b: u64) -> OpRecord {
    OpRecord {
        op_id: op_id(&NODE_B, seq),
        origin: NODE_B,
        origin_seq: seq,
        op_type: OpType::Write,
        path: path.into(),
        path_old: None,
        uuid: None,
        mode: 0o644,
        size: data.len() as u64,
        content_hash: Some(*blake3::hash(data).as_bytes()),
        vv: [(NODE_B, vv_b)].into_iter().collect(),
    }
}

/// One full, correct receive-path pass for a write op.
async fn deliver_write(store: &Store, share: &Path, op: &OpRecord, data: &[u8]) {
    // Step 2: idempotency fast path.
    if store.has_applied(op.op_id).await.unwrap() {
        return; // would just re-ack
    }
    // Step 3: decision.
    let local = store.load_file(&op.path).await.unwrap();
    let decision = decide(local.as_ref(), &op.vv);
    // Steps 4–5: bytes + atomic fs apply (only for Apply).
    if decision == Decision::Apply {
        let hash = op.content_hash.expect("write op carries a hash");
        let suppress = Suppressor::new();
        apply_write(share, &op.path, op.mode, &hash, data, &suppress).unwrap();
    }
    // Step 6: the durability point.
    store.apply_remote(op.clone(), decision).await.unwrap();
}

#[tokio::test]
async fn crash_between_rename_and_commit_recovers_exactly_once() {
    let dir = tempfile::tempdir().unwrap();
    let share = dir.path().join("share");
    std::fs::create_dir_all(&share).unwrap();
    let db = dir.path().join("state.db");

    let data = b"recording-bytes";
    let op = remote_write(1, "b/call.wav", data, 1);

    // --- First delivery, crashing in the bad window -------------------------
    {
        let store = Store::open(&db, NODE_A).unwrap();
        let local = store.load_file(&op.path).await.unwrap();
        assert_eq!(decide(local.as_ref(), &op.vv), Decision::Apply);

        // fs apply completes (RENAME happened)...
        let suppress = Suppressor::new();
        apply_write(
            &share,
            &op.path,
            op.mode,
            &op.content_hash.unwrap(),
            data,
            &suppress,
        )
        .unwrap();
        assert_eq!(std::fs::read(share.join("b/call.wav")).unwrap(), data);

        // ...and the process dies HERE: no apply_remote, no COMMIT, no ack.
        drop(store);
    }

    // --- Restart: store knows nothing, sender redelivers --------------------
    let store = Store::open(&db, NODE_A).unwrap();
    assert!(!store.has_applied(op.op_id).await.unwrap());
    assert!(store.load_file(&op.path).await.unwrap().is_none());
    assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 0); // never advanced

    deliver_write(&store, &share, &op, data).await;

    // Exactly-once end state.
    assert_eq!(std::fs::read(share.join("b/call.wav")).unwrap(), data);
    assert_eq!(store.op_count().await.unwrap(), 1);
    let local = store.load_file(&op.path).await.unwrap().unwrap();
    assert_eq!(local.vv.get(&NODE_B), 1); // merged exactly once
    assert!(!local.tombstone);
    assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 1);

    // --- Crash AFTER commit, BEFORE ack: redelivery is a pure no-op ---------
    deliver_write(&store, &share, &op, data).await;
    assert_eq!(store.op_count().await.unwrap(), 1); // no dup row
    let local2 = store.load_file(&op.path).await.unwrap().unwrap();
    assert_eq!(local2.vv.get(&NODE_B), 1); // no double merge
    assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 1);
}

/// M2 chunked-plane variant of the rename-vs-commit window: all chunks landed
/// in the CAS and the file was assembled+renamed, but the store commit never
/// happened. Redelivery must re-assemble purely from the CAS (zero refetched
/// chunks — FR-404) and converge to exactly-once.
#[tokio::test]
async fn crash_between_assemble_and_commit_resumes_from_cas() {
    use replicore::apply::apply_assembled;
    use replicore::chunk::{Cas, Manifest};
    use replicore::proto::ChunkEntry;

    let dir = tempfile::tempdir().unwrap();
    let share = dir.path().join("share");
    std::fs::create_dir_all(&share).unwrap();
    let db = dir.path().join("state.db");
    let cas = Cas::open(&dir.path().join("cas")).unwrap();

    // A 3-chunk file, chunks already fetched+verified into the CAS.
    let data: Vec<u8> = (0u32..30_000).map(|i| (i % 241) as u8).collect();
    let mut chunks = Vec::new();
    for piece in data.chunks(10_000) {
        let h = *blake3::hash(piece).as_bytes();
        cas.put_verified(&h, piece).unwrap();
        chunks.push(ChunkEntry {
            hash: h,
            len: piece.len() as u32,
        });
    }
    let manifest = Manifest {
        content_hash: *blake3::hash(&data).as_bytes(),
        chunks,
    };
    let op = OpRecord {
        op_id: op_id(&NODE_B, 1),
        origin: NODE_B,
        origin_seq: 1,
        op_type: OpType::Write,
        path: "b/chunked.bin".into(),
        path_old: None,
        uuid: None,
        mode: 0o644,
        size: data.len() as u64,
        content_hash: Some(manifest.content_hash),
        vv: [(NODE_B, 1u64)].into_iter().collect(),
    };

    // First delivery: manifest durable, chunks in CAS, file assembled and
    // RENAMED... and the process dies before apply_remote's COMMIT.
    {
        let store = Store::open(&db, NODE_A).unwrap();
        store.put_manifest(manifest.clone()).await.unwrap();
        let suppress = Suppressor::new();
        apply_assembled(
            &share,
            &op.path,
            op.mode,
            &manifest.content_hash,
            &manifest,
            &cas,
            &suppress,
        )
        .unwrap();
        assert_eq!(std::fs::read(share.join("b/chunked.bin")).unwrap(), data);
        drop(store); // kill -9 here
    }

    // Restart: op un-acked, store knows nothing about it — but the manifest
    // row and every chunk survived (their inserts are atomic).
    let store = Store::open(&db, NODE_A).unwrap();
    assert!(!store.has_applied(op.op_id).await.unwrap());
    let recovered = store
        .manifest_for(manifest.content_hash)
        .await
        .unwrap()
        .expect("manifest survived the crash");
    assert_eq!(recovered, manifest);
    for c in &manifest.chunks {
        assert!(cas.has(&c.hash), "chunk lost across the crash");
    }

    // Redelivery: decide=Apply, every chunk already present (the resume
    // question is a stat), re-assemble idempotently, then THE commit.
    let local = store.load_file(&op.path).await.unwrap();
    assert_eq!(decide(local.as_ref(), &op.vv), Decision::Apply);
    let suppress = Suppressor::new();
    apply_assembled(
        &share,
        &op.path,
        op.mode,
        &manifest.content_hash,
        &recovered,
        &cas,
        &suppress,
    )
    .unwrap();
    store
        .apply_remote(op.clone(), Decision::Apply)
        .await
        .unwrap();

    // Exactly-once end state.
    assert_eq!(std::fs::read(share.join("b/chunked.bin")).unwrap(), data);
    assert_eq!(store.op_count().await.unwrap(), 1);
    let local = store.load_file(&op.path).await.unwrap().unwrap();
    assert_eq!(local.vv.get(&NODE_B), 1);
    assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 1);
}

#[tokio::test]
async fn crash_between_unlink_and_commit_recovers_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let share = dir.path().join("share");
    std::fs::create_dir_all(&share).unwrap();
    let db = dir.path().join("state.db");

    let data = b"to-be-deleted";
    let write_op = remote_write(1, "b/x", data, 1);
    let delete_op = OpRecord {
        op_id: op_id(&NODE_B, 2),
        origin: NODE_B,
        origin_seq: 2,
        op_type: OpType::Delete,
        path: "b/x".into(),
        path_old: None,
        uuid: None,
        mode: 0o644,
        size: 0,
        content_hash: None,
        vv: [(NODE_B, 2u64)].into_iter().collect(),
    };

    {
        let store = Store::open(&db, NODE_A).unwrap();
        deliver_write(&store, &share, &write_op, data).await;

        // Delete arrives; fs unlink happens, then crash before COMMIT.
        let suppress = Suppressor::new();
        apply_delete(&share, "b/x", &suppress).unwrap();
        assert!(!share.join("b/x").exists());
        drop(store);
    }

    // Restart + redelivery of the delete.
    let store = Store::open(&db, NODE_A).unwrap();
    assert!(!store.has_applied(delete_op.op_id).await.unwrap());
    let local = store.load_file("b/x").await.unwrap().unwrap();
    let decision = decide(Some(&local), &delete_op.vv);
    assert_eq!(decision, Decision::Apply);
    let suppress = Suppressor::new();
    apply_delete(&share, "b/x", &suppress).unwrap(); // missing file = ok
    store
        .apply_remote(delete_op.clone(), decision)
        .await
        .unwrap();

    // Tombstone retained with the delete's VV; cursor caught up.
    let local = store.load_file("b/x").await.unwrap().unwrap();
    assert!(local.tombstone);
    assert_eq!(local.vv.get(&NODE_B), 2);
    assert_eq!(store.recv_cursor(NODE_B).await.unwrap(), 2);

    // A stale write (pre-delete) redelivered after all this must NOT
    // resurrect the file (reviewer checklist).
    let stale = remote_write(1, "b/x", data, 1);
    let local = store.load_file("b/x").await.unwrap().unwrap();
    // It's already in `applied`, so the fast path drops it...
    assert!(store.has_applied(stale.op_id).await.unwrap());
    // ...and even without that, the decision is Ignore.
    assert_eq!(decide(Some(&local), &stale.vv), Decision::Ignore);
    assert!(!share.join("b/x").exists());
}
