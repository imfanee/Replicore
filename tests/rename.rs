//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! FR-205 (identity-lite) + FR-304 rename rules: renames are ONE op whose two
//! path-effects commit atomically — identity (uuid) and the VV lineage
//! continue at the target, no content retransfer, no self-conflict. The
//! FR-304 pairs involving renames resolve deterministically per path:
//!
//! - rename-vs-modify: the concurrent write RESURRECTS the source (modify
//!   wins against the rename's tombstone); the moved file keeps the target.
//!   Both contents survive — zero loss. (Cross-path write redirect is
//!   SEAM(M4): rename redirect.)
//! - rename-vs-rename: both targets materialize the (identical) content; the
//!   source tombstones once. Convergent; the duplicate name is operator
//!   cleanup, not data loss.

use replicore::decide::Decision;
use replicore::proto::OpType;
use replicore::replica::Replica;
use replicore::vv::NodeId;

const NODE_A: NodeId = [0xaa; 16];
const NODE_B: NodeId = [0xbb; 16];

#[tokio::test]
async fn rename_preserves_identity_and_lineage() {
    let mut a = Replica::new(NODE_A).unwrap();
    let mut b = Replica::new(NODE_B).unwrap();

    let op_w = a.local_write("dir/f.txt", &[1]).await.unwrap().unwrap();
    let uuid = op_w.uuid.expect("create mints a uuid");
    b.receive(&op_w).await.unwrap();

    let op_r = a
        .local_rename("dir/f.txt", "dir/g.txt")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(op_r.op_type, OpType::Rename);
    assert_eq!(op_r.uuid, Some(uuid), "identity travels with the move");
    assert_eq!(op_r.path_old.as_deref(), Some("dir/f.txt"));
    // Lineage continues: the rename's VV builds on the file's, not a fresh
    // one (this is what makes it NOT delete+create causally).
    assert_eq!(op_r.vv.get(&NODE_A), 2);

    assert_eq!(b.receive(&op_r).await.unwrap(), Some(Decision::Apply));

    let snap_a = a.snapshot().await.unwrap();
    let snap_b = b.snapshot().await.unwrap();
    assert_eq!(snap_a, snap_b, "rename converges in one op");
    let g = snap_a.iter().find(|r| r.path == "dir/g.txt").unwrap();
    assert_eq!(g.uuid, Some(uuid));
    assert!(!g.tombstone);
    let f = snap_a.iter().find(|r| r.path == "dir/f.txt").unwrap();
    assert!(f.tombstone);
    a.assert_fs_matches_index().await.unwrap();
    b.assert_fs_matches_index().await.unwrap();

    // Redelivery is a no-op (idempotency).
    assert_eq!(b.receive(&op_r).await.unwrap(), None);
    assert_eq!(b.snapshot().await.unwrap(), snap_b);
}

/// FR-304 rename-vs-modify: B writes the file while A concurrently renames
/// it away. Modify wins at the source (it resurrects with B's content); the
/// move wins at the target. Both nodes converge without anti-entropy and
/// neither content is lost.
#[tokio::test]
async fn rename_vs_modify_resurrects_the_source() {
    let mut a = Replica::new(NODE_A).unwrap();
    let mut b = Replica::new(NODE_B).unwrap();

    let op_w = a.local_write("f", &[1]).await.unwrap().unwrap();
    b.receive(&op_w).await.unwrap();

    // Concurrent: A moves f→g while B writes f.
    let op_r = a.local_rename("f", "g").await.unwrap().unwrap();
    let op_m = b.local_write("f", &[9]).await.unwrap().unwrap();

    a.receive(&op_m).await.unwrap();
    b.receive(&op_r).await.unwrap();

    let snap_a = a.snapshot().await.unwrap();
    let snap_b = b.snapshot().await.unwrap();
    assert_eq!(snap_a, snap_b, "rename-vs-modify must converge");

    let g = snap_a.iter().find(|r| r.path == "g").unwrap();
    assert_eq!(g.content_hash, Some(*blake3::hash(&[1]).as_bytes()));
    assert!(!g.tombstone, "the moved file keeps the target");
    let f = snap_a.iter().find(|r| r.path == "f").unwrap();
    assert!(!f.tombstone, "modify wins: the source resurrects");
    assert_eq!(f.content_hash, Some(*blake3::hash(&[9]).as_bytes()));
    // Both sides absorbed at the source: neither op can re-fire there.
    assert_eq!(f.vv.get(&NODE_A), 2);
    assert_eq!(f.vv.get(&NODE_B), 1);
    a.assert_fs_matches_index().await.unwrap();
    b.assert_fs_matches_index().await.unwrap();
}

/// FR-304 rename-vs-rename (same file, two targets): the source tombstones
/// once; BOTH targets materialize the content. Deterministic and convergent;
/// nothing is lost.
#[tokio::test]
async fn rename_vs_rename_materializes_both_targets() {
    let mut a = Replica::new(NODE_A).unwrap();
    let mut b = Replica::new(NODE_B).unwrap();

    let op_w = a.local_write("f", &[5]).await.unwrap().unwrap();
    b.receive(&op_w).await.unwrap();

    let op_ra = a.local_rename("f", "g").await.unwrap().unwrap();
    let op_rb = b.local_rename("f", "h").await.unwrap().unwrap();

    a.receive(&op_rb).await.unwrap();
    b.receive(&op_ra).await.unwrap();

    let snap_a = a.snapshot().await.unwrap();
    let snap_b = b.snapshot().await.unwrap();
    assert_eq!(snap_a, snap_b, "rename-vs-rename must converge");

    let hash = Some(*blake3::hash(&[5]).as_bytes());
    for target in ["g", "h"] {
        let row = snap_a.iter().find(|r| r.path == target).unwrap();
        assert!(!row.tombstone, "{target} must hold the file");
        assert_eq!(row.content_hash, hash);
    }
    let f = snap_a.iter().find(|r| r.path == "f").unwrap();
    assert!(f.tombstone, "the source is gone everywhere");
    a.assert_fs_matches_index().await.unwrap();
    b.assert_fs_matches_index().await.unwrap();
}

/// The append-side no-op filters (loop defense for the scanner re-observing
/// applied remote renames).
#[tokio::test]
async fn rename_noop_filters() {
    let mut a = Replica::new(NODE_A).unwrap();

    // Absent source.
    assert!(a.local_rename("nope", "x").await.unwrap().is_none());
    // Self-rename.
    a.local_write("f", &[1]).await.unwrap().unwrap();
    assert!(a.local_rename("f", "f").await.unwrap().is_none());
    // Tombstoned source.
    a.local_delete("f").await.unwrap().unwrap();
    assert!(a.local_rename("f", "x").await.unwrap().is_none());
    // Re-observed move: target already holds the content.
    a.local_write("p", &[2]).await.unwrap().unwrap();
    a.local_rename("p", "q").await.unwrap().unwrap();
    assert!(a.local_rename("p", "q").await.unwrap().is_none());
}

/// Renaming over an existing live target absorbs the target's lineage (the
/// user intentionally replaced it): receivers see a clean dominating apply —
/// no spurious conflict, no copy.
#[tokio::test]
async fn rename_over_existing_target_dominates() {
    let mut a = Replica::new(NODE_A).unwrap();
    let mut b = Replica::new(NODE_B).unwrap();

    let w1 = a.local_write("src", &[1]).await.unwrap().unwrap();
    let w2 = a.local_write("dst", &[2]).await.unwrap().unwrap();
    b.receive(&w1).await.unwrap();
    b.receive(&w2).await.unwrap();

    let op_r = a.local_rename("src", "dst").await.unwrap().unwrap();
    assert_eq!(b.receive(&op_r).await.unwrap(), Some(Decision::Apply));

    let snap_a = a.snapshot().await.unwrap();
    let snap_b = b.snapshot().await.unwrap();
    assert_eq!(snap_a, snap_b);
    let dst = snap_a.iter().find(|r| r.path == "dst").unwrap();
    assert_eq!(dst.content_hash, Some(*blake3::hash(&[1]).as_bytes()));
    assert!(
        !snap_a.iter().any(|r| r.path.contains(".sync-conflict-")),
        "an intentional replace is not a conflict"
    );
    a.assert_fs_matches_index().await.unwrap();
    b.assert_fs_matches_index().await.unwrap();
}
