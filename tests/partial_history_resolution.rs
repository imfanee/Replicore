//! Conflict resolution under PARTIAL op history — the coverage-branch case
//! the conflict proptest does not construct (its replicas always hold every
//! op they resolved against).
//!
//! A join-bootstrapped node holds `files` rows delivered as reconcile state
//! with NO backing ops (the frontier handoff never backfills history; the
//! same shape arises after any future oplog GC). `resolve_rows`'s coverage
//! branch (`oplog.rs`) must then include the row itself as a candidate.
//! Two properties are pinned here (see docs/review-3a-conflict.md §2):
//!
//! 1. **Bootstrap equivalence**: when the row faithfully summarizes the
//!    history (row = the op set's antichain max), a bootstrapped node and a
//!    full-history node resolve the SAME concurrent op to byte-identical
//!    rows — winner, VV, and copy name all equal, with the include-arm
//!    provably exercised (`op_count == 0`).
//! 2. **Dominance healing**: when the full node knows a contender the
//!    bootstrapped node never will, their resolutions differ transiently —
//!    but the full node's winner-row VV STRICTLY dominates, so one
//!    reconcile exchange converges them byte-identically (never the
//!    equal-VV/different-content deadlock of the pairwise design).

use replicore::conflict::{copy_path_for, META_NONE};
use replicore::decide::Decision;
use replicore::oplog::ReconciledRow;
use replicore::proto::{op_id, OpRecord, OpType};
use replicore::replica::{ApplyEffect, Replica};
use replicore::vv::NodeId;

const NODE_F: NodeId = [0xff; 16]; // full history
const NODE_B: NodeId = [0xb0; 16]; // bootstrapped (rows, no ops)
const SRC: NodeId = [0x51; 16]; // origin of the path's history
const SRC2: NodeId = [0x52; 16]; // origin of the contender only F sees
const SRC3: NodeId = [0x53; 16]; // origin of the concurrent op under test

fn op(origin: NodeId, seq: i64, vv: &[(NodeId, u64)], content: &[u8]) -> OpRecord {
    OpRecord {
        op_id: op_id(&origin, seq),
        origin,
        origin_seq: seq,
        op_type: OpType::Write,
        path: "shared/p.txt".into(),
        path_old: None,
        uuid: Some([0x11; 16]),
        mode: 0o644,
        size: content.len() as u64,
        content_hash: Some(*blake3::hash(content).as_bytes()),
        meta: None,
        vv: vv.iter().copied().collect(),
    }
}

/// Three distinct contents ordered by their BLAKE3 (lo < mid < hi) — found
/// deterministically so the winner expectations are explicit, not lucky.
fn ordered_contents() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut pool: Vec<Vec<u8>> = (0u8..8).map(|b| vec![b; 4]).collect();
    pool.sort_by_key(|c| *blake3::hash(c).as_bytes());
    (pool[0].clone(), pool[3].clone(), pool[7].clone())
}

/// Seed `replica` the way a join bootstrap does: the ROW arrives as
/// reconcile state (files-plane only — provably zero ops), the content
/// appears on the (fake) fs.
async fn bootstrap_row(replica: &mut Replica, from: &OpRecord) {
    replica
        .store
        .reconcile_upsert(ReconciledRow {
            path: from.path.clone(),
            content_hash: from.content_hash,
            mode: from.mode,
            size: from.size,
            vv: from.vv.clone(),
            tombstone: false,
            uuid: from.uuid,
            meta: None,
        })
        .await
        .unwrap();
    replica.fs.write(&from.path, from.content_hash.unwrap());
    assert_eq!(
        replica.store.op_count().await.unwrap(),
        0,
        "bootstrap must hold the row WITHOUT history — that is the case under test"
    );
}

/// Case 1: row-without-history resolves identically to full history when
/// the row faithfully summarizes it.
#[tokio::test]
async fn bootstrapped_node_resolves_identically_to_full_history() {
    let (_lo, mid, hi) = ordered_contents();

    // History at the source: X{s:1} superseded by Y{s:2} (content `hi`).
    let x = op(SRC, 1, &[(SRC, 1)], &mid);
    let y = op(SRC, 2, &[(SRC, 2)], &hi);
    // The concurrent op under test (content `mid` — the loser, so a copy
    // must be minted identically on both nodes).
    let z = op(SRC3, 1, &[(SRC3, 1)], &mid);

    let mut f = Replica::new(NODE_F).unwrap();
    assert_eq!(f.receive(&x).await.unwrap(), Some(Decision::Apply));
    assert_eq!(f.receive(&y).await.unwrap(), Some(Decision::Apply));

    let mut b = Replica::new(NODE_B).unwrap();
    bootstrap_row(&mut b, &y).await;

    // Both witness the same conflict…
    assert_eq!(f.receive(&z).await.unwrap(), Some(Decision::Concurrent));
    assert_eq!(b.receive(&z).await.unwrap(), Some(Decision::Concurrent));

    // …and resolve it to byte-identical rows: same winner, same merged VV,
    // same content-derived copy name — despite B holding zero history ops.
    let rows_f = f.snapshot().await.unwrap();
    let rows_b = b.snapshot().await.unwrap();
    assert_eq!(rows_f, rows_b, "bootstrap and full history diverged");

    let winner = rows_f.iter().find(|r| r.path == "shared/p.txt").unwrap();
    assert_eq!(winner.content_hash, Some(*blake3::hash(&hi).as_bytes()));
    assert_eq!(winner.vv.get(&SRC), 2);
    assert_eq!(winner.vv.get(&SRC3), 1); // both sides absorbed
    let copy = copy_path_for("shared/p.txt", blake3::hash(&mid).as_bytes(), &META_NONE);
    assert!(rows_f.iter().any(|r| r.path == copy), "loser copy missing");

    // Idempotency: redelivery moves nothing on either node.
    assert_eq!(f.receive(&z).await.unwrap(), None);
    assert_eq!(b.receive(&z).await.unwrap(), None);
    assert_eq!(f.snapshot().await.unwrap(), rows_f);
    assert_eq!(b.snapshot().await.unwrap(), rows_b);
}

/// Case 2: the full node knows a contender (V) the bootstrapped node never
/// receives. Resolutions differ transiently — the healing lemma says the
/// full node's winner-row VV strictly dominates, and one reconcile exchange
/// converges the pair byte-identically.
#[tokio::test]
async fn asymmetric_history_heals_by_dominance_via_reconcile() {
    let (lo, mid, hi) = ordered_contents();

    let y = op(SRC, 1, &[(SRC, 1)], &mid); // the shared base row
    let v = op(SRC2, 1, &[(SRC2, 1)], &hi); // only F ever sees this (max key)
    let z = op(SRC3, 1, &[(SRC3, 1)], &lo); // the op both resolve against

    let mut f = Replica::new(NODE_F).unwrap();
    assert_eq!(f.receive(&y).await.unwrap(), Some(Decision::Apply));
    // F witnesses Y-vs-V and resolves it (winner `hi`, copy of `mid`).
    assert_eq!(f.receive(&v).await.unwrap(), Some(Decision::Concurrent));

    let mut b = Replica::new(NODE_B).unwrap();
    bootstrap_row(&mut b, &y).await; // B's world: only Y's row, no ops

    assert_eq!(f.receive(&z).await.unwrap(), Some(Decision::Concurrent));
    assert_eq!(b.receive(&z).await.unwrap(), Some(Decision::Concurrent));

    // Transient divergence is REAL: different winners…
    let row_f = f.store.load_row("shared/p.txt").await.unwrap().unwrap();
    let row_b = b.store.load_row("shared/p.txt").await.unwrap().unwrap();
    assert_eq!(row_f.content_hash, Some(*blake3::hash(&hi).as_bytes()));
    assert_eq!(row_b.content_hash, Some(*blake3::hash(&mid).as_bytes()));
    // …but ORDERED divergence: F's VV strictly dominates B's (the healing
    // lemma — never equal-VV/different-content).
    assert_eq!(
        row_f.vv.compare(&row_b.vv),
        replicore::vv::Ord3::Dominates,
        "full-history resolution must causally dominate the partial one"
    );

    // One anti-entropy exchange heals: B adopts the dominating rows; the
    // back-exchange carries any copy only B minted.
    let from_f = f.snapshot().await.unwrap();
    b.reconcile_from(&from_f).await.unwrap();
    let from_b = b.snapshot().await.unwrap();
    f.reconcile_from(&from_b).await.unwrap();

    let rows_f = f.snapshot().await.unwrap();
    let rows_b = b.snapshot().await.unwrap();
    assert_eq!(rows_f, rows_b, "reconcile did not converge the pair");

    // Zero loss across BOTH histories: hi won; mid and lo survive as copies.
    let winner = rows_f.iter().find(|r| r.path == "shared/p.txt").unwrap();
    assert_eq!(winner.content_hash, Some(*blake3::hash(&hi).as_bytes()));
    for loser in [&mid, &lo] {
        let copy = copy_path_for("shared/p.txt", blake3::hash(loser).as_bytes(), &META_NONE);
        let row = rows_f
            .iter()
            .find(|r| r.path == copy)
            .unwrap_or_else(|| panic!("copy missing for {loser:?}"));
        assert_eq!(row.content_hash, Some(*blake3::hash(loser).as_bytes()));
    }
    f.assert_fs_matches_index().await.unwrap();
    b.assert_fs_matches_index().await.unwrap();
}
