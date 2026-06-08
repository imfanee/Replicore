//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! The stale-decision property on the CONFLICT path (M3 gate): a concurrent
//! LOCAL write landing *during* a conflict-copy fetch must be caught by the
//! committing re-check — the M2 `apply_remote` re-validation, extended to
//! `resolve_rows`. Trusting the stale plan would clobber the newer local
//! write exactly like the stale-Apply hazard M2 closed.
//!
//! Drives the real store through its public API; the "fetch window" is the
//! gap between obtaining the plan and committing it.

use replicore::conflict::{copy_path_for, copy_vv, META_NONE};
use replicore::decide::{decide, Decision};
use replicore::oplog::{LocalChange, ResolveOutcome, Store};
use replicore::proto::{op_id, OpRecord, OpType};
use replicore::vv::NodeId;

const NODE_A: NodeId = [0xaa; 16]; // local
const NODE_B: NodeId = [0xbb; 16]; // remote origin

fn mem_store() -> Store {
    Store::open(std::path::Path::new(":memory:"), NODE_A).unwrap()
}

fn write_change(path: &str, hash: [u8; 32]) -> LocalChange {
    LocalChange {
        path: path.into(),
        op_type: OpType::Write,
        mode: 0o644,
        size: 8,
        content_hash: Some(hash),
        meta: None,
        manifest: None,
    }
}

fn remote_op(path: &str, hash: [u8; 32]) -> OpRecord {
    OpRecord {
        op_id: op_id(&NODE_B, 1),
        origin: NODE_B,
        origin_seq: 1,
        op_type: OpType::Write,
        path: path.into(),
        path_old: None,
        uuid: None,
        mode: 0o644,
        size: 8,
        content_hash: Some(hash),
        meta: None,
        vv: [(NODE_B, 1u64)].into_iter().collect(),
    }
}

fn op_version(op: &OpRecord) -> replicore::conflict::Version {
    replicore::conflict::Version {
        tombstone: false,
        content_hash: op.content_hash,
        meta_hash: replicore::conflict::META_NONE,
        mode: op.mode,
        size: op.size,
        vv: op.vv.clone(),
        uuid: op.uuid,
        meta: op.meta.clone(),
    }
}

/// THE gate: plan obtained → local write lands ("during the fetch") → the
/// stale plan is refused, nothing committed, and the retry resolves against
/// the fresh state with zero loss.
#[tokio::test]
async fn local_write_during_copy_fetch_is_caught_by_the_recheck() {
    let store = mem_store();

    // Local content LA; remote op RB concurrent with it.
    store
        .append_local(write_change("race/p", [0x0a; 32]))
        .await
        .unwrap()
        .unwrap();
    let op = remote_op("race/p", [0x0b; 32]);
    let local = store.load_file("race/p").await.unwrap();
    assert_eq!(decide(local.as_ref(), &op.vv), Decision::Concurrent);

    // The op is durably recorded first (detection), exactly like net.rs.
    store
        .apply_remote(op.clone(), Decision::Concurrent)
        .await
        .unwrap();

    // T0: obtain the authoritative plan (an empty staging never matches).
    let stale_plan = match store
        .resolve_rows("race/p", op_version(&op), Vec::new())
        .await
        .unwrap()
    {
        ResolveOutcome::Stale { plan } => plan,
        other => panic!("expected the plan, got {other:?}"),
    };
    // The plan resolves LA-vs-RB: winner = larger hash (RB), loser LA copied.
    assert_eq!(stale_plan.len(), 2);
    assert_eq!(stale_plan[0].content_hash, Some([0x0b; 32]));

    // T1 (during the "loser fetch"): a concurrent LOCAL write lands — LA is
    // superseded by LC in A's own history.
    store
        .append_local(write_change("race/p", [0x0c; 32]))
        .await
        .unwrap()
        .unwrap();

    // T2: committing with the stale plan MUST be refused: nothing committed.
    let outcome = store
        .resolve_rows("race/p", op_version(&op), stale_plan.clone())
        .await
        .unwrap();
    let fresh_plan = match outcome {
        ResolveOutcome::Stale { plan } => plan,
        other => panic!("stale plan was accepted: {other:?}"),
    };
    assert_ne!(fresh_plan, stale_plan);
    let row = store.load_row("race/p").await.unwrap().unwrap();
    assert_eq!(
        row.content_hash,
        Some([0x0c; 32]),
        "stale resolution clobbered the local write"
    );
    assert_eq!(row.vv.get(&NODE_B), 0, "remote VV masked before resolution");
    for r in store.all_files().await.unwrap() {
        assert!(
            !r.path.contains(".sync-conflict-"),
            "stale plan leaked a copy row: {}",
            r.path
        );
    }

    // T3: the retry resolves against the FRESH antichain {RB, LC} — LA is
    // superseded by LC and is no longer a contender.
    assert_eq!(
        store
            .resolve_rows("race/p", op_version(&op), fresh_plan.clone())
            .await
            .unwrap(),
        ResolveOutcome::Resolved
    );
    let rows = store.all_files().await.unwrap();
    let winner = rows.iter().find(|r| r.path == "race/p").unwrap();
    // max(blake-keys) over {0x0b…, 0x0c…} — 0x0c wins the content order.
    assert_eq!(winner.content_hash, Some([0x0c; 32]));
    assert_eq!(winner.vv.get(&NODE_A), 2);
    assert_eq!(winner.vv.get(&NODE_B), 1); // both sides absorbed
    let copy = copy_path_for("race/p", &[0x0b; 32], &META_NONE);
    let copy_row = rows.iter().find(|r| r.path == copy).expect("loser copy");
    assert_eq!(copy_row.content_hash, Some([0x0b; 32]));
    assert_eq!(copy_row.vv, copy_vv(&copy));
    // LA (superseded by its own author) is correctly NOT preserved: it is
    // history, not a conflict loser.
    assert_eq!(rows.len(), 2);

    // Idempotency: re-running the resolution protocol is a no-op.
    assert_eq!(
        store
            .resolve_rows("race/p", op_version(&op), Vec::new())
            .await
            .unwrap(),
        ResolveOutcome::NotConcurrent(Decision::Ignore)
    );
    assert_eq!(store.all_files().await.unwrap(), rows);
}

/// A resolution that lost the race entirely (another path — e.g. reconcile —
/// already merged a dominating row) must come back NotConcurrent and leave
/// state untouched.
#[tokio::test]
async fn resolution_superseded_by_a_dominating_row_is_refused() {
    let store = mem_store();
    store
        .append_local(write_change("race/q", [0x0a; 32]))
        .await
        .unwrap()
        .unwrap();
    let op = remote_op("race/q", [0x0b; 32]);
    let plan = match store
        .resolve_rows("race/q", op_version(&op), Vec::new())
        .await
        .unwrap()
    {
        ResolveOutcome::Stale { plan } => plan,
        other => panic!("expected the plan, got {other:?}"),
    };

    // Reconcile merges a row that dominates the op (e.g. a peer already
    // resolved this conflict and its merged row arrived as a leaf).
    let mut merged_vv = store.load_row("race/q").await.unwrap().unwrap().vv;
    merged_vv.merge(&op.vv);
    store
        .reconcile_upsert(replicore::oplog::ReconciledRow {
            path: "race/q".into(),
            content_hash: Some([0x0b; 32]),
            mode: 0o644,
            size: 8,
            vv: merged_vv.clone(),
            tombstone: false,
            uuid: None,
            meta: None,
        })
        .await
        .unwrap();

    let outcome = store
        .resolve_rows("race/q", op_version(&op), plan)
        .await
        .unwrap();
    assert_eq!(outcome, ResolveOutcome::NotConcurrent(Decision::Ignore));
    let row = store.load_row("race/q").await.unwrap().unwrap();
    assert_eq!(row.content_hash, Some([0x0b; 32]));
    assert_eq!(row.vv, merged_vv);
}
