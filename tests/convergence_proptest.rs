//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! THE M1 correctness gate (exit criterion 4): random op sequences applied in
//! different orders on two simulated nodes converge to identical state.
//!
//! The harness (`replicore::replica`) runs the real store (`:memory:` SQLite,
//! same transactions and idempotency table), real `decide`, real ingest no-op
//! filter — only the fs effect is faked. Delivery here is adversarial: an
//! arbitrary permutation per receiver plus injected duplicates, which is
//! strictly harsher than the real transport (in-order per origin with
//! redelivery only after crashes).
//!
//! Under partitioned write ownership (the M1 operating regime) convergence
//! must be exact. With overlapping writes, the conflict is detected
//! (Decision::Concurrent) and resolved deterministically with a conflict
//! copy (M3, FR-303) — the dense-overlap convergence gate lives in
//! `tests/conflict_proptest.rs`.

use proptest::prelude::*;
use replicore::conflict::META_NONE;
use replicore::decide::Decision;
use replicore::proto::OpRecord;
use replicore::replica::Replica;
use replicore::vv::NodeId;

const NODE_A: NodeId = [0xaa; 16];
const NODE_B: NodeId = [0xbb; 16];

#[derive(Clone, Debug)]
enum Action {
    Write(u8),
    Delete,
}

fn arb_script() -> impl Strategy<Value = Vec<(usize, Action)>> {
    proptest::collection::vec(
        (
            0usize..4, // path index within the node's own namespace
            prop_oneof![
                3 => (0u8..8).prop_map(Action::Write),
                1 => Just(Action::Delete),
            ],
        ),
        0..12,
    )
}

/// Run a script of local mutations on `replica` within its own namespace
/// `prefix`; return the ops it emitted.
async fn run_script(
    replica: &mut Replica,
    prefix: &str,
    script: &[(usize, Action)],
) -> Vec<OpRecord> {
    let mut ops = Vec::new();
    for (idx, action) in script {
        let path = format!("{prefix}/p{idx}");
        let emitted = match action {
            Action::Write(c) => replica.local_write(&path, &[*c]).await.unwrap(),
            Action::Delete => replica.local_delete(&path).await.unwrap(),
        };
        ops.extend(emitted); // None = causal no-op (e.g. same content)
    }
    ops
}

/// Deliver `ops` to `replica` in the permutation chosen by `picks`, weaving in
/// duplicate redeliveries chosen by `dups`.
async fn deliver_permuted(
    replica: &mut Replica,
    mut ops: Vec<OpRecord>,
    picks: &[prop::sample::Index],
    dups: &[prop::sample::Index],
) {
    let mut delivered: Vec<OpRecord> = Vec::new();
    let mut step = 0usize;
    while !ops.is_empty() {
        let i = picks
            .get(step % picks.len().max(1))
            .map(|p| p.index(ops.len()))
            .unwrap_or(0);
        let op = ops.remove(i);
        replica.receive(&op).await.unwrap();
        delivered.push(op);
        // Every third step, redeliver something already seen (duplicate).
        if step % 3 == 2 {
            if let Some(d) = dups.get(step % dups.len().max(1)) {
                let dup = delivered[d.index(delivered.len())].clone();
                replica.receive(&dup).await.unwrap();
            }
        }
        step += 1;
    }
}

/// Default 64 cases for CI speed; override with PROPTEST_CASES for deep runs
/// (e.g. `PROPTEST_CASES=20000 cargo test --release --test convergence_proptest`).
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Partitioned namespaces: full convergence under permuted, duplicated
    /// delivery, and total quiescence on redelivery (the no-storm property).
    #[test]
    fn partitioned_namespaces_converge(
        script_a in arb_script(),
        script_b in arb_script(),
        picks_a in proptest::collection::vec(any::<prop::sample::Index>(), 1..32),
        picks_b in proptest::collection::vec(any::<prop::sample::Index>(), 1..32),
        dups in proptest::collection::vec(any::<prop::sample::Index>(), 1..32),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let mut a = Replica::new(NODE_A).unwrap();
            let mut b = Replica::new(NODE_B).unwrap();

            // Each node mutates only its own sub-namespace (M1 regime).
            let ops_a = run_script(&mut a, "a", &script_a).await;
            let ops_b = run_script(&mut b, "b", &script_b).await;

            // Cross-deliver in independent adversarial orders + duplicates.
            deliver_permuted(&mut a, ops_b.clone(), &picks_a, &dups).await;
            deliver_permuted(&mut b, ops_a.clone(), &picks_b, &dups).await;

            // Convergence: identical materialized state on both nodes.
            let snap_a = a.snapshot().await.unwrap();
            let snap_b = b.snapshot().await.unwrap();
            prop_assert_eq!(&snap_a, &snap_b);

            // The (fake) fs agrees with each node's index.
            a.assert_fs_matches_index().await.unwrap();
            b.assert_fs_matches_index().await.unwrap();

            // Idempotency / quiescence: redelivering EVERYTHING changes
            // nothing — no new ops, no state movement (FR-802/901; exit
            // criterion 2's "op counts quiesce").
            let count_a = a.store.op_count().await.unwrap();
            let count_b = b.store.op_count().await.unwrap();
            for op in ops_b.iter() {
                prop_assert_eq!(a.receive(op).await.unwrap(), None);
            }
            for op in ops_a.iter() {
                prop_assert_eq!(b.receive(op).await.unwrap(), None);
            }
            prop_assert_eq!(a.snapshot().await.unwrap(), snap_a);
            prop_assert_eq!(b.snapshot().await.unwrap(), snap_b);
            prop_assert_eq!(a.store.op_count().await.unwrap(), count_a);
            prop_assert_eq!(b.store.op_count().await.unwrap(), count_b);
            Ok(())
        })?;
    }

    /// Overlapping concurrent writes: both sides detect the conflict AND
    /// resolve it identically (FR-303/304) — deterministic winner by the
    /// content total order, loser preserved as a conflict copy with the same
    /// derived name on both nodes. Zero silent loss, byte-identical trees.
    #[test]
    fn concurrent_overlap_resolves_identically(ca in 0u8..8, cb in 8u8..16) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let mut a = Replica::new(NODE_A).unwrap();
            let mut b = Replica::new(NODE_B).unwrap();

            let op_a = a.local_write("shared/p", &[ca]).await.unwrap().unwrap();
            let op_b = b.local_write("shared/p", &[cb]).await.unwrap().unwrap();

            // Both sides detect Concurrent — nothing else may order this.
            prop_assert_eq!(a.receive(&op_b).await.unwrap(), Some(Decision::Concurrent));
            prop_assert_eq!(b.receive(&op_a).await.unwrap(), Some(Decision::Concurrent));

            // Deterministic winner: the larger content hash (kind ranks tie —
            // both writes). The loser survives as the content-derived copy.
            let hash_a = *blake3::hash(&[ca]).as_bytes();
            let hash_b = *blake3::hash(&[cb]).as_bytes();
            let (winner, loser) = if hash_a > hash_b {
                (hash_a, hash_b)
            } else {
                (hash_b, hash_a)
            };
            let copy = replicore::conflict::copy_path_for("shared/p", &loser, &META_NONE);

            let snap_a = a.snapshot().await.unwrap();
            let snap_b = b.snapshot().await.unwrap();
            prop_assert_eq!(&snap_a, &snap_b); // byte-identical incl. the copy

            let row = snap_a.iter().find(|r| r.path == "shared/p").unwrap();
            prop_assert_eq!(row.content_hash, Some(winner));
            // Winner VV merged both sides: neither op can re-fire.
            prop_assert_eq!(row.vv.get(&NODE_A), 1);
            prop_assert_eq!(row.vv.get(&NODE_B), 1);
            let copy_row = snap_a.iter().find(|r| r.path == copy).unwrap();
            prop_assert_eq!(copy_row.content_hash, Some(loser));
            prop_assert_eq!(&copy_row.vv, &replicore::conflict::copy_vv(&copy));

            a.assert_fs_matches_index().await.unwrap();
            b.assert_fs_matches_index().await.unwrap();

            // The foreign op IS durably recorded: a redelivery is dropped on
            // the idempotency fast path and nothing moves.
            prop_assert_eq!(a.receive(&op_b).await.unwrap(), None);
            prop_assert_eq!(b.receive(&op_a).await.unwrap(), None);
            prop_assert_eq!(a.snapshot().await.unwrap(), snap_a);
            prop_assert_eq!(b.snapshot().await.unwrap(), snap_b);
            Ok(())
        })?;
    }
}
