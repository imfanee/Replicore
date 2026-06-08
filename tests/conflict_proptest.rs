//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! THE M3 convergence gate (FR-303/304, exit criterion 3): dense concurrent
//! write/delete sets across N nodes, delivered in adversarial per-receiver
//! permutations with duplicates, must converge to **byte-identical state
//! including conflict-copy rows and names** — with zero silent loss.
//!
//! Like `convergence_proptest`, this drives the real store (`:memory:` SQLite,
//! real transactions, real `decide`, real `resolve_rows` committing path) via
//! the `Replica` harness; only the fs effect is faked.
//!
//! Delivery model honesty: live ops alone converge every node that *witnesses*
//! a conflict; a node that receives a causal successor before one half of a
//! concurrent pair records the late half as Ignore and derives no copy. The
//! copy reaches it via anti-entropy — copy rows are ordinary, deterministic
//! Merkle leaves. The test therefore finishes with reconcile passes
//! (`reconcile_from`, the leaf-delivery the Merkle session performs) before
//! asserting byte-identity: exactly the production contract (ops for
//! liveness, reconcile as the correctness backstop).
//!
//! Run deep: `PROPTEST_CASES=20000 cargo test --release --test conflict_proptest`.

use proptest::prelude::*;
use replicore::conflict::COPY_MARKER;
use replicore::metadata::Meta;
use replicore::replica::Replica;
use replicore::state::FileRow;
use replicore::vv::NodeId;

const NODES: [NodeId; 3] = [[0xaa; 16], [0xbb; 16], [0xcc; 16]];

#[derive(Clone, Debug)]
enum Action {
    /// (content byte, mode variant) — the mode dimension generates
    /// META-ONLY conflicts (same bytes, different metadata), the S1 review
    /// finding's class: the losing metadata snapshot must survive.
    Write(u8, u8),
    Delete,
    /// Identity-preserving move to another pool slot (FR-205/FR-304:
    /// rename-vs-modify and rename-vs-rename interleavings).
    Rename(usize),
}

const MODES: [u32; 2] = [0o644, 0o600];

/// Scripts over a SHARED namespace: every node writes the same few paths, so
/// concurrent overlap (the thing under test) is dense, with deletes and
/// renames mixed in for the FR-304 rule matrix.
fn arb_script() -> impl Strategy<Value = Vec<(usize, Action)>> {
    proptest::collection::vec(
        (
            0usize..3, // shared path pool: p0..p2 — collisions are the point
            prop_oneof![
                4 => (0u8..6, 0u8..2).prop_map(|(c, m)| Action::Write(c, m)),
                1 => Just(Action::Delete),
                1 => (0usize..3).prop_map(Action::Rename),
            ],
        ),
        0..8,
    )
}

async fn run_script(
    replica: &mut Replica,
    script: &[(usize, Action)],
) -> Vec<replicore::proto::OpRecord> {
    let mut ops = Vec::new();
    for (idx, action) in script {
        let path = format!("shared/p{idx}");
        let emitted = match action {
            Action::Write(c, m) => replica
                .local_write_with_mode(&path, &[*c], MODES[*m as usize])
                .await
                .unwrap(),
            Action::Delete => replica.local_delete(&path).await.unwrap(),
            Action::Rename(to) => {
                let target = format!("shared/p{to}");
                replica.local_rename(&path, &target).await.unwrap()
            }
        };
        ops.extend(emitted);
    }
    ops
}

async fn deliver_permuted(
    replica: &mut Replica,
    mut ops: Vec<replicore::proto::OpRecord>,
    picks: &[prop::sample::Index],
    dups: &[prop::sample::Index],
) {
    let mut delivered: Vec<replicore::proto::OpRecord> = Vec::new();
    let mut step = 0usize;
    while !ops.is_empty() {
        let i = picks
            .get(step % picks.len().max(1))
            .map(|p| p.index(ops.len()))
            .unwrap_or(0);
        let op = ops.remove(i);
        replica.receive(&op).await.unwrap();
        delivered.push(op);
        if step % 3 == 2 {
            if let Some(d) = dups.get(step % dups.len().max(1)) {
                let dup = delivered[d.index(delivered.len())].clone();
                replica.receive(&dup).await.unwrap();
            }
        }
        step += 1;
    }
}

/// Pairwise anti-entropy until globally quiescent: each pass exchanges full
/// snapshots in both directions; repeat until no snapshot changes. Production
/// runs this continuously (FR-602); two passes over a triangle is the usual
/// fixed point, the loop guards the odd case where a pass mints a new copy row
/// that a later pair must still carry.
async fn reconcile_to_fixpoint(replicas: &mut [Replica]) {
    for _ in 0..5 {
        let before = snapshots(replicas).await;
        for i in 0..replicas.len() {
            for j in 0..replicas.len() {
                if i == j {
                    continue;
                }
                let rows = replicas[j].snapshot().await.unwrap();
                replicas[i].reconcile_from(&rows).await.unwrap();
            }
        }
        if snapshots(replicas).await == before {
            return;
        }
    }
    panic!("reconcile did not reach a fixed point in 5 passes");
}

async fn snapshots(replicas: &mut [Replica]) -> Vec<Vec<FileRow>> {
    let mut out = Vec::new();
    for r in replicas.iter_mut() {
        out.push(r.snapshot().await.unwrap());
    }
    out
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(256)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// The gate: shared-namespace scripts on 3 nodes, adversarial delivery,
    /// reconcile to fixpoint → byte-identical rows everywhere (paths, content,
    /// tombstones, VVs, copy rows, copy NAMES), no silent loss, and full
    /// quiescence on redelivery.
    #[test]
    fn concurrent_writes_converge_with_identical_copies(
        scripts in proptest::array::uniform3(arb_script()),
        picks in proptest::array::uniform3(
            proptest::collection::vec(any::<prop::sample::Index>(), 1..24)),
        dups in proptest::collection::vec(any::<prop::sample::Index>(), 1..24),
    ) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio runtime");
        rt.block_on(async {
            let mut replicas = Vec::new();
            for id in NODES {
                replicas.push(Replica::new(id).unwrap());
            }

            // Concurrent local histories over the SAME paths.
            let mut all_ops: Vec<Vec<_>> = Vec::new();
            for (r, script) in replicas.iter_mut().zip(scripts.iter()) {
                all_ops.push(run_script(r, script).await);
            }

            // Deliver every other node's ops in an adversarial order.
            for (i, replica) in replicas.iter_mut().enumerate() {
                let mut foreign: Vec<_> = Vec::new();
                for (j, ops) in all_ops.iter().enumerate() {
                    if i != j {
                        foreign.extend(ops.iter().cloned());
                    }
                }
                deliver_permuted(replica, foreign, &picks[i], &dups).await;
            }

            // Anti-entropy backstop, then the convergence assertion.
            reconcile_to_fixpoint(&mut replicas).await;
            let snaps = snapshots(&mut replicas).await;
            prop_assert_eq!(&snaps[0], &snaps[1]);
            prop_assert_eq!(&snaps[0], &snaps[2]);
            for r in replicas.iter() {
                r.assert_fs_matches_index().await.unwrap();
            }

            // ZERO SILENT LOSS (FR-303), (content, META) PAIRS — the S1
            // review finding's oracle: every (bytes, metadata) version any
            // author finally wrote must survive at the path or in a copy
            // row; metadata-only losers count as loss too.
            let mut last_by_author: std::collections::BTreeMap<
                (String, NodeId),
                ([u8; 32], [u8; 32]),
            > = std::collections::BTreeMap::new();
            for ops in &all_ops {
                for op in ops {
                    if let Some(old_path) = &op.path_old {
                        last_by_author.remove(&(old_path.clone(), op.origin));
                    }
                    match op.content_hash {
                        Some(h) => last_by_author.insert(
                            (op.path.clone(), op.origin),
                            (h, Meta::hash_of(&op.meta)),
                        ),
                        None => last_by_author.remove(&(op.path.clone(), op.origin)),
                    };
                }
            }
            let surviving: std::collections::BTreeSet<([u8; 32], [u8; 32])> = snaps[0]
                .iter()
                .filter(|r| !r.tombstone)
                .filter_map(|r| r.content_hash.map(|h| (h, Meta::hash_of(&r.meta))))
                .collect();
            for ((path, _author), pair) in &last_by_author {
                // The author's final (content, meta) for the path must
                // survive somewhere — at the path or as a conflict copy.
                // (A delete only dominates its own node's prior write,
                // removing it from last_by_author above; a concurrent
                // delete LOSES to a write — modify wins.)
                prop_assert!(
                    surviving.contains(pair),
                    "version (content {}, meta {}) written at {} by an author's final op was lost",
                    hex::encode(&pair.0[..4]),
                    hex::encode(&pair.1[..4]),
                    path
                );
            }

            // Every copy row is named by the pure naming function of its own
            // content — i.e. copy names carry no node-local input.
            for row in snaps[0].iter().filter(|r| r.path.contains(COPY_MARKER)) {
                let hash = row.content_hash.expect("copy rows always carry content");
                let original = row.path
                    .split(COPY_MARKER)
                    .next()
                    .unwrap()
                    .to_string();
                // Reconstruct: original may have had an extension restored
                // after the marker; accept either form.
                let with_ext = row.path.rsplit('.').next().filter(|e| !e.contains('-'));
                // Names derive from the STABLE naming subset, not the full meta hash
                // (review-copy-naming.md).
                let mh = Meta::naming_hash(&row.meta);
                let candidate_a = replicore::conflict::copy_path_for(&original, &hash, &mh);
                let candidate_b = with_ext
                    .map(|e| {
                        replicore::conflict::copy_path_for(&format!("{original}.{e}"), &hash, &mh)
                    });
                prop_assert!(
                    row.path == candidate_a || Some(row.path.clone()) == candidate_b,
                    "copy row {} does not match its derived name",
                    row.path
                );
            }

            // Quiescence: redeliver EVERYTHING — no movement, no new ops.
            let counts = {
                let mut c = Vec::new();
                for r in &replicas {
                    c.push(r.store.op_count().await.unwrap());
                }
                c
            };
            for (i, replica) in replicas.iter_mut().enumerate() {
                for (j, ops) in all_ops.iter().enumerate() {
                    if i != j {
                        for op in ops {
                            prop_assert_eq!(replica.receive(op).await.unwrap(), None);
                        }
                    }
                }
            }
            let snaps_after = snapshots(&mut replicas).await;
            prop_assert_eq!(&snaps_after[0], &snaps[0]);
            for (r, count) in replicas.iter().zip(counts) {
                prop_assert_eq!(r.store.op_count().await.unwrap(), count);
            }
            Ok(())
        })?;
    }
}
