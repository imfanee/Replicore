//! Property tests for the membership register's convergence (FR-1303).
//!
//! The register is an epoch-versioned LWW per node_id ordered by
//! `(epoch, rank(kind), content_hash)`. That order is a total order, so
//! `merge_entry` is a join over a semilattice: commutative, associative,
//! idempotent. The properties below are the observable consequences:
//!
//!   1. Replicas that ingest the SAME multiset of signed entries in ANY order,
//!      with ANY duplication, converge to a byte-identical roster (digest).
//!   2. A Remove at epoch e is never displaced by an Add at epoch ≤ e — a stale
//!      add can never resurrect a tombstoned node, no matter the arrival order.
//!   3. A forged entry (signed by a non-admin key) never enters any replica.

use proptest::prelude::*;

use replicore::admin::{generate_admin_key, sign_entry, AdminPubKey, AdminSecret, EntryKind};
use replicore::membership::{MergeOutcome, Roster, SignedEntry};
use replicore::vv::NodeId;

fn nid(b: u8) -> NodeId {
    let mut id = [0u8; 16];
    id[0] = b;
    id
}

fn entry(
    sk: &AdminSecret,
    node: u8,
    port: u16,
    fp: u8,
    epoch: u64,
    kind: EntryKind,
) -> SignedEntry {
    let n = nid(node);
    let a = format!("10.0.0.1:{port}").parse().unwrap();
    let f = [fp; 32];
    let sig = sign_entry(sk, &n, &a, &f, epoch, kind);
    SignedEntry {
        node_id: n,
        addr: a,
        fingerprint: f,
        epoch,
        kind,
        sig,
    }
}

// A single admin key shared by all replicas (the cluster trust anchor). Built
// once; proptest reuses it across cases.
fn cluster_admin() -> (AdminSecret, AdminPubKey) {
    let (doc, pk) = generate_admin_key().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("admin.sk");
    std::fs::write(&p, &doc).unwrap();
    let sk = AdminSecret::load(&p).unwrap();
    std::mem::forget(dir); // keep the key file alive for the process
    (sk, pk)
}

// A small alphabet of mutations over a handful of nodes, with overlapping
// epochs so equal-epoch Add/Remove races and stale replays are well-covered.
fn mutation_strategy() -> impl Strategy<Value = (u8, u16, u8, u64, bool)> {
    (
        0u8..4,        // node id
        0u16..2,       // port variant (different addr at same epoch → tie-break)
        0u8..2,        // fingerprint variant
        1u64..4,       // epoch
        any::<bool>(), // true = Add, false = Remove
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Order- and duplication-independence: shuffle + duplicate the same entry
    /// set across two replicas → identical digests.
    #[test]
    fn replicas_converge_regardless_of_order(
        muts in prop::collection::vec(mutation_strategy(), 1..40),
        shuffle in prop::collection::vec(any::<prop::sample::Index>(), 0..80),
        dup in prop::collection::vec(any::<prop::sample::Index>(), 0..40),
    ) {
        let (sk, pk) = cluster_admin();
        let entries: Vec<SignedEntry> = muts
            .iter()
            .map(|&(node, port, fp, epoch, is_add)| {
                let kind = if is_add { EntryKind::Add } else { EntryKind::Remove };
                entry(&sk, node, 7000 + port, fp, epoch, kind)
            })
            .collect();

        // Replica A: in original order.
        let mut a = Roster::new();
        for e in &entries {
            a.merge_entry(e.clone(), &pk);
        }

        // Replica B: a shuffled, duplicated permutation of the same entries.
        let mut b_order: Vec<&SignedEntry> = entries.iter().collect();
        for idx in &shuffle {
            if !b_order.is_empty() {
                let i = idx.index(b_order.len());
                let j = idx.index(b_order.len());
                b_order.swap(i, j);
            }
        }
        for idx in &dup {
            if !entries.is_empty() {
                b_order.push(&entries[idx.index(entries.len())]);
            }
        }
        let mut b = Roster::new();
        for e in b_order {
            b.merge_entry(e.clone(), &pk);
        }

        prop_assert_eq!(a.digest(), b.digest());
        // Idempotent: re-merging A's own winners changes nothing.
        let winners: Vec<SignedEntry> = a.all_entries().cloned().collect();
        for e in winners {
            a.merge_entry(e, &pk);
        }
        prop_assert_eq!(a.digest(), b.digest());
    }

    /// Anti-resurrection: once a node has a Remove at epoch e as its winner, no
    /// Add at epoch ≤ e — applied in any order, any number of times — can make
    /// it an effective member again.
    #[test]
    fn tombstone_is_never_resurrected_by_stale_add(
        target in 0u8..4,
        remove_epoch in 2u64..5,
        stale_adds in prop::collection::vec((0u16..2, 0u8..2, 1u64..5), 0..30),
    ) {
        let (sk, pk) = cluster_admin();
        let mut r = Roster::new();

        // Establish the tombstone.
        prop_assert_eq!(
            r.merge_entry(entry(&sk, target, 7000, 1, remove_epoch, EntryKind::Remove), &pk),
            MergeOutcome::Applied
        );

        // Throw stale/equal-epoch Adds at it in arbitrary order.
        for (port, fp, epoch) in stale_adds {
            if epoch <= remove_epoch {
                r.merge_entry(entry(&sk, target, 7000 + port, fp, epoch, EntryKind::Add), &pk);
                // Still tombstoned after every such add.
                prop_assert!(r.get(&nid(target)).map(|e| e.kind == EntryKind::Remove).unwrap_or(false));
            }
        }
        prop_assert_eq!(r.effective_members().filter(|e| e.node_id == nid(target)).count(), 0);
    }

    /// Forged entries (correct content, wrong signer) never enter, and never
    /// perturb the converged state of legitimately-signed entries.
    #[test]
    fn forged_entries_are_rejected(
        muts in prop::collection::vec(mutation_strategy(), 1..20),
    ) {
        let (sk, pk) = cluster_admin();
        let (forger, _) = generate_admin_key().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("forger.sk");
        std::fs::write(&p, &forger).unwrap();
        let forger = AdminSecret::load(&p).unwrap();

        let mut legit = Roster::new();
        let mut mixed = Roster::new();
        for &(node, port, fp, epoch, is_add) in &muts {
            let kind = if is_add { EntryKind::Add } else { EntryKind::Remove };
            let good = entry(&sk, node, 7000 + port, fp, epoch, kind);
            legit.merge_entry(good.clone(), &pk);
            mixed.merge_entry(good, &pk);
            // Interleave a forged variant — must be rejected, leaving no trace.
            let bad = entry(&forger, node, 7000 + port, fp, epoch, kind);
            prop_assert_eq!(mixed.merge_entry(bad, &pk), MergeOutcome::Rejected);
        }
        prop_assert_eq!(legit.digest(), mixed.digest());
    }
}
