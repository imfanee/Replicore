//! Property tests for version-vector dominance (CLAUDE.md: correctness-critical
//! logic MUST have property-based tests; M1 reviewer checklist: the concurrent
//! case must be detected correctly and nothing else may order it).

use proptest::prelude::*;
use replicore::vv::{NodeId, Ord3, VersionVector};

fn nid(b: u8) -> NodeId {
    let mut id = [0u8; 16];
    id[0] = b;
    id
}

/// Vectors drawn from a 4-node pool with small counters so overlap (and thus
/// every Ord3 variant) is common.
fn arb_vv() -> impl Strategy<Value = VersionVector> {
    proptest::collection::btree_map(0u8..4, 0u64..5, 0..4)
        .prop_map(|m| m.into_iter().map(|(n, c)| (nid(n), c)).collect())
}

proptest! {
    /// compare() is antisymmetric: swapping operands swaps Dominates/Dominated
    /// and fixes Equal/Concurrent.
    #[test]
    fn compare_antisymmetric(a in arb_vv(), b in arb_vv()) {
        let fwd = a.compare(&b);
        let rev = b.compare(&a);
        let expected = match fwd {
            Ord3::Dominates => Ord3::Dominated,
            Ord3::Dominated => Ord3::Dominates,
            Ord3::Equal => Ord3::Equal,
            Ord3::Concurrent => Ord3::Concurrent,
        };
        prop_assert_eq!(rev, expected);
    }

    /// Equal means structurally identical (normalization makes this sound).
    #[test]
    fn equal_iff_same_vector(a in arb_vv(), b in arb_vv()) {
        prop_assert_eq!(a.compare(&b) == Ord3::Equal, a == b);
    }

    /// merge() is an upper bound of both operands.
    #[test]
    fn merge_dominates_or_equals_both(a in arb_vv(), b in arb_vv()) {
        let mut m = a.clone();
        m.merge(&b);
        prop_assert!(matches!(m.compare(&a), Ord3::Dominates | Ord3::Equal));
        prop_assert!(matches!(m.compare(&b), Ord3::Dominates | Ord3::Equal));
    }

    /// merge() is commutative and idempotent (the CRDT laws convergence
    /// depends on).
    #[test]
    fn merge_commutative_idempotent(a in arb_vv(), b in arb_vv()) {
        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        prop_assert_eq!(&ab, &ba);
        let snapshot = ab.clone();
        ab.merge(&b);
        ab.merge(&a);
        prop_assert_eq!(ab, snapshot);
    }

    /// merge() is associative.
    #[test]
    fn merge_associative(a in arb_vv(), b in arb_vv(), c in arb_vv()) {
        let mut left = a.clone();
        left.merge(&b);
        left.merge(&c);
        let mut bc = b.clone();
        bc.merge(&c);
        let mut right = a.clone();
        right.merge(&bc);
        prop_assert_eq!(left, right);
    }

    /// A local increment strictly dominates its predecessor and leaves other
    /// components untouched.
    #[test]
    fn increment_strictly_dominates(a in arb_vv(), n in 0u8..4) {
        let node = nid(n);
        let mut bumped = a.clone();
        bumped.increment(&node);
        prop_assert_eq!(bumped.compare(&a), Ord3::Dominates);
        prop_assert_eq!(bumped.get(&node), a.get(&node) + 1);
        for m in 0u8..4 {
            if m != n {
                prop_assert_eq!(bumped.get(&nid(m)), a.get(&nid(m)));
            }
        }
    }

    /// Dominance is transitive.
    #[test]
    fn dominance_transitive(a in arb_vv(), b in arb_vv(), c in arb_vv()) {
        if a.dominates(&b) && b.dominates(&c) {
            prop_assert!(a.dominates(&c));
        }
    }
}
