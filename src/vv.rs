//! vv.rs — per-file version vectors (FR-301/302).
//!
//! Causality comes from these vectors, **never** wall-clock time (RSD FR-301,
//! CLAUDE.md invariant 1). This module is deliberately pure: no clock, no I/O,
//! no dependencies beyond `serde`. `Ord3::Concurrent` is a terminal answer —
//! any tie-breaking between concurrent versions (M3) happens *outside* this
//! module and never decides causal ordering.
//!
//! Invariant: a stored counter is never zero. "Absent" and "zero" are the same
//! causal state, so constructors and `merge` normalize zeros away — this makes
//! `Eq` on the underlying map coincide with causal equality.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Stable node identity (uuid-shaped, supplied by config as 32 hex chars).
pub type NodeId = [u8; 16];

/// A per-file version vector: `node_id -> count of local writes seen from it`.
///
/// `BTreeMap` (not `HashMap`) so serialization is deterministic — the encoded
/// blob is stable for a given causal state.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct VersionVector(BTreeMap<NodeId, u64>);

/// Outcome of comparing two version vectors. Exactly one of four cases.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ord3 {
    /// `self` strictly dominates `other` (>= on every component, > on one).
    Dominates,
    /// `other` strictly dominates `self`.
    Dominated,
    /// Identical causal state.
    Equal,
    /// Neither dominates: concurrent writes. Conflict — never reordered here.
    Concurrent,
}

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Component for `node`; absent components are causally zero.
    pub fn get(&self, node: &NodeId) -> u64 {
        self.0.get(node).copied().unwrap_or(0)
    }

    /// Record one more local write by `node` (FR-301: local write increments
    /// this node's counter).
    pub fn increment(&mut self, node: &NodeId) {
        *self.0.entry(*node).or_insert(0) += 1;
    }

    /// Componentwise max. Used when applying a causally-dominating remote
    /// version: the merged vector covers both histories. Idempotent,
    /// commutative, associative.
    pub fn merge(&mut self, other: &VersionVector) {
        for (node, &count) in &other.0 {
            debug_assert!(count > 0, "normalized VV never stores zero");
            let mine = self.0.entry(*node).or_insert(0);
            if count > *mine {
                *mine = count;
            }
        }
    }

    /// Compare over the union of components (absent == 0).
    pub fn compare(&self, other: &VersionVector) -> Ord3 {
        let mut self_gt = false;
        let mut other_gt = false;
        // Visiting a shared key twice is harmless: same comparison result.
        for node in self.0.keys().chain(other.0.keys()) {
            let a = self.get(node);
            let b = other.get(node);
            if a > b {
                self_gt = true;
            } else if b > a {
                other_gt = true;
            }
            if self_gt && other_gt {
                return Ord3::Concurrent; // early out: already incomparable
            }
        }
        match (self_gt, other_gt) {
            (true, true) => Ord3::Concurrent, // unreachable, kept for totality
            (true, false) => Ord3::Dominates,
            (false, true) => Ord3::Dominated,
            (false, false) => Ord3::Equal,
        }
    }

    /// True iff `self` strictly dominates `other`.
    pub fn dominates(&self, other: &VersionVector) -> bool {
        self.compare(other) == Ord3::Dominates
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterate `(node, count)` components (all counts > 0 by invariant).
    pub fn iter(&self) -> impl Iterator<Item = (&NodeId, &u64)> {
        self.0.iter()
    }
}

impl FromIterator<(NodeId, u64)> for VersionVector {
    /// Builds a normalized vector: zero counters are dropped, duplicate keys
    /// keep the max (so any iteration source yields a canonical vector).
    fn from_iter<T: IntoIterator<Item = (NodeId, u64)>>(iter: T) -> Self {
        let mut map = BTreeMap::new();
        for (node, count) in iter {
            if count > 0 {
                let e = map.entry(node).or_insert(0);
                if count > *e {
                    *e = count;
                }
            }
        }
        VersionVector(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn vv(entries: &[(u8, u64)]) -> VersionVector {
        entries.iter().map(|&(n, c)| (nid(n), c)).collect()
    }

    #[test]
    fn empty_vectors_are_equal() {
        assert_eq!(
            VersionVector::new().compare(&VersionVector::new()),
            Ord3::Equal
        );
    }

    #[test]
    fn absent_component_is_zero() {
        let a = vv(&[(1, 1)]);
        let b = VersionVector::new();
        assert_eq!(a.get(&nid(2)), 0);
        assert_eq!(a.compare(&b), Ord3::Dominates);
        assert_eq!(b.compare(&a), Ord3::Dominated);
    }

    #[test]
    fn zero_entries_normalize_to_absent() {
        let a = vv(&[(1, 0), (2, 3)]);
        let b = vv(&[(2, 3)]);
        assert_eq!(a, b);
        assert_eq!(a.compare(&b), Ord3::Equal);
    }

    #[test]
    fn dominate_dominated_equal() {
        let a = vv(&[(1, 2), (2, 1)]);
        let b = vv(&[(1, 1), (2, 1)]);
        assert_eq!(a.compare(&b), Ord3::Dominates);
        assert_eq!(b.compare(&a), Ord3::Dominated);
        assert_eq!(a.compare(&a.clone()), Ord3::Equal);
        assert!(a.dominates(&b));
        assert!(!b.dominates(&a));
        assert!(!a.dominates(&a.clone()));
    }

    #[test]
    fn concurrent_neither_dominates() {
        // The reviewer-checklist case: each side is ahead on a different
        // component. Nothing — especially not a timestamp — may order these.
        let a = vv(&[(1, 2), (2, 1)]);
        let b = vv(&[(1, 1), (2, 2)]);
        assert_eq!(a.compare(&b), Ord3::Concurrent);
        assert_eq!(b.compare(&a), Ord3::Concurrent);
        assert!(!a.dominates(&b));
        assert!(!b.dominates(&a));
    }

    #[test]
    fn concurrent_with_disjoint_nodes() {
        let a = vv(&[(1, 1)]);
        let b = vv(&[(2, 1)]);
        assert_eq!(a.compare(&b), Ord3::Concurrent);
    }

    #[test]
    fn increment_strictly_dominates_predecessor() {
        let mut a = vv(&[(1, 1), (2, 5)]);
        let before = a.clone();
        a.increment(&nid(1));
        assert_eq!(a.compare(&before), Ord3::Dominates);
        assert_eq!(a.get(&nid(1)), 2);
    }

    #[test]
    fn merge_covers_both_and_is_idempotent() {
        let a = vv(&[(1, 2), (2, 1)]);
        let b = vv(&[(1, 1), (2, 3), (3, 1)]);
        let mut m = a.clone();
        m.merge(&b);
        assert_eq!(m, vv(&[(1, 2), (2, 3), (3, 1)]));
        assert!(matches!(m.compare(&a), Ord3::Dominates | Ord3::Equal));
        assert!(matches!(m.compare(&b), Ord3::Dominates | Ord3::Equal));
        let snapshot = m.clone();
        m.merge(&b); // idempotent
        assert_eq!(m, snapshot);
    }
}
