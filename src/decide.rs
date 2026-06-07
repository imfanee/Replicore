//! Architected & Developed By:- Faisal Hanif | imfanee@gmail.com
//! decide.rs — the pure apply/ignore/concurrent decision (FR-302).
//!
//! Given the local materialized state of a path and an incoming remote op,
//! decide what to do. This function is the single place that decision is made,
//! and it is a pure function of two version vectors:
//!
//! - remote strictly dominates local  → **Apply**
//! - local dominates, or equal        → **Ignore** (VV dedup half of FR-901)
//! - neither dominates                → **Concurrent** (conflict *detected*;
//!   M1 records the decision durably and skips — resolution is M3, FR-303)
//!
//! No wall-clock, no filesystem, no network may enter this decision (FR-301).
//! Tombstone non-resurrection needs **no special case** here: a delete bumps
//! the path's version vector like any other op, so a stale write that predates
//! the delete is simply `Dominated` → Ignore. A write that genuinely dominates
//! the tombstone's vector legitimately resurrects the file — that is correct
//! causality, not a bug. Do not add a clock-based guard.

use crate::vv::{Ord3, VersionVector};

/// Local materialized state for a path, as read from the `files` index.
#[derive(Clone, Debug)]
pub struct LocalFile {
    pub vv: VersionVector,
    pub tombstone: bool,
    pub content_hash: Option<[u8; 32]>,
    /// Not a decision input (metadata fidelity is M3); carried so the
    /// stale-decision repair can restore a clobbered file faithfully.
    pub mode: u32,
}

/// What to do with a remote op for one path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Decision {
    /// Remote causally dominates: apply it (write content or set tombstone).
    Apply,
    /// We are causally ahead of or identical to the remote: drop it.
    Ignore,
    /// Concurrent versions: conflict detected. M1 logs and skips, durably
    /// recording that the op was seen so it is never re-fetched.
    /// TODO(M3): deterministic winner + conflict copy (FR-303/304).
    Concurrent,
    /// The engine could not materialize the op for a PERMANENT reason
    /// (hostile path, missing/unfetchable/corrupt content, oversized): the op
    /// is durably recorded as handled WITHOUT touching the file index, so the
    /// stream advances instead of reconnect-looping on a poison op. The
    /// local VV is left behind the origin's, so a later superseding op (or
    /// M2 anti-entropy) repairs the path. Never returned by [`decide`] —
    /// only the engine downgrades Apply to this.
    Quarantined,
}

/// Decide the fate of a remote op carrying `remote_vv` for a path whose local
/// state is `local` (`None` = path never seen here, including no tombstone).
pub fn decide(local: Option<&LocalFile>, remote_vv: &VersionVector) -> Decision {
    let local = match local {
        // Never seen the path: the remote vector trivially dominates our
        // empty history. (A real op always carries at least one increment,
        // so `Equal` cannot occur against an absent row.)
        None => return Decision::Apply,
        Some(l) => l,
    };
    match remote_vv.compare(&local.vv) {
        Ord3::Dominates => Decision::Apply,
        Ord3::Dominated | Ord3::Equal => Decision::Ignore,
        Ord3::Concurrent => Decision::Concurrent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vv::NodeId;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn vv(entries: &[(u8, u64)]) -> VersionVector {
        entries.iter().map(|&(n, c)| (nid(n), c)).collect()
    }

    fn local(vv: VersionVector, tombstone: bool) -> LocalFile {
        LocalFile {
            vv,
            tombstone,
            content_hash: if tombstone { None } else { Some([0u8; 32]) },
            mode: 0o644,
        }
    }

    #[test]
    fn unknown_path_applies() {
        assert_eq!(decide(None, &vv(&[(1, 1)])), Decision::Apply);
    }

    #[test]
    fn dominating_remote_applies() {
        let l = local(vv(&[(1, 1)]), false);
        assert_eq!(decide(Some(&l), &vv(&[(1, 2)])), Decision::Apply);
        // Remote knows our history plus its own write.
        assert_eq!(decide(Some(&l), &vv(&[(1, 1), (2, 1)])), Decision::Apply);
    }

    #[test]
    fn dominated_or_equal_remote_ignored() {
        let l = local(vv(&[(1, 2), (2, 1)]), false);
        assert_eq!(decide(Some(&l), &vv(&[(1, 1)])), Decision::Ignore);
        // Re-delivered op with identical vector: dedup (FR-901).
        assert_eq!(decide(Some(&l), &vv(&[(1, 2), (2, 1)])), Decision::Ignore);
    }

    #[test]
    fn concurrent_detected_not_ordered() {
        // Reviewer checklist: the concurrent case must be detected, and the
        // decision must come from the vectors alone — there is no tie-break
        // input to this function at all.
        let l = local(vv(&[(1, 2), (2, 1)]), false);
        assert_eq!(
            decide(Some(&l), &vv(&[(1, 1), (2, 2)])),
            Decision::Concurrent
        );
    }

    #[test]
    fn stale_write_does_not_resurrect_tombstone() {
        // Delete happened at vv {a:2} (the delete itself incremented a's
        // counter). A slow peer re-sends a write from before the delete.
        let dead = local(vv(&[(1, 2)]), true);
        assert_eq!(decide(Some(&dead), &vv(&[(1, 1)])), Decision::Ignore);
    }

    #[test]
    fn genuinely_newer_write_resurrects_tombstone() {
        // A write that causally followed the delete dominates the tombstone:
        // resurrection is the *correct* outcome (it saw the delete and wrote
        // anyway).
        let dead = local(vv(&[(1, 2)]), true);
        assert_eq!(decide(Some(&dead), &vv(&[(1, 2), (2, 1)])), Decision::Apply);
    }

    #[test]
    fn concurrent_write_vs_tombstone_is_conflict() {
        // delete-vs-modify race: detected as Concurrent in M1, resolved in M3
        // (FR-304). The tombstone stays (skip), the conflict is recorded.
        let dead = local(vv(&[(1, 2)]), true);
        assert_eq!(
            decide(Some(&dead), &vv(&[(1, 1), (2, 1)])),
            Decision::Concurrent
        );
    }

    #[test]
    fn delete_op_follows_same_rules() {
        // A remote delete is just an op: dominating delete applies (sets the
        // tombstone), stale delete is ignored.
        let l = local(vv(&[(1, 1), (2, 1)]), false);
        assert_eq!(decide(Some(&l), &vv(&[(1, 2), (2, 1)])), Decision::Apply);
        assert_eq!(decide(Some(&l), &vv(&[(1, 1)])), Decision::Ignore);
    }
}
