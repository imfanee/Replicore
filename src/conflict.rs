//! conflict.rs — deterministic conflict resolution, the pure half (FR-303/304).
//!
//! `decide.rs` answers *whether* two versions are concurrent; this module
//! answers *which one wins* and *what the losers' conflict copies are called*.
//! Like `decide`, it is deliberately pure: no clock, no I/O, no node-local
//! state. The committing half (materializing the winner row + copy rows inside
//! the re-validated transaction) lives in `oplog.rs::resolve_rows` —
//! resolution is layered OUTSIDE `decide`, never inside it.
//!
//! ## The determinism law (the membership lesson, FR-303)
//!
//! Every node resolving the SAME conflict must derive the same winner and the
//! same conflict-copy names, or replicas diverge forever. So the winner is a
//! **total order over content all nodes agree on** — mirroring the roster's
//! `(epoch, rank(kind), content_hash)` order key:
//!
//! ```text
//! side_key = (kind_rank, content_hash, meta_hash)      larger wins
//!   kind_rank:    Write(1) > Delete(0)  — modify wins over delete (FR-304:
//!                 a concurrent write resurrects; the delete loses and carries
//!                 no content, so nothing is lost and no copy is made)
//!   content_hash: BLAKE3 of the version's content — agreed mesh-wide
//!   meta_hash:    breaks content ties deterministically (meta-only conflicts
//!                 pick one side's metadata; identical content is never copied)
//! ```
//!
//! ## Resolution input: the antichain, never just a pair
//!
//! The winner is `max(side_key)` over the **maximal antichain** of the path's
//! candidate versions — the versions no other candidate causally dominates.
//! Candidates are the path's op history (which every node converges on), plus
//! the current row when ops do not fully explain it (post-bootstrap), plus the
//! remote leaf during reconcile.
//!
//! Pairwise row-vs-op contests are PROVABLY non-confluent: resolving a pair
//! merges both VVs into the row, and a later op that causally supersedes one
//! input then meets the row as "concurrent" — letting an already-superseded
//! intermediate win the content contest on nodes that witnessed it, and not
//! on nodes that didn't. End state: equal VVs, different content, unhealable.
//! Deriving from the antichain makes the winner a pure function of the op SET
//! (max is associative and commutative), so delivery order cannot matter, and
//! a superseded intermediate is never maximal — it can never win.
//!
//! Deliberately NOT inputs: wall-clock time (FR-301), the local node id, and
//! the writing op's `(origin, origin_seq)` — they are not symmetric knowledge.
//!
//! ## Conflict-copy naming
//!
//! The copy name is a pure function of the LOSING content AND its STABLE
//! metadata subset: `<stem>.sync-conflict-<hex16><.ext>` with
//! `hex16 = blake3(loser_content_hash ‖ Meta::naming_hash(loser_meta))[..8]`.
//! The naming subset is {kind, mode, rdev, symlink_target, xattrs} and
//! EXCLUDES mtime/uid/gid (durable, node-agreed fields distinguish copies;
//! timestamp/ownership skew would only proliferate near-duplicates — see
//! docs/review-copy-naming.md). Same path + same content + same durable meta
//! ⇒ same name on every node; re-deriving is idempotent; a genuine durable
//! difference names a distinct copy (S1 no-loss). The committed copy ROW
//! still stores the loser's FULL metadata — only the NAME uses the subset.
//!
//! Copies derived at intermediate states (before the full op set arrived)
//! persist — they are never garbage-collected by a later derivation. The set
//! of copies is the union of what any node ever derived, spread by reconcile;
//! conservative in exactly the no-silent-loss direction (FR-303).
//!
//! ## The copy row's version vector
//!
//! A copy is **derived locally on every node that witnesses the conflict — it
//! is never emitted as an op** (the resolution commit writes only `files`, and
//! a copy op from two resolvers would itself conflict). For every node to
//! derive a byte-identical row, the copy's VV must also be a pure function of
//! the conflict: a single component `{ copy_origin(copy_path): 1 }`, where the
//! synthetic origin is `blake3("replicore-conflict" ‖ copy_path)[..16]`.
//! A user edit to the copy increments a real component on top and dominates
//! normally. If the copy path collides with a genuinely existing file, the
//! synthetic VV is concurrent with any real VV, so the collision is just
//! another conflict resolved by this same machinery — no node-local existence
//! probe (that input would diverge names across nodes).

use crate::metadata::Meta;
use crate::state::FileRow;
use crate::vv::{NodeId, Ord3, VersionVector};

/// Marker embedded in every conflict-copy file name. Copies are ordinary
/// replicated files; the marker exists for operators and tests, not the engine.
pub const COPY_MARKER: &str = ".sync-conflict-";

/// `meta_hash` for versions without metadata (deletes, pre-v4 rows).
pub use crate::metadata::META_NONE;

/// A full version descriptor: one candidate in a resolution. Op history rows,
/// the current `files` row, and reconcile leaves all reduce to this.
#[derive(Clone, Debug)]
pub struct Version {
    pub tombstone: bool,
    /// `None` only for tombstones (a delete carries no content).
    pub content_hash: Option<[u8; 32]>,
    /// Canonical hash of `meta` ([`META_NONE`] when absent): the third level
    /// of the winner key, so meta-only conflicts resolve deterministically.
    pub meta_hash: [u8; 32],
    /// The metadata itself — committed with the row the version wins.
    pub meta: Option<Meta>,
    pub mode: u32,
    pub size: u64,
    pub vv: VersionVector,
    /// File identity (FR-205). NOT a winner-key input — identity does not
    /// rank content — but the committed winner row carries the winner's uuid
    /// (normalized like `mode` when keys tie).
    pub uuid: Option<[u8; 16]>,
}

impl Version {
    /// The total-order key. Larger wins. (See the module header.)
    fn key(&self) -> (u8, [u8; 32], [u8; 32]) {
        (
            // Kind rank: Write beats Delete at concurrency (modify wins).
            u8::from(!self.tombstone),
            self.content_hash.unwrap_or([0u8; 32]),
            self.meta_hash,
        )
    }

    /// A candidate from the `files` index (the row view).
    pub fn from_row(row: &FileRow) -> Version {
        Version {
            tombstone: row.tombstone,
            content_hash: row.content_hash,
            meta_hash: Meta::hash_of(&row.meta),
            meta: row.meta.clone(),
            mode: row.mode,
            size: row.size,
            vv: row.vv.clone(),
            uuid: row.uuid,
        }
    }
}

/// One row mutation a resolution will commit. The committing transaction
/// re-derives the plan from fresh rows and commits only on exact equality
/// with what the caller staged — the conflict-path form of the stale-decision
/// re-check.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlannedRow {
    pub path: String,
    pub content_hash: Option<[u8; 32]>,
    pub mode: u32,
    pub size: u64,
    pub tombstone: bool,
    pub vv: VersionVector,
    pub uuid: Option<[u8; 16]>,
    pub meta: Option<Meta>,
}

/// Copy chains longer than this are refused (`plan_candidates` returns
/// `None`). Reaching depth 2 already requires a real file occupying a name
/// that embeds 16 hex chars of a BLAKE3 hash; nested collisions do not happen
/// by accident — refusing keeps the resolution auditable instead of unbounded.
pub const MAX_COPY_DEPTH: usize = 4;

/// Reduce candidates to the maximal antichain: drop every version another
/// candidate strictly dominates, and collapse causally-equal duplicates (an
/// op redelivered, or the row echoing an op). Output order is normalized by
/// `key()` descending, so the derivation is independent of input order.
fn antichain(candidates: &[Version]) -> Vec<&Version> {
    let mut keep: Vec<&Version> = Vec::new();
    'cand: for c in candidates {
        let mut i = 0;
        while i < keep.len() {
            match c.vv.compare(&keep[i].vv) {
                Ord3::Dominated | Ord3::Equal => continue 'cand,
                Ord3::Dominates => {
                    keep.remove(i);
                }
                Ord3::Concurrent => i += 1,
            }
        }
        keep.push(c);
    }
    keep.sort_by_key(|v| std::cmp::Reverse(v.key()));
    keep
}

/// Derive the full, deterministic row plan for one conflicted path.
///
/// - **Winner** = `max(side_key)` over the antichain of `candidates` — a pure
///   function of the candidate SET (max is associative/commutative), so every
///   node with the same set derives the same winner in any delivery order.
/// - **Winner row VV** = merge of ALL candidates' VVs: the row absorbs every
///   contender, so none can re-fire and stale versions cannot reintroduce
///   themselves.
/// - **Copies**: every losing antichain member that carries content distinct
///   from the winner's, at its content-derived name. `lookup` supplies
///   existing rows at candidate copy paths so collisions resolve through the
///   same total order; every input is replicated state, so every node derives
///   the same plan from the same rows.
///
/// Determinism details encoded here, in one place:
/// - Equal keys (identical kind+content+meta, only the VVs concurrent): the
///   versions are interchangeable except `mode` (not part of any key until
///   3c) — normalized to the max mode among equal-key members.
/// - Tombstone winner rows are normalized to `mode 0, size 0`: a tombstone's
///   mode is meaningless and contenders' may differ, but committed rows must
///   not.
///
/// Returns `None` if a copy chain exceeds [`MAX_COPY_DEPTH`], or if
/// `candidates` is empty.
pub fn plan_candidates<E>(
    path: &str,
    candidates: &[Version],
    lookup: &mut dyn FnMut(&str) -> Result<Option<Version>, E>,
) -> Result<Option<Vec<PlannedRow>>, E> {
    let maximal = antichain(candidates);
    let Some(winner) = maximal.first() else {
        return Ok(None);
    };
    let mut vv = VersionVector::new();
    for c in candidates {
        vv.merge(&c.vv);
    }
    // Among equal-key members the content is identical but mode/uuid are not
    // part of any key: normalize so all nodes commit the same row.
    let equal_key = || maximal.iter().filter(|m| m.key() == winner.key());
    let mode = if winner.tombstone {
        0
    } else {
        equal_key().map(|m| m.mode).max().unwrap_or(winner.mode)
    };
    let uuid = equal_key().filter_map(|m| m.uuid).max().or(winner.uuid);
    let mut rows = vec![PlannedRow {
        path: path.to_string(),
        content_hash: winner.content_hash,
        mode,
        size: if winner.tombstone { 0 } else { winner.size },
        tombstone: winner.tombstone,
        vv,
        uuid,
        // Equal keys ⇒ equal meta_hash ⇒ identical canonical meta: no
        // normalization needed beyond the winner's own.
        meta: if winner.tombstone {
            None
        } else {
            winner.meta.clone()
        },
    }];

    // Losers with content of their own become copies. The antichain is key-
    // sorted, so the copy order (and any collision chaining below) is
    // derivation-order-free.
    for loser in maximal.iter().skip(1) {
        let Some(hash) = loser.content_hash else {
            continue; // losing delete: nothing to preserve (modify wins)
        };
        if loser.key() == winner.key() {
            // Identical kind+content+META: truly interchangeable, nothing to
            // preserve. A meta-only loser (same bytes, different meta) does
            // NOT pass this test — its metadata snapshot is replicated state
            // and gets a copy like any other loser (FR-303; review finding).
            continue;
        }
        // The copy chain: each link is (copy path, the version whose content
        // lands there); a collision with a live row pushes the chain one
        // deterministic link further. The NAME uses the stable metadata
        // subset (Meta::naming_hash — excludes mtime/uid/gid) so mtime/owner-
        // only losers coalesce; the committed row below keeps FULL `meta`.
        let mut link = Some((
            copy_path_for(path, &hash, &Meta::naming_hash(&loser.meta)),
            (**loser).clone(),
        ));
        let mut depth = 0usize;
        while let Some((cp, content)) = link.take() {
            depth += 1;
            if depth > MAX_COPY_DEPTH {
                return Ok(None);
            }
            // A copy planned for this same resolution already? The name is a
            // pure function of (content, naming-subset meta), so a collision
            // here means a same-content, same-DURABLE-meta version is already
            // preserved. Two losers differing ONLY in the excluded fields
            // (mtime/uid/gid) intentionally COALESCE to this one copy — the
            // first wins; the metadata that survives is its full snapshot.
            if let Some(planned) = rows.iter().find(|r| r.path == cp) {
                debug_assert_eq!(planned.content_hash, content.content_hash);
                debug_assert_eq!(
                    Meta::naming_hash(&planned.meta),
                    Meta::naming_hash(&content.meta),
                    "copy-name collision with differing durable meta"
                );
                break;
            }
            let cvv = copy_vv(&cp);
            // A copy row's uuid is as synthetic as its VV: a deterministic
            // function of the copy path (a copy is a NEW file, not the
            // original's identity at a second name).
            let cuuid = Some(copy_origin(&cp));
            match lookup(&cp)? {
                None => rows.push(PlannedRow {
                    path: cp.clone(),
                    content_hash: content.content_hash,
                    mode: content.mode,
                    size: content.size,
                    tombstone: false,
                    vv: cvv,
                    uuid: cuuid,
                    meta: content.meta.clone(),
                }),
                Some(existing) => match cvv.compare(&existing.vv) {
                    // Empty-history row only; treat like absent.
                    Ord3::Dominates => rows.push(PlannedRow {
                        path: cp.clone(),
                        content_hash: content.content_hash,
                        mode: content.mode,
                        size: content.size,
                        tombstone: false,
                        vv: cvv,
                        uuid: cuuid,
                        meta: content.meta.clone(),
                    }),
                    // Idempotent re-derivation (Equal) or the copy was since
                    // edited by a user (Dominated): the existing row stands.
                    Ord3::Equal | Ord3::Dominated => {}
                    // A real file occupies the copy name: the same machinery,
                    // one level down — winner by the total order, loser pushed
                    // to a content-derived name of its own.
                    Ord3::Concurrent => {
                        let as_copy = Version {
                            tombstone: false,
                            vv: cvv.clone(),
                            uuid: cuuid,
                            ..content.clone()
                        };
                        let pair = [existing.clone(), as_copy];
                        let nested = antichain(&pair);
                        let (w, l) = (nested[0], nested[1]);
                        let mut nvv = existing.vv.clone();
                        nvv.merge(&cvv);
                        let keys_tie = w.key() == l.key();
                        rows.push(PlannedRow {
                            path: cp.clone(),
                            content_hash: w.content_hash,
                            mode: if keys_tie { w.mode.max(l.mode) } else { w.mode },
                            size: w.size,
                            tombstone: false,
                            vv: nvv,
                            uuid: if keys_tie {
                                w.uuid.max(l.uuid)
                            } else {
                                w.uuid.or(cuuid)
                            },
                            meta: w.meta.clone(),
                        });
                        if let Some(lh) = l.content_hash {
                            if l.key() != w.key() {
                                link = Some((
                                    copy_path_for(&cp, &lh, &Meta::naming_hash(&l.meta)),
                                    l.clone(),
                                ));
                            }
                        }
                    }
                },
            }
        }
    }
    Ok(Some(rows))
}

/// Conflict-copy name for a losing VERSION: a pure function of the losing
/// content hash AND a metadata hash — never the clock, never node-local
/// state. Callers pass the STABLE naming subset ([`Meta::naming_hash`],
/// excludes mtime/uid/gid) so a loser differing only in durable metadata
/// (a real xattr/mode/kind difference) gets its own deterministic name
/// (S1 no-loss), while mtime/owner-only variants coalesce to one copy.
/// `META_NONE` for meta-less (delete-shaped) losers. See
/// docs/review-copy-naming.md.
///
/// `dir/report.txt` → `dir/report.sync-conflict-<hex16>.txt`. The extension is
/// preserved (operators expect `.wav` to stay playable); a leading dot is not
/// an extension (`.bashrc` → `.bashrc.sync-conflict-<hex16>`).
pub fn copy_path_for(path: &str, loser_hash: &[u8; 32], loser_meta: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(loser_hash);
    h.update(loser_meta);
    let hex16 = hex::encode(&h.finalize().as_bytes()[..8]);
    let (dir, name) = match path.rfind('/') {
        Some(i) => (&path[..=i], &path[i + 1..]),
        None => ("", path),
    };
    match name.rfind('.').filter(|&i| i > 0) {
        Some(i) => format!("{dir}{}{COPY_MARKER}{hex16}.{}", &name[..i], &name[i + 1..]),
        None => format!("{dir}{name}{COPY_MARKER}{hex16}"),
    }
}

/// Synthetic origin for a conflict-copy row: `blake3("replicore-conflict" ‖
/// copy_path)[..16]`. Disjoint by construction from configured node ids in any
/// realistic deployment.
pub fn copy_origin(copy_path: &str) -> NodeId {
    let mut h = blake3::Hasher::new();
    h.update(b"replicore-conflict");
    h.update(copy_path.as_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&h.finalize().as_bytes()[..16]);
    id
}

/// The copy row's version vector: `{ copy_origin: 1 }` — identical on every
/// node that derives the copy, so the Merkle leaf never flaps in reconcile.
pub fn copy_vv(copy_path: &str) -> VersionVector {
    std::iter::once((copy_origin(copy_path), 1)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    fn nid(b: u8) -> NodeId {
        let mut id = [0u8; 16];
        id[0] = b;
        id
    }

    fn vv(entries: &[(u8, u64)]) -> VersionVector {
        entries.iter().map(|&(n, c)| (nid(n), c)).collect()
    }

    fn write(hash: u8, v: VersionVector) -> Version {
        Version {
            tombstone: false,
            content_hash: Some([hash; 32]),
            meta_hash: META_NONE,
            mode: 0o644,
            size: 1,
            vv: v,
            uuid: None,
            meta: None,
        }
    }

    /// A write carrying a REAL `Meta` (so `naming_hash` reflects it). The
    /// `meta_hash` field is kept consistent with `meta` like production.
    fn write_meta(hash: u8, v: VersionVector, meta: crate::metadata::Meta) -> Version {
        let some = Some(meta);
        Version {
            tombstone: false,
            content_hash: Some([hash; 32]),
            meta_hash: Meta::hash_of(&some),
            mode: some.as_ref().unwrap().mode,
            size: 1,
            vv: v,
            uuid: None,
            meta: some,
        }
    }

    fn base_meta() -> crate::metadata::Meta {
        crate::metadata::Meta {
            kind: crate::metadata::FileKind::Regular,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime_s: 1_000,
            mtime_ns: 0,
            symlink_target: None,
            rdev: 0,
            xattrs: vec![],
        }
    }

    fn tomb(v: VersionVector) -> Version {
        Version {
            tombstone: true,
            content_hash: None,
            meta_hash: META_NONE,
            mode: 0o644,
            size: 0,
            vv: v,
            uuid: None,
            meta: None,
        }
    }

    fn plan(path: &str, candidates: &[Version]) -> Vec<PlannedRow> {
        match plan_candidates::<Infallible>(path, candidates, &mut |_| Ok(None)) {
            Ok(p) => p.expect("plan"),
        }
    }

    /// The convergence law itself: the plan is a pure function of the
    /// candidate SET — any permutation derives byte-identical rows.
    #[test]
    fn plan_is_order_independent() {
        let c = [
            write(3, vv(&[(1, 1)])),
            write(7, vv(&[(2, 1)])),
            tomb(vv(&[(3, 1)])),
        ];
        let base = plan("dir/f.txt", &c);
        let mut perm = c.to_vec();
        perm.rotate_left(1);
        assert_eq!(plan("dir/f.txt", &perm), base);
        perm.reverse();
        assert_eq!(plan("dir/f.txt", &perm), base);
        // The conflict copy's NAME is part of that byte-identical plan — two
        // nodes deriving the same conflict (same candidate set, any order)
        // produce the identical copy path. This is the determinism property.
        let copy = base.iter().find(|r| r.path.contains(COPY_MARKER));
        assert!(copy.is_some(), "expected a conflict copy in the plan");
    }

    /// The pairwise non-confluence repro: B writes H0, C writes H1 then H0.
    /// C's second write causally supersedes its first — H1 is never maximal
    /// and must never win or be copied, regardless of how the candidates are
    /// presented.
    #[test]
    fn superseded_intermediate_never_wins() {
        let b1 = write(0, vv(&[(2, 1)]));
        let c1 = write(1, vv(&[(3, 1)]));
        let c2 = write(0, vv(&[(3, 2)]));
        for candidates in [
            vec![b1.clone(), c1.clone(), c2.clone()],
            vec![c2.clone(), c1.clone(), b1.clone()],
            vec![c1.clone(), b1.clone(), c2.clone()],
        ] {
            let rows = plan("p", &candidates);
            assert_eq!(rows.len(), 1, "no copy: the maximal contents are equal");
            assert_eq!(rows[0].content_hash, Some([0u8; 32]));
            assert_eq!(rows[0].vv, vv(&[(2, 1), (3, 2)]));
        }
    }

    #[test]
    fn winner_is_max_key_and_losers_become_copies() {
        let lo = write(3, vv(&[(1, 1)]));
        let hi = write(7, vv(&[(2, 1)]));
        let rows = plan("dir/f.txt", &[lo.clone(), hi.clone()]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].path, "dir/f.txt");
        assert_eq!(rows[0].content_hash, Some([7u8; 32]));
        assert_eq!(rows[0].vv, vv(&[(1, 1), (2, 1)])); // merged: neither re-fires
        assert_eq!(
            rows[1].path,
            copy_path_for("dir/f.txt", &[3u8; 32], &META_NONE)
        );
        assert_eq!(rows[1].content_hash, Some([3u8; 32]));
        assert_eq!(rows[1].vv, copy_vv(&rows[1].path));
    }

    #[test]
    fn modify_wins_over_delete_no_copy() {
        // FR-304 delete-vs-modify: the write resurrects; the losing delete
        // (no content) produces no copy.
        let rows = plan("f", &[tomb(vv(&[(1, 1)])), write(1, vv(&[(2, 1)]))]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content_hash, Some([1u8; 32]));
        assert!(!rows[0].tombstone);
    }

    #[test]
    fn delete_vs_delete_merges_without_copy() {
        let rows = plan("f", &[tomb(vv(&[(1, 1)])), tomb(vv(&[(2, 1)]))]);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].tombstone);
        // Tombstone rows are normalized: contenders' modes may differ.
        assert_eq!((rows[0].mode, rows[0].size), (0, 0));
        assert_eq!(rows[0].vv, vv(&[(1, 1), (2, 1)]));
    }

    #[test]
    fn identical_content_is_never_copied() {
        let rows = plan("f", &[write(5, vv(&[(1, 1)])), write(5, vv(&[(2, 1)]))]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content_hash, Some([5u8; 32]));
    }

    #[test]
    fn equal_keys_normalize_mode_to_max() {
        let mut a = write(5, vv(&[(1, 1)]));
        let mut b = write(5, vv(&[(2, 1)]));
        a.mode = 0o600;
        b.mode = 0o644;
        let rows = plan("f", &[a.clone(), b.clone()]);
        assert_eq!(rows[0].mode, 0o644);
        let rows = plan("f", &[b, a]); // either order
        assert_eq!(rows[0].mode, 0o644);
    }

    #[test]
    fn durable_meta_losers_get_distinct_copies() {
        // S1 (review-copy-naming.md §2): two losers with identical bytes but a
        // genuine DURABLE metadata difference (mode here, xattr below) must
        // each be preserved as a DISTINCT copy — the naming subset keeps mode
        // and xattrs, so the names differ. (Winner = the one whose full key
        // is larger; the two losers are what we check survive.)
        let mut hi = write_meta(9, vv(&[(1, 1)]), base_meta()); // content winner
        hi.meta = Some(crate::metadata::Meta {
            mode: 0o600,
            ..base_meta()
        });
        hi.meta_hash = Meta::hash_of(&hi.meta);
        hi.mode = 0o600;
        let mut lo_a = write_meta(5, vv(&[(2, 1)]), base_meta()); // loser, mode 644
        let mut lo_b = write_meta(5, vv(&[(3, 1)]), base_meta()); // loser, same bytes
        lo_b.meta = Some(crate::metadata::Meta {
            mode: 0o755,
            ..base_meta()
        });
        lo_b.meta_hash = Meta::hash_of(&lo_b.meta);
        lo_b.mode = 0o755;
        // lo_a and lo_b share content (5) but differ in mode (644 vs 755).
        let _ = &mut lo_a;
        let rows = plan("f", &[hi.clone(), lo_a.clone(), lo_b.clone()]);
        let copies: Vec<_> = rows
            .iter()
            .filter(|r| r.path.contains(COPY_MARKER))
            .collect();
        assert_eq!(
            copies.len(),
            2,
            "two losers with different DURABLE meta (mode) must each be copied (S1)"
        );
        let names: std::collections::BTreeSet<_> = copies.iter().map(|r| &r.path).collect();
        assert_eq!(names.len(), 2, "the two copies must have DISTINCT names");
        // Order-independent.
        let rows2 = plan("f", &[lo_b, lo_a, hi]);
        assert_eq!(rows, rows2);

        // Same content, different XATTR → also distinct copies.
        let mut x = write_meta(9, vv(&[(1, 1)]), base_meta());
        let mut y_a = write_meta(5, vv(&[(2, 1)]), base_meta());
        let mut y_b = write_meta(5, vv(&[(3, 1)]), base_meta());
        y_a.meta = Some(crate::metadata::Meta {
            xattrs: vec![(b"user.k".to_vec(), b"1".to_vec())],
            ..base_meta()
        });
        y_a.meta_hash = Meta::hash_of(&y_a.meta);
        y_b.meta = Some(crate::metadata::Meta {
            xattrs: vec![(b"user.k".to_vec(), b"2".to_vec())],
            ..base_meta()
        });
        y_b.meta_hash = Meta::hash_of(&y_b.meta);
        let _ = &mut x;
        let xr = plan("g", &[x, y_a, y_b]);
        assert_eq!(
            xr.iter().filter(|r| r.path.contains(COPY_MARKER)).count(),
            2,
            "two losers differing only by xattr value must each be copied (S1)"
        );
    }

    #[test]
    fn mtime_only_losers_coalesce_to_one_copy() {
        // Proliferation fix (review-copy-naming.md §1): two losers with
        // identical bytes AND identical durable meta but DIFFERENT mtime must
        // collapse to ONE copy — mtime is excluded from the name.
        let winner = write_meta(9, vv(&[(1, 1)]), base_meta()); // content winner
        let mut l1 = write_meta(5, vv(&[(2, 1)]), base_meta());
        let mut l2 = write_meta(5, vv(&[(3, 1)]), base_meta());
        l1.meta = Some(crate::metadata::Meta {
            mtime_s: 100,
            ..base_meta()
        });
        l1.meta_hash = Meta::hash_of(&l1.meta);
        l2.meta = Some(crate::metadata::Meta {
            mtime_s: 999,
            ..base_meta()
        });
        l2.meta_hash = Meta::hash_of(&l2.meta);
        // Distinct full meta_hash (mtime differs) but same naming subset.
        assert_ne!(l1.meta_hash, l2.meta_hash);
        assert_eq!(
            Meta::naming_hash(&l1.meta),
            Meta::naming_hash(&l2.meta),
            "mtime must not affect the naming subset"
        );
        let rows = plan("f", &[winner, l1, l2]);
        assert_eq!(
            rows.iter().filter(|r| r.path.contains(COPY_MARKER)).count(),
            1,
            "mtime-only-different losers must coalesce to ONE copy"
        );
    }

    #[test]
    fn uid_only_losers_coalesce_to_one_copy() {
        // ownership is excluded too (the residual EPERM-skew case): two
        // losers differing only in uid/gid coalesce.
        let winner = write_meta(9, vv(&[(1, 1)]), base_meta());
        let mut l1 = write_meta(5, vv(&[(2, 1)]), base_meta());
        let mut l2 = write_meta(5, vv(&[(3, 1)]), base_meta());
        l1.meta = Some(crate::metadata::Meta {
            uid: 1000,
            gid: 1000,
            ..base_meta()
        });
        l1.meta_hash = Meta::hash_of(&l1.meta);
        l2.meta = Some(crate::metadata::Meta {
            uid: 2000,
            gid: 2000,
            ..base_meta()
        });
        l2.meta_hash = Meta::hash_of(&l2.meta);
        let rows = plan("f", &[winner, l1, l2]);
        assert_eq!(
            rows.iter().filter(|r| r.path.contains(COPY_MARKER)).count(),
            1,
            "uid/gid-only-different losers must coalesce to ONE copy"
        );
    }

    #[test]
    fn kind_rank_dominates_content_hash() {
        // Even a maximal content hash on a tombstone cannot beat a write —
        // the kind rank is the first key level. (Guards against reordering
        // the tuple by accident.)
        let mut t = tomb(vv(&[(1, 1)]));
        t.content_hash = None;
        let rows = plan("f", &[t, write(0, vv(&[(2, 1)]))]);
        assert!(!rows[0].tombstone);
        assert_eq!(rows[0].content_hash, Some([0u8; 32]));
    }

    #[test]
    fn copy_collision_resolves_through_the_same_order() {
        // A real file already lives at the loser's copy name: the collision
        // is just another conflict — winner by key at the copy path, the
        // displaced content pushed one content-derived link further.
        let lo = write(3, vv(&[(1, 1)]));
        let hi = write(7, vv(&[(2, 1)]));
        let cp = copy_path_for("f", &[3u8; 32], &META_NONE);
        let squatter = write(9, vv(&[(4, 2)])); // real row at the copy path
        let rows = match plan_candidates::<Infallible>("f", &[lo, hi], &mut |p| {
            Ok((p == cp).then(|| squatter.clone()))
        }) {
            Ok(p) => p.expect("plan"),
        };
        assert_eq!(rows.len(), 3);
        // Copy-path row: squatter (hash 9) beats the loser content (hash 3);
        // VV merges the squatter's history with the synthetic component.
        let crow = rows.iter().find(|r| r.path == cp).unwrap();
        assert_eq!(crow.content_hash, Some([9u8; 32]));
        let mut expect_vv = vv(&[(4, 2)]);
        expect_vv.merge(&copy_vv(&cp));
        assert_eq!(&crow.vv, &expect_vv);
        // The displaced loser lands one link further, named by its content.
        let cp2 = copy_path_for(&cp, &[3u8; 32], &META_NONE);
        let c2row = rows.iter().find(|r| r.path == cp2).unwrap();
        assert_eq!(c2row.content_hash, Some([3u8; 32]));
        assert_eq!(&c2row.vv, &copy_vv(&cp2));
    }

    #[test]
    fn existing_identical_copy_is_left_alone() {
        // Re-derivation when the copy row already exists (Equal VV): no row
        // is planned for it — idempotent.
        let lo = write(3, vv(&[(1, 1)]));
        let hi = write(7, vv(&[(2, 1)]));
        let cp = copy_path_for("f", &[3u8; 32], &META_NONE);
        let existing = Version {
            tombstone: false,
            content_hash: Some([3u8; 32]),
            meta_hash: META_NONE,
            mode: 0o644,
            size: 1,
            vv: copy_vv(&cp),
            uuid: None,
            meta: None,
        };
        let rows = match plan_candidates::<Infallible>("f", &[lo, hi], &mut |p| {
            Ok((p == cp).then(|| existing.clone()))
        }) {
            Ok(p) => p.expect("plan"),
        };
        assert_eq!(rows.len(), 1, "only the winner row; the copy stands");
    }

    #[test]
    fn user_edited_copy_is_never_clobbered() {
        // The copy was edited locally after a previous resolution: its VV
        // dominates the synthetic one, so re-derivation leaves it alone.
        let lo = write(3, vv(&[(1, 1)]));
        let hi = write(7, vv(&[(2, 1)]));
        let cp = copy_path_for("f", &[3u8; 32], &META_NONE);
        let mut edited_vv = copy_vv(&cp);
        edited_vv.increment(&nid(9));
        let edited = write(8, edited_vv);
        let rows = match plan_candidates::<Infallible>("f", &[lo, hi], &mut |p| {
            Ok((p == cp).then(|| edited.clone()))
        }) {
            Ok(p) => p.expect("plan"),
        };
        assert_eq!(rows.len(), 1, "only the winner row; the edit stands");
    }

    #[test]
    fn copy_name_is_deterministic_and_content_addressed() {
        let h1 = [9u8; 32];
        let h2 = [10u8; 32];
        assert_eq!(
            copy_path_for("a/b/f.txt", &h1, &META_NONE),
            copy_path_for("a/b/f.txt", &h1, &META_NONE)
        );
        assert_ne!(
            copy_path_for("a/b/f.txt", &h1, &META_NONE),
            copy_path_for("a/b/f.txt", &h2, &META_NONE)
        );
        // Pure function of (path, losing content): no clock, no node input.
    }

    #[test]
    fn copy_name_formats() {
        let h = [0xabu8; 32];
        let hex16 = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&h);
            hasher.update(&META_NONE);
            hex::encode(&hasher.finalize().as_bytes()[..8])
        };
        assert_eq!(
            copy_path_for("dir/report.txt", &h, &META_NONE),
            format!("dir/report.sync-conflict-{hex16}.txt")
        );
        // No extension: marker is appended.
        assert_eq!(
            copy_path_for("dir/Makefile", &h, &META_NONE),
            format!("dir/Makefile.sync-conflict-{hex16}")
        );
        // A leading dot is not an extension.
        assert_eq!(
            copy_path_for(".bashrc", &h, &META_NONE),
            format!(".bashrc.sync-conflict-{hex16}")
        );
        // Multi-dot: split on the LAST dot only.
        assert_eq!(
            copy_path_for("a/archive.tar.gz", &h, &META_NONE),
            format!("a/archive.tar.sync-conflict-{hex16}.gz")
        );
        // Dots in directories never confuse the split.
        assert_eq!(
            copy_path_for("v1.2/notes", &h, &META_NONE),
            format!("v1.2/notes.sync-conflict-{hex16}")
        );
    }

    #[test]
    fn copy_vv_is_a_pure_function_of_the_copy_path() {
        let p = "dir/f.sync-conflict-0011223344556677.txt";
        assert_eq!(copy_vv(p), copy_vv(p));
        assert_eq!(copy_origin(p), copy_origin(p));
        // Distinct copies get distinct synthetic origins.
        assert_ne!(copy_origin(p), copy_origin("dir/g.sync-conflict-aa.txt"));
        // Exactly one component at count 1: dominates an absent row once,
        // and any later real edit dominates it.
        let vv = copy_vv(p);
        assert_eq!(vv.get(&copy_origin(p)), 1);
    }
}
