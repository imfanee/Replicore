# Review — conflict-copy naming by a stable metadata subset

Determinism-critical AND no-loss-critical surface (the S1 class). This proves
the two required properties of the change that makes copy NAMES derive from a
stable metadata subset (`Meta::naming_hash`, `src/metadata.rs:146`) instead of
the full `meta_hash`. Citations are to the code as committed with this change.

**Correction of record (carried from the task):** the tree did NOT previously
exclude mtime from copy naming — `copy_path_for` hashed the full `meta_hash`
(mtime+uid+gid) right up to this change; the prior turn only documented the
option. This review covers the change *as now implemented*.

The copy NAME is:
```
copy_path_for(path, loser.content_hash, Meta::naming_hash(&loser.meta))
        = <stem>.sync-conflict-<blake3(content_hash ‖ naming_hash)[..8]><.ext>
```
(`src/conflict.rs:378`, fed at `:257` and `:341`). The committed copy **row**
still stores the loser's FULL `meta` (`PlannedRow.meta`, `src/conflict.rs:292,
304, 337`) — only the NAME uses the subset.

---

## Field list

`Meta::naming_hash` (`src/metadata.rs:146`) hashes a fixed, length-prefixed
encoding of:

| Field | In name? | Why |
|---|---|---|
| `kind` | **INCLUDED** | regular/symlink/fifo/dev are genuinely different files |
| `mode` | **INCLUDED** | a real permission difference is durable, user-set |
| `rdev` | **INCLUDED** | device number is the node's identity |
| `symlink_target` | **INCLUDED** | a different target is a different link |
| `xattrs` (⊃ POSIX ACLs) | **INCLUDED** | durable, user-set; sorted+len-prefixed |
| `mtime_s`, `mtime_ns` | **EXCLUDED** | timestamp skew has no content meaning |
| `uid`, `gid` | **EXCLUDED** | ownership skew; also diverges under residual EPERM |
| (`content_hash`) | in name, separately | the bytes — the primary discriminator |

`naming_hash(&None) == META_NONE` so every meta-less (delete-shaped) loser
keeps the exact name it had before this change (all existing `META_NONE`
callers are byte-for-byte unaffected).

---

## Proof 1 — NODE-AGNOSTIC NAMING

**Claim:** two nodes resolving the same conflict derive the identical copy
name; no included field can differ between them, and mtime/uid/gid can never
feed the name.

### 1a. Every input to the name is replication-agreed (never local re-capture)

The name's inputs are a loser `Version`'s `content_hash` and `meta`. A loser
is an element of the antichain over the candidate set; candidates come from
exactly three sources, all wire/disk-agreed, none a fresh local stat at
resolution time:

- `ops_as_candidates` (`src/oplog.rs:1259`) — reads `meta` (and content_hash)
  straight out of the `oplog` rows; an op's `meta` is the **originator's**
  captured snapshot, carried verbatim on the wire (`OpRecord.meta`) and stored
  unchanged. Every node that holds the op holds the identical bytes.
- the `remote` op being resolved (`src/oplog.rs:1354`) — the same op on the
  wire, identical on every node.
- `Version::from_row(&local_row)` (`src/oplog.rs:1363`, the coverage branch) —
  `from_row` (`src/conflict.rs:123`) copies the `files` row's stored `meta`,
  which was written by `apply_remote`/`reconcile_upsert`/`resolve_rows` from an
  op/leaf's `meta` — again the originator's snapshot, not a local re-capture.

There is no path where the resolution reads the local filesystem's current
metadata to feed the name. (The scanner's *re-capture* of local metadata
produces a NEW op with that node as originator — a different version with its
own wire-carried meta — not a different view of an existing loser. See §1c.)

Therefore, for a **given loser version**, `content_hash` and `meta` are
byte-identical on every node, so `Meta::naming_hash(&meta)` (a pure function,
`src/metadata.rs:146` — no clock, no node id, no I/O) and the resulting name
are byte-identical on every node. Which losers exist for a conflict is the
antichain/coverage-branch convergence already proven in
`docs/review-3a-conflict.md` §2 (full-vs-partial heals by dominance); this
proof is about the naming function being node-agnostic given a loser.

### 1b. mtime and uid/gid are excluded — confirmed

`naming_hash` updates the hasher with `kind, mode, rdev, symlink_target,
xattrs` and **never** touches `mtime_s`, `mtime_ns`, `uid`, `gid`
(`src/metadata.rs:146`; pinned by `metadata::tests::
naming_hash_includes_durable_excludes_skew`, which asserts mtime/uid/gid
changes leave the hash unchanged). So even the residual
`owner_policy = numeric` EPERM-skip case — where a node's *re-captured* file
shows its own daemon uid — cannot put a node-local uid into a name: uid is not
in the subset at all, and the re-capture is a separate originator op anyway.

### 1c. The sharper truth (and why excluding is still strictly safe)

Because all loser meta is replication-agreed (§1a), even the FULL `meta_hash`
naming was already node-agnostic per loser — mtime/uid/gid drive copy
**proliferation** (many near-duplicate copies when the same bytes appear under
different timestamps/owners, e.g. independent same-content writes, `touch`, or
the EPERM re-capture op), not cross-node **divergence**. Excluding them is
therefore a proliferation policy that is *strictly determinism-safe*: removing
fields from a pure, node-agnostic hash cannot introduce divergence.

**VERDICT 1: PASS.** Included fields are all replication-agreed ⇒ node-agnostic;
mtime and uid/gid are excluded and cannot reach the name. No mtime/uid
divergence is possible (and none existed even before, per §1c).

---

## Proof 2 — S1 NO-LOSS PRESERVED

**Claim:** two losers with identical bytes but a genuinely different DURABLE
metadata field (a real xattr or mode difference, not mtime) still produce
DISTINCT copies — the S1 metadata-loss hole stays closed.

`naming_hash` includes `mode` and `xattrs` (and `kind`, `rdev`,
`symlink_target`). So two losers that share `content_hash` but differ in any of
those produce different `naming_hash` values ⇒ different
`blake3(content ‖ naming_hash)` ⇒ different copy paths ⇒ both are materialized
as separate copy rows in `plan_candidates` (`src/conflict.rs:256–305`). The
collision/coalesce branch (`:269`) only fires when the names are EQUAL, i.e.
same content AND same durable subset — by definition not a durable difference;
its debug-assert now checks `Meta::naming_hash` equality (`:271`).

Pinned by `conflict::tests::durable_meta_losers_get_distinct_copies`: two
same-bytes losers differing in `mode` → two distinct copies; same for an
`xattr` value difference. And the copy ROW always stores the loser's full
`meta`, so even the coalesced cases lose no *content* — only a redundant
near-duplicate file is avoided.

### Deliberate coalescing (policy, not S1 loss)

Two losers differing ONLY in an EXCLUDED field (mtime, or uid/gid) coalesce to
one copy (`conflict::tests::mtime_only_losers_coalesce_to_one_copy`,
`uid_only_losers_coalesce_to_one_copy`). This is the intended proliferation
fix and the user's directive. Tradeoff, stated plainly: a loser differing from
another loser ONLY in ownership keeps one of the two ownership snapshots in its
copy row (the first in antichain key order — deterministic). This is a
narrowing of "preserve every distinct metadata snapshot" to "preserve every
distinct DURABLE-AND-NODE-AGNOSTIC metadata snapshot." Ownership is excluded by
design because it is the field that can skew node-to-node (residual EPERM), so
keeping it in the name would reintroduce proliferation without a node-agnostic
benefit. Content is never lost; mode/xattrs/kind/rdev/symlink differences are
never coalesced.

**VERDICT 2: PASS.** Durable differences (mode, xattrs, kind, rdev, symlink
target) still name distinct copies; the S1 hole stays closed. Only the
deliberately-excluded skew fields coalesce, and never at the cost of content.

---

## Tests (verification, not assertion)

- `metadata::tests::naming_hash_includes_durable_excludes_skew` — durable
  fields change the hash; mtime/uid/gid do not; xattr order canonicalized.
- `conflict::tests::durable_meta_losers_get_distinct_copies` — S1: mode and
  xattr differences → distinct copies (order-independent).
- `conflict::tests::mtime_only_losers_coalesce_to_one_copy`,
  `uid_only_losers_coalesce_to_one_copy` — the proliferation fix.
- `conflict::tests::plan_is_order_independent` — the plan (copy paths included)
  is identical across candidate orderings (per-conflict determinism).
- `tests/conflict_proptest.rs` — the metadata dimension (varying the durable
  `mode`) still asserts the (content, meta) no-loss oracle; name
  reconstruction switched to `Meta::naming_hash`. Run at
  `PROPTEST_CASES=20000` (release): GREEN. Its 3-node convergence asserts
  byte-identical trees INCLUDING copy rows/names — the cross-node determinism
  test.

Scope: this change + its proofs/tests only; no other conflict logic touched.
