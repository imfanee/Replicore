# Review 3c — metadata apply path (the deferred M3 review diff)

Scope: `src/metadata.rs` (`apply_meta` :242, `capture` :124,
`create_special` :345), call sites in `src/apply.rs` (`apply_write` :127,
`apply_assembled` :210, `apply_rename` :286, `apply_symlink` :336,
`apply_special` :376, `apply_meta_only` :440). Analysis of the code at
`cfd3754`; no changes made.

---

## ⚠ FINDING (reported, deliberately NOT fixed in this task)

**The no-storm law is conditionally violated: two or more unprivileged
daemons with different uids under `owner_policy = "numeric"` produce an
unbounded op ping-pong.**

Trace (every step cited):

1. Node B (daemon uid 1000, no CAP_CHOWN) applies an op whose meta carries
   `uid: 2000`. `apply_meta` step 2 hits EPERM and skips ownership whole
   (`metadata.rs:288–296`) — correct in isolation. B's **row** stores the
   op's meta (`uid 2000`); B's **disk** file is owned by uid 1000.
2. B's scanner re-captures under `Numeric` → `(st.uid, st.gid) = (1000, …)`
   (`metadata.rs:146–149`). The append no-op filter compares
   `Meta::hash_of(row) == Meta::hash_of(captured)` (`oplog.rs::append_local`,
   the Write arm) — they differ → B emits a corrective meta-only op with
   `uid 1000`, VV bumped.
3. With **one** unprivileged node this is bounded: B's own row now matches
   B's disk (quiet); a privileged peer chowns to 1000 and also quiesces.
   One corrective op total — graceful.
4. With a **second** unprivileged node C (daemon uid 2000): C applies B's
   `uid 1000` op, EPERM-skips, disk stays 2000, re-captures `uid 2000` ≠
   row's `1000` → emits. B applies, skips, re-captures `1000` ≠ `2000` →
   emits. **Unbounded alternation**, one op per side per scan interval,
   VVs growing forever.

Mitigating context: `owner_policy` is documented as requiring CAP_CHOWN
mesh-wide under `numeric` (config doc at `config.rs`, the no-storm section
of `metadata.rs:26–45`), and `skip` exists precisely for unprivileged
deployments (captures the 0/0 sentinel — storm-free, verified below). The
EPERM skip was designed as an *edge* degradation. But the failure mode of
the misconfiguration is a **silent permanent op storm** (visible only as
`meta_owner_skips_total` and op-rate growth), not a refusal — which is the
kind of "mostly followed" posture CLAUDE.md says to reject. The soak's
lag/oplog monitors would catch it, prose wouldn't.

**STATUS: FIXED** — the daemon now refuses to start under
`owner_policy = "numeric"` without CAP_CHOWN (`metadata::can_chown` probe +
the boot gate in `main.rs`), which eliminates the storm-producing
configuration class. Residual: a privileged daemon facing PER-PATH
squashing (e.g. one NFS export with root-squash) can still EPERM-skip on
those paths and, paired with a second such daemon of a different uid,
ping-pong on the squashed subtree — surfaced by
`replicore_meta_owner_skips_total` and op-rate growth; capture-side
pinning remains the follow-up if that corner ever matters in practice.

Everything else below **passes**.

---

## 1. Apply order is correct, and mtime is genuinely last on every path

`apply_meta` (`metadata.rs:242`) runs, in order:

1. **xattrs** (`:246–276`): `lsetxattr` in canonical (capture-sorted) order;
   POSIX ACL entries (`system.posix_acl_*`) therefore land **before** the
   chmod below, so the final mode settles the ACL mask deterministically.
   Per-xattr ENOTSUP/EPERM degrade to a warning (value preserved in the
   row; the storm analysis for xattrs mirrors ownership — but unsupported
   xattrs FAIL CAPTURE-SIDE on the same filesystem too (`read_xattrs`
   returns the empty set on ENOTSUP, `:191`), so capture and apply degrade
   *together* and re-capture matches: no storm).
2. **ownership** (`:278–300`): `lchown` BEFORE mode — deliberately, because
   chown clears setuid/setgid bits; the chmod in step 3 then re-asserts the
   full captured mode including those bits. The comment at `:278` states
   it; the order in code matches. EPERM skips uid+gid **as a unit**
   (`owner_skipped`, never a half-applied uid-without-gid), counted in
   `OWNER_SKIPS` (`:281, :292`) → `replicore_meta_owner_skips_total`.
3. **mode** (`:303–311`): `chmod(mode & 0o7777)` — skipped for symlinks
   (Linux ignores symlink modes; a path chmod would follow the link).
4. **mtime LAST** (`:314–337`): `utimensat(AT_SYMLINK_NOFOLLOW)`, atime
   `UTIME_OMIT`. Nothing in `apply_meta` runs after it.

Call-site audit — `apply_meta` is the **final mutation** before publish on
every path:

| Path | Sequence | mtime last? |
|---|---|---|
| `apply_write` (`apply.rs:111–135`) | create→write→fsync→chmod(arg)→verify→**apply_meta**→rename | ✓ (rename changes ctime only) |
| `apply_assembled` (`:189–216`) | create→assemble→fsync→chmod(arg)→verify→**apply_meta**→rename | ✓ |
| `apply_rename` (`:277–292`) | fs rename→`set_permissions`→**apply_meta** | ✓ — the pre-meta `set_permissions` is redundant-but-harmless (apply_meta's chmod+mtime have the last word) |
| `apply_symlink` (`:332–341`) | symlink(tmp)→**apply_meta**→rename | ✓ — step 3 skipped (kind == Symlink), `utimensat` no-follow touches the LINK's mtime |
| `apply_special` (`:372–381`) | `create_special` (mkfifo/mknod with mode, `metadata.rs:345`)→**apply_meta**→rename | ✓ |
| `apply_meta_only` (`:430–442`) | suppression→**apply_meta** on the live dest | ✓ |

The FR-804 framing holds throughout: content (or node creation) first,
metadata on the staged temp, publish rename last — metadata travels with
the inode; no observer sees content with stale metadata or vice versa.

## 2. The no-storm law, field by field

Law: every field `apply_meta` writes must be a field `capture`
(`metadata.rs:124`) reads back identically on the same node, or the scanner
re-emits forever. Trace:

| Field | Applied via | Re-captured via | Identical? |
|---|---|---|---|
| `mode` | chmod `mode & 0o7777` | `st.mode() & 0o7777` | ✓ verbatim |
| `mtime_s/ns` | utimensat exact ns | `st.mtime()/mtime_nsec()` | ✓ (Linux stores ns; same fs reads back what was set) |
| `xattrs` | lsetxattr, sorted | `read_xattrs` + sort (`:150–151`) | ✓ canonical both sides; per-fs unsupported namespaces degrade on BOTH sides (§1.1) |
| `symlink_target` | created from raw bytes | `read_link` raw bytes | ✓ never followed either side |
| `rdev` | mknod arg | `st.rdev()` | ✓ (device-capable hosts only; mknod EPERM degrades to the caller's permanent-error path, and capture of a node that was never created can't mismatch — the file is absent, the scanner's delete pass owns it) |
| `kind` | dispatch (`apply_version`) | file-type probe | ✓ |
| `uid/gid` under `skip` | never applied; captured as 0/0 sentinel (`:148`) | 0/0 again | ✓ storm-free — the safe unprivileged config |
| `uid/gid` under `numeric`, CAP_CHOWN present | lchown verbatim | `st.uid()/gid()` | ✓ |
| `uid/gid` under `numeric`, EPERM | **skipped** | **real (different) uid** | ✗ — bounded with ≤1 unprivileged node; **unbounded ping-pong with ≥2 differing-uid unprivileged nodes — the FINDING above** |

Supporting invariants confirmed: `capture` is the single canonicalization
point (xattr sort at `:150–151`), `Meta::hash_of` hashes the canonical
bincode (`:108–118`), and nothing node-local (dev/ino, hostnames, clocks)
appears in any `Meta` field — the hardlink-grouping exclusion documented at
`metadata.rs:35–39` is the designed-out instance of this whole failure
class.

## 3. Reviewer-checklist cross-reference

- xattr/ACL round-trip byte-exact: `tests/metadata_fidelity.rs::
  regular_file_meta_round_trips_through_the_apply_path` (hash equality of
  applied vs re-captured meta). File-level ACLs ride as xattrs; **default
  ACLs on directories remain the documented dir-meta SEAM** (directories
  carry no row), unchanged by this review.
- Ownership never half-applied, policy documented: §1 step 2; config doc;
  mesh-uniform requirement in `metadata.rs:31–34`. The FINDING qualifies
  the EPERM degradation, not the design intent.
- Sparse stays sparse / symlinks never followed: pinned by
  `metadata_fidelity` tests (out of this review's strict scope but
  adjacent and green).
- Meta-only change emits an op: `oplog.rs::append_local` no-op filter
  compares content **and** meta hash; `src/ingest.rs` test
  `meta_only_change_emits_an_op` pins it.
