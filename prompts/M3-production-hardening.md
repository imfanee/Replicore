# M3 — Production hardening

> Paste into a fresh Claude Code session at the repo root (`/clear` first). Plan Mode.
> This is the largest milestone and the dominant cost. Consider splitting it into
> sub-sessions (3a conflicts+metadata, 3b ops/QoS/CLI, 3c test suite) if the
> context window gets tight.

## Read first
- `docs/RSD.md` §3.1, §3.3, §3.10, §3.11, §4 (NFRs), §5 (acceptance), §II.8 (tests)
- `docs/design-guide.md` §2 (metadata fidelity), §4 (conflict cases), §11, §16

## Goal
Make Replicore trustworthy with real production data: correct conflict
resolution with no silent loss, full POSIX metadata fidelity, bandwidth/QoS
control, observability, an admin interface, and a fault-injection + soak test
suite that proves the RSD acceptance criteria.

## In scope (RSD requirements)
- FR-303/304/305: deterministic conflict winner + **conflict copies** (no silent
  loss); explicit rules for delete-vs-modify, rename-vs-modify, rename-vs-rename,
  create-vs-create, dir-delete-vs-child-create; conflict counter + per-conflict
  log. (This is where the M1 "concurrent → log-and-skip" TODO is resolved.)
- FR-205: stable per-file identity (UUID at create) so renames are
  identity-preserving, not delete+create.
- FR-106 / FR-804: full metadata fidelity — xattrs, POSIX ACLs, hardlinks,
  symlinks, FIFO/device/socket, sparse-file holes; uid/gid mapping policy;
  metadata applied only after content is in place.
- FR-102/103: upgrade the watcher to fanotify **FID reporting**
  (`FAN_REPORT_DFID_NAME`) for create/delete/rename; full baseline scan at start.
- FR-1003/1004: admin authn; optional per-share encryption key.
- FR-1101/1103/1104/1105/1107: Prometheus metrics (lag, queue depth, bytes,
  cache hit, conflicts, reconcile events, apply errors); bandwidth limits
  (per-peer + global) with time-of-day schedule; priority lanes (control/small
  assets ahead of bulk); admin CLI/API (status, peers, pause/resume,
  force-resync, bandwidth); free-space guard with reserve.
- FR-1202/1203: config validation; reload without dropping in-flight transfers.

## Out of scope (Phase 4)
Distributed write-locking, gossip membership, web UI, object-store back-ends.

## Mandated design (do not improvise)
- **No conflict ever loses data silently.** The loser becomes a
  `name.sync-conflict-<node>-<ts>.<ext>` copy; emit a metric and a log line.
- **Track file identity, not just path.** Rename = same UUID, new path.
- **Capturing all xattrs captures ACLs** (`system.posix_acl_access/default`);
  apply with `lsetxattr` after content, preserving order; document the uid/gid
  mapping policy explicitly (numeric-preserve vs name-map) and make it config.
- **Non-negotiable rules go in CI**, not just prose: a corruption/data-loss test
  and the convergence property test must gate merges.
- Bandwidth limiter: token-bucket per-peer and global; QUIC pacing is not a
  substitute (a UDP transport will otherwise starve other apps on the link).

## Deliverables
- `conflict` module (rules + copies + counter), file-identity in `state`,
  `metadata` module (xattr/ACL/hardlink/symlink/sparse capture+apply), watcher
  upgrade to FID, `metrics`, `qos` (token buckets + schedule + priority lanes),
  `admin` (CLI/API), `config` (validate + reload), free-space guard.
- Full test suite (see below). CI workflow running unit+property+integration;
  nightly running fault-injection+soak.

## Exit criteria — the RSD acceptance criteria (§I.5), demonstrated on the rig
1. 3-node mesh: all op types replicate with **full metadata fidelity** (verify
   xattr/ACL/hardlink/symlink/sparse round-trip), no loops.
2. `kill -9` during transfer and during apply → no corruption, no partial files,
   correct resume.
3. Multi-minute partition with **concurrent writes on both sides** → heals with
   deterministic conflict copies and **zero data loss**.
4. Reference WAN (`tc netem` 150ms / 1% loss): meets NFR-P4 (small file < 15s
   P95) and NFR-P6 (>=80% link utilization at 1% loss).
5. Clock skew of hours on one node → ordering still correct.
6. One-week soak under synthetic IVR traffic → no memory growth, no lag drift,
   correct tombstone GC.

## Reviewer checklist (human gate — this is the most important review of all)
- [ ] Walk EVERY conflict pair in FR-304 and confirm the rule + that the loser is
      preserved. Adversarially: can any ordering of two concurrent ops drop data?
- [ ] xattr/ACL round-trip is byte-exact, including default ACLs on directories.
- [ ] uid/gid mapping policy is correct and documented; no accidental
      privilege/ownership change on apply.
- [ ] Sparse files stay sparse (no hole inflation); hardlinks stay linked (not
      duplicated); symlinks not followed.
- [ ] FID watcher correctly handles create/delete/rename including the
      mkdir-then-write race and rename across the share boundary.
- [ ] Bandwidth cap is actually honored on a shaped link (measure, don't trust).
- [ ] Free-space guard refuses to fill the disk; verify near-full behavior.
- [ ] The corruption test and convergence property test gate CI (try a PR that
      breaks them and confirm the merge is blocked).
- [ ] Config reload does not drop in-flight transfers (verify mid-transfer).
- [ ] No `unwrap`/`panic!` reachable from network input remains.
