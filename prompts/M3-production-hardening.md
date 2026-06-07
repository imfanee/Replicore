# M3 — Production hardening (authoritative, post-M2.5 reconciliation)

> This file supersedes the M0-era draft: the operator control plane,
> `replicorectl`, config validate/diff/reload, SO_PEERCRED auth, and the
> conflicts counter were all delivered in M2.5 — M3 wires real behavior behind
> the existing surfaces and does NOT rebuild them.

## Goal
Make Replicore trustworthy with real production data: deterministic conflict
resolution with **zero silent loss**, full POSIX metadata fidelity, real QoS,
Prometheus metrics, free-space safety, and a fault-injection + soak suite that
proves the RSD acceptance criteria (§I.5).

## In scope
- FR-303/304/305: deterministic conflict winner + conflict copies (no silent
  loss); explicit rules for delete-vs-modify, rename-vs-modify,
  rename-vs-rename, create-vs-create, dir-delete-vs-child-create.
- FR-205: stable per-file identity (UUID at create); identity-preserving
  renames (identity-lite per user decision; redirect is SEAM(M4)).
- FR-106 / FR-804: full metadata fidelity — xattrs (⊃ POSIX ACLs), uid/gid
  (numeric-preserve policy, mesh-uniform), mtime, symlinks (never followed),
  FIFO/device nodes, sparse holes; metadata applied only after content.
  Hardlinks-as-links and directory metadata are explicit SEAMs (see
  metadata.rs header for the storm-free hardlink design).
- FR-102/103: fanotify FID watcher (`FAN_REPORT_DFID_NAME`); baseline scan
  stays authoritative.
- FR-1101/1103/1104/1107: Prometheus behind the existing `/healthz` listener;
  token-bucket bandwidth limits (per-peer + global, time-of-day schedule,
  priority lanes) behind the existing `bandwidth` stub; free-space guard.
- FR-1004 per-share encryption: DEFERRED (user decision).

## Mandated design (fixed)
1. Resolution + conflict-copy creation route through the re-validated
   committing transaction (`resolve_rows`, the `apply_remote` discipline) —
   NO new write path to `files`/disk (`tests/write_path_gate.rs` gates it).
2. Deterministic convergence: winner = max(kind_rank, content_hash,
   meta_hash) over the maximal ANTICHAIN of the path's op history (pairwise
   contests are provably non-confluent — see conflict.rs header). Copy names
   are a pure function of losing content; copy VVs are synthetic
   path-derived vectors. No wall-clock, no node-local input, anywhere.
3. No silent loss: losers are preserved as copies with their content fetched.
4. Metadata is its own correctness axis: canonical Meta + meta_hash in the
   winner key AND the v4 Merkle leaf; the no-storm law (metadata.rs header).
5. QoS is token-bucket per-peer AND global; QUIC pacing is not a substitute.
   Free-space guard refuses to fill the disk.
6. CI gates: `tests/conflict_proptest.rs` (PROPTEST_CASES=20000 for deep
   runs), `tests/conflict_race.rs`, `tests/write_path_gate.rs`,
   `tests/metadata_fidelity.rs` are part of the default `cargo test`.

## Exit criteria — RSD §I.5, demonstrated on the rig
1. 3-node mesh: all op types with full metadata fidelity, no loops.
2. `kill -9` during transfer/apply → no corruption, correct resume.
3. Multi-minute partition with concurrent writes both sides → heals with
   deterministic conflict copies, zero loss, byte-identical trees.
4. Reference WAN (150ms/1%): NFR-P4 (<15s P95 small file), NFR-P6 (≥80%
   utilization), bandwidth cap honored (measured).
5. Hours of clock skew on one node → ordering and resolution unchanged.
6. One-week soak: no memory growth, no lag drift, GC correct, copy count
   stable.
