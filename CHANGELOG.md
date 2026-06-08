*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Changelog

Replicore is developed in milestones. Each milestone is independently tested on
the emulated-WAN rig before the next begins. The wire protocol is a flag-day
version — a mesh runs one protocol version end to end.

## M3 — Production hardening (complete)

Hardens a dynamic cluster for production.

- **Conflict resolution** — deterministic, confluent winner via the maximal
  antichain (`side_key = (kind_rank, content_hash, meta_hash)`); every loser
  preserved as a node-agnostic conflict copy. Resolution commits through a
  re-validated store transaction (no third write path to files). All concurrent
  sites resolve through the committing path.
- **File identity & renames** — stable per-file UUID; identity-preserving rename
  ops.
- **Metadata fidelity** — full POSIX metadata (mode, ownership, mtime, xattrs,
  symlink/dev) captured, replicated, and applied in a safe order; v4 Merkle leaf
  formula; protocol **v4** (ALPN `replicore/4`).
- **fanotify FID watcher** — low-latency create/delete/rename/attrib detection,
  backed by the authoritative rescan.
- **QoS & production guards** — debt-model token buckets (global ∩ per-peer) with
  priority lanes and a time-of-day schedule; Prometheus `/metrics`; free-space
  reserve guard.
- **BBR congestion control** — replaces Cubic for throughput on lossy WANs.
- **Acceptance** — exit-criteria fault-injection suite, partial-history
  resolution test, and a self-deciding long-duration soak harness.

### Post-M3 fixes

- Conflict copy naming derives from a stable, node-agnostic metadata subset
  (excludes mtime/uid/gid skew) while the copy row retains full metadata —
  proven node-agnostic and S1-no-loss-preserving.
- Severity-1 metadata-only conflict loss closed (copy only skipped on full
  content+durable-metadata equality).
- `owner_policy = numeric` without `CAP_CHOWN` now refuses to boot (was an EPERM
  storm); membership removal/registration race and roster-persist hardening;
  poison dir-op quarantine.
- Partial-manifest crash residue now reads as absent (re-fetchable) and heals on
  re-put, instead of wedging the node — `put_manifest` is atomic.

## M2.5 — Cluster membership + management plane (complete)

Dynamic membership so M3 hardens a live, changing cluster.

- Admin trust primitives + `gen-admin-key`; admin-signed membership changes.
- Epoch-versioned LWW membership register with deterministic convergence.
- Join via a version-vector frontier (protocol **v3**) — bulk bootstrap composes
  with live ops, no lost/double-applied ops.
- Intent/roster config split — the daemon never writes the human-owned
  `replicore.toml`; learned membership lives in the daemon-owned roster.
- Per-handshake dynamic TLS allowlist; lean SWIM roster gossip.
- Operator control plane over a Unix domain socket + `replicorectl`.
- CI gate: the daemon never writes the intent file.

## M2 — Mesh + self-healing (complete)

- Content-defined chunking (FastCDC) + persistent content-addressed store.
- Multi-source chunk fetch; streamed atomic assembly from the CAS.
- Merkle anti-entropy (tree, pull sessions, the reconcile gate).
- Peer registries + full-jitter reconnect backoff; engine-wide transfer bound and
  backpressure.
- `/healthz` endpoint; stats counters.
- Protocol **v2** (flag-day). Self-healing CAS on bit-rot; hostile-input bounds.

## M1 — Bidirectional correctness core (complete)

- Version vectors + apply-suppression (causality and loop control).
- mTLS with pinned peer certificates; subscribe-model QUIC engine.
- Local-change pipeline: ingest, authoritative scanner, watcher.
- Atomic suppressed apply with crash-window coverage.
- Convergence property tests; poison-op quarantine; ack-frontier safety.

## M0 — Spike (complete, superseded)

Proof that fanotify + QUIC + atomic apply compose: one-directional file
replication over QUIC. Superseded by the M1+ correctness core.
