# M1 — MVP: two-node bidirectional sync (the correctness core)

> Paste this into a Claude Code session at the repo root. Start in Plan Mode.

## Read first
- `docs/RSD.md` §3.2, §3.3, §3.8, §3.9 (op-log, causality, recovery, loops)
- `docs/design-guide.md` §3, §4, §9 (op-log schema, version vectors, loop prevention)
- The existing M0 spike in `src/` (watcher, QUIC transport, atomic apply)

## Goal
Turn the M0 one-way file copier into the **bidirectional correctness core** of
Replicore: two nodes, each watching and writing its own share, exchanging an
ordered operation log, applying peers' ops idempotently and atomically, with no
replication loops. Operate under **partitioned write ownership** (each node owns
a distinct sub-namespace) so conflicts cannot occur yet — conflict *resolution*
is M3; conflict *detection* via version vectors is in scope now.

## In scope (RSD requirements)
- FR-201/202: durable, WAL-backed op-log; ops carry id, origin, type, path(s),
  metadata snapshot, content hash, version vector.
- FR-203: materialized current-state index per path.
- FR-204: deletes as tombstones (GC deferred; just retain correctly).
- FR-301/302: per-file version vectors; apply/ignore/concurrent decision.
- FR-401/404: transfer only data the peer lacks (whole-file by hash is fine for
  M1; chunking is M2); resume on reconnect.
- FR-501/504: keep QUIC; add a control stream carrying op-log records, separate
  from data streams.
- FR-601: static peer config.
- FR-801/802/803: durable op-log, idempotent apply, atomic staged apply.
- FR-901/902: version-vector dedup AND apply-suppression.
- FR-1001/1002: replace the `AcceptAny` verifier with mutual TLS + pinned peer
  certs.
- FR-1201: declarative config file (shares, peers, certs).

## Out of scope (do NOT build these yet)
Content-defined chunking, multi-source fetch, Merkle anti-entropy, mesh > 2
nodes, conflict copies/resolution rules, full metadata fidelity (xattr/ACL/
hardlink/sparse), QoS, metrics, admin CLI. Note where seams for them go; don't
implement.

## Mandated design (do not improvise these)
- **Version vectors are per file**, map `node_id -> u64`. Local write increments
  this node's counter. Apply iff remote VV strictly dominates local; ignore if
  local dominates; mark concurrent otherwise (M1 may log-and-skip concurrent
  with a TODO for M3 — but it must *detect* it correctly).
- **Op-log is append-only** with a per-node monotonic seq; a peer cursor records
  `last_acked_seq`. Re-applied ops are no-ops (idempotency table keyed by op id).
- **Apply-suppression**: before writing a file due to a remote op, record
  `(path, expected_hash)`; the watcher drops the matching event. Combine with VV
  dedup; neither alone is sufficient.
- **Two QUIC stream types**: one long-lived control stream (op-log records +
  acks) per connection; ephemeral uni-streams for file bytes.
- **mTLS**: each node has a cert+key; peers are accepted only if their cert
  fingerprint is in the configured allowlist. Delete `AcceptAny`.
- Keep the atomic-apply path from M0 (stage→fsync→verify→rename→fsync dir).

## Deliverables
- `oplog` module (schema + append + cursor + idempotency), `vv` module (version
  vectors + dominance), `state` module (materialized index + tombstones),
  reworked `net` (control + data streams, mTLS), `apply` (idempotent + suppress),
  `config` (declarative file).
- Unit tests + **property test**: random op sequences applied in different
  orders on two simulated nodes converge to identical state.
- An integration test runnable on `scripts/wan-testbed.sh`.

## Exit criteria (must be demonstrated)
1. Two nodes, partitioned namespaces, bidirectional: a create/modify/delete on
   either node appears correctly on the other.
2. No loops/storms (observe steady state after a burst; op counts quiesce).
3. `kill -9` a node mid-run; on restart it resumes from `last_acked_seq` with no
   duplication and no corruption.
4. Version-vector property test passes (convergence under reordering).
5. mTLS: a peer with an unlisted cert is rejected.
6. `cargo clippy --all-targets -- -D warnings` clean.

## Reviewer checklist (human gate — verify by reading, not by trusting tests)
- [ ] VV dominance logic is correct for the concurrent case (neither dominates),
      not just the easy dominate/dominated cases. Check the tie-break does NOT
      decide ordering.
- [ ] No wall-clock comparison anywhere in the apply-decision path.
- [ ] Apply-suppression cannot leak: confirm an applied remote write does not
      generate an outbound op (trace one end to end).
- [ ] Idempotency: re-delivering the same op id is a true no-op (no double write,
      no VV double-increment).
- [ ] Tombstone retained on delete; a stale write older than the tombstone does
      NOT resurrect the file.
- [ ] Atomic apply unchanged: no code path writes directly to the destination.
- [ ] Crash recovery: `last_acked_seq` is persisted before the ack is sent, not
      after (otherwise a crash loses ops).
- [ ] `AcceptAny` is gone from the tree.
