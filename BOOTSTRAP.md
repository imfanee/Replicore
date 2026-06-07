*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore — Bootstrap Prompt

A single, self-contained build prompt. Hand this to a capable engineer or coding
agent and it can reconstruct Replicore from scratch — what to build, in what
order, under which non-negotiable invariants, and how to know each step is done.
It replaces the former per-milestone prompt pack and the in-repo agent memory.

---

## 0. What you are building

Replicore: an agent-based, eventually-consistent, **multi-master** file
replication engine for LAN and WAN. One daemon per node; nodes form a dynamic,
self-healing mesh; each node reads/writes local storage normally and the engine
propagates changes **without blocking local I/O**. Metadata replicates as a
causally-ordered operation log; file data replicates as content-addressed chunks;
divergence heals via Merkle anti-entropy; membership is dynamic and signed.

The shipped behavior is described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
Build toward that.

## 1. Tech stack (locked — raise it before substituting)

- Language: **Rust**. Async: **tokio**.
- Transport: **quinn** (QUIC, pluggable CC). Never hand-roll UDP
  reliability/congestion. Congestion control: **BBR** (Cubic is the fallback).
- Hash: **blake3**. Chunking: **fastcdc**.
- FS monitoring: **fanotify** via `libc` (FID reporting) + a periodic Merkle scan
  as the correctness backstop.
- State store: **rusqlite** (WAL).
- Membership: SWIM-style gossip + a versioned roster (no Raft).
- Serialization: **serde** + versioned binary (`bincode`/`postcard`).
- Metrics: **prometheus**. Logging: **tracing**. CLI: `replicorectl` over a Unix
  domain socket.

## 2. Non-negotiable invariants (violating any is a defect, not a style nit)

**Replication core**

1. **Causality comes from version vectors, never wall-clock time.** Wall-clock
   may only break ties between already-concurrent versions.
2. **Apply is atomic.** Stage in the destination dir → fsync → verify BLAKE3 →
   `rename(2)` → fsync parent. Never expose a partial/unverified file.
3. **Loop prevention requires BOTH** version-vector dedup AND apply-suppression
   of the engine's own fs event. One alone storms the mesh.
4. **Tombstones, not hard deletes;** GC only after all peers ack + a safety
   window. Never resurrect a deleted file via a late write.
5. **Never trust network input.** No panics on malformed/hostile peer data; bound
   every buffer; reject path escapes.
6. **The dev-only `AcceptAny` cert verifier must never ship.** Production uses
   mutual TLS with a pinned peer-cert allowlist.

**Cluster membership & control plane**

7. **Intent config is human-owned; the roster is agent-owned.** The daemon never
   writes the intent file (`replicore.toml`); learned membership lives in the
   separate agent-managed roster.
8. **Announcement is not authorization.** A peer enters the data path only after
   its cert validates against the trust anchor; membership changes are
   admin-signed. Being vouched-for by a peer is not trust.
9. **Config reload is atomic.** Invalid candidate → reject, running config
   untouched. Partial application is prohibited.
10. **Membership converges, never diverges.** The roster is epoch-versioned;
    concurrent add/remove from different nodes converge deterministically. The
    tie-break hashes canonical bytes, never the signature.
11. **Join uses a version-vector frontier.** Bulk bootstrap + parallel live ops
    must compose with no lost or double-applied ops across the frontier.

Any rule that cannot afford to be "mostly followed" must also be enforced in CI /
pre-commit — do not rely on prose alone.

## 3. Conventions

- Errors: `thiserror` for library enums, `anyhow` only at binary boundaries.
- **No `unwrap`/`expect`/`panic!`** in non-test code except on a documented,
  locally-proven invariant (with a `// SAFETY:`-style justification).
- Prefer message-passing over shared `Mutex` state. `unsafe` needs a `// SAFETY:`
  comment and review.
- Every fallible I/O path handles partial writes, short reads, disconnects.
- Correctness-critical logic (version vectors, conflict rules, reconcile, apply,
  roster convergence, join frontier) MUST have **property-based tests**.

## 4. Build order (one milestone at a time)

Build, test on the rig, and review each milestone before starting the next.

**M0 — Spike.** Prove fanotify + QUIC + atomic apply compose: one-directional
file replication over QUIC. Throwaway scaffolding for the real core.

**M1 — Bidirectional correctness core.** Op-log, version vectors,
apply-suppression, mutual TLS with pinned certs, the local-change pipeline
(ingest + authoritative scanner + watcher), atomic suppressed apply with
crash-window coverage. Convergence property tests; poison-op quarantine.

**M2 — Mesh + self-healing.** FastCDC chunking + persistent content-addressed
store; multi-source chunk fetch; streamed atomic assembly; Merkle anti-entropy
with the reconcile gate (never apply a peer's live ops before completing an
anti-entropy session with it); peer registries + jittered reconnect; `/healthz`;
transfer bounds + backpressure. Protocol v2 (flag-day).

**M2.5 — Cluster membership + management plane.** Admin trust primitives +
`gen-admin-key`; admin-signed, epoch-versioned membership with deterministic
convergence; join via a version-vector frontier (protocol v3); intent/roster
config split; per-handshake dynamic TLS allowlist; SWIM roster gossip; the
`replicorectl` control plane over a UDS. M2.5 precedes M3 deliberately, so
hardening hardens a *dynamic* cluster.

**M3 — Production hardening.** Deterministic confluent conflict resolution
(maximal antichain; node-agnostic conflict copies); file identity + renames; full
POSIX metadata fidelity (protocol v4); fanotify FID watcher; QoS (token buckets +
priority lanes + schedule); Prometheus metrics; free-space guard; BBR. Then a
long-duration soak.

## 5. The two highest-risk subsystems — review by hand, do not trust tests alone

1. **Version vectors + apply-suppression (M1)** — the causality and loop-control
   core. Plausible-looking code here causes silent corruption or mesh storms.
2. **Join frontier (M2.5)** — "keep syncing live writes while initial sync runs"
   loses or double-applies writes at the boundary if coded carelessly, and won't
   show up in a casual demo.

For these and for the M3 conflict-decision and metadata-apply paths: design first,
get the design reviewed, then implement.

## 6. Definition of Done (per milestone)

Implemented + `cargo clippy --all-targets -- -D warnings` clean + unit/property
tests pass + the milestone integration test passes on the emulated-WAN rig +
the exit criterion demonstrated. Commit in logical units. When unsure about a
correctness decision, **stop and ask** rather than guess.

## 7. Commands

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --all

# emulated-WAN rig (netns + tc netem):
sudo modprobe sch_netem
sudo scripts/wan-testbed.sh up | status | down
```

## 8. Deployment constraint to design for (NFS-fronted nodes)

If nodes NFS-export to LAN app servers: the watcher is **best-effort** for writes
arriving via `nfsd`; the **rescan is authoritative** for NFS-exported shares. Do
not weaken the rescan path on the assumption fanotify catches everything. See
[docs/DEPLOYMENT-NFS-RUNBOOK.md](docs/DEPLOYMENT-NFS-RUNBOOK.md).
