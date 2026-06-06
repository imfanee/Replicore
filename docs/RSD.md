# Replicore — Requirements Specification Document & Development Plan

| | |
|---|---|
| **Product** | Replicore — multipoint-to-multipoint file replication engine |
| **Document** | Requirements Specification Document (RSD) + Development Plan |
| **Version** | 1.0 (Draft) |
| **Status** | For review |
| **Date** | 2026-06-03 |
| **Audience** | Engineering, ops, project lead |

### Revision history

| Version | Date | Author | Notes |
|---|---|---|---|
| 0.1 | 2026-06-03 | — | Initial architecture (design guide) |
| 1.0 | 2026-06-03 | — | First full RSD + development plan |

---

# Part I — Requirements Specification Document

## 1. Introduction

### 1.1 Purpose
This document specifies the functional and non-functional requirements for
**Replicore**, an agent-based, eventually-consistent, multi-master file
replication engine for LAN and WAN. It is the authoritative requirements
baseline against which Replicore is built, tested, and accepted.

### 1.2 Product summary
Replicore runs a daemon (**agent**) on each participating node. Agents form a
mesh. Each node reads and writes its local storage normally; Replicore observes
local changes, replicates them to peers, and applies peers' changes locally,
without blocking local I/O. It separates a small, causally-ordered **metadata
plane** (an operation log) from a large, content-addressed **data plane** (file
chunks), and heals divergence through periodic anti-entropy.

### 1.3 Primary use case
A distributed IVR / FreeSWITCH storage tier across multiple datacenters, where
each site predominantly writes its own namespace (write-once call recordings,
voicemail, fax) and shared assets (prompts, grammars, TTS cache) are
read-mostly. Sites are interconnected over a routable VPN.

### 1.4 Scope

**In scope (v1):** POSIX filesystem replication on Linux; full metadata fidelity
(permissions, ownership, mtime, xattrs, ACLs, hardlinks, symlinks, special and
sparse files); multi-master eventual consistency with conflict detection;
content-addressed delta transfer; QUIC transport with WAN performance; mesh
topology with static discovery; anti-entropy reconciliation; crash recovery;
mTLS security; metrics, QoS, and an admin CLI/API.

**Out of scope (v1):** Windows/macOS agents; block-level replication; synchronous
/ strongly-consistent modes; a graphical management console; cloud object-store
back-ends; distributed write-locking. These are candidate future work (Phase 4+).

### 1.5 Definitions and glossary

| Term | Meaning |
|---|---|
| Agent | The Replicore daemon running on a node. |
| Share | A configured directory tree replicated among a set of peers. |
| Op / operation | An immutable record of one local filesystem mutation. |
| Op-log | The append-only, ordered journal of operations for a node. |
| Version vector (VV) | Per-file causal clock `{node_id: counter}` used for conflict detection. |
| Manifest | Ordered list of content-chunk hashes describing a file. |
| Chunk | A content-defined, hash-addressed slice of file data. |
| Anti-entropy | Merkle-tree reconciliation that heals divergence. |
| Tombstone | A retained deletion marker preventing resurrection. |
| Apply-suppression | Mechanism that stops a locally-applied remote op from re-emitting. |
| RPO/RTO | Recovery point/time objective. |

### 1.6 References
- Replicore Architecture & Build Guide (companion design document).
- QUIC (RFC 9000), TLS 1.3 (RFC 8446), BBR congestion control.

---

## 2. Overall description

### 2.1 System context
Each node hosts: the local filesystem (source of truth for that node's writes),
the Replicore agent, and a control/admin interface. Agents communicate
peer-to-peer over QUIC. No central server is in the data path; an optional
coordinator may assist discovery only.

### 2.2 Stakeholders
- **Operators**: deploy, configure, monitor, and recover the system.
- **Consuming applications** (FreeSWITCH, IVR services): read/write the shares,
  oblivious to replication.
- **Developers/maintainers**: build and evolve Replicore.

### 2.3 Assumptions
- Linux kernel ≥ 5.9 on all nodes (for `fanotify` FID reporting).
- Inter-site network is routable (e.g., over the existing VPN); inter-agent
  direct addressing is available.
- Clocks are loosely synchronized (NTP) but not trusted for correctness.
- Write ownership is partitionable by namespace for the primary use case.

### 2.4 Constraints
- The agent requires `CAP_SYS_ADMIN` for whole-mount fanotify monitoring.
- Local I/O performance must not regress measurably due to monitoring.
- All cross-node traffic is encrypted and mutually authenticated.

### 2.5 Operating modes
- **Steady state**: real-time event-driven replication.
- **Catch-up**: bounded replay of backlog after downtime/partition.
- **Reconcile**: full Merkle anti-entropy on startup, reconnect, and on a timer.

---

## 3. Functional requirements

Priority key: **M** = Must (v1), **S** = Should, **C** = Could/later. "Phase"
references the development plan (Part II §5).

### 3.1 Change detection (FR-1xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-101 | The agent **shall** detect local create, modify, delete, rename/move, permission, ownership, and xattr/ACL changes within a configured share in real time. | M | 0–1 |
| FR-102 | The agent **shall** monitor an entire mount efficiently using fanotify FID reporting, without one watch per directory. | M | 1 |
| FR-103 | The agent **shall** perform a full baseline scan of each share at startup before relying on the real-time stream. | M | 1 |
| FR-104 | On event-queue overflow or detected gaps, the agent **shall** trigger a targeted rescan rather than silently dropping changes. | M | 2 |
| FR-105 | The agent **shall** coalesce rapid successive writes to the same path using a quiescence timer before emitting a write operation. | M | 1 |
| FR-106 | The agent **shall** capture and reproduce extended attributes and POSIX ACLs, hardlinks, symlinks, FIFO/device/socket nodes, and sparse-file holes. | M | 3 |
| FR-107 | The agent **shall** apply a configurable include/exclude filter (globs) per share. | S | 2 |

### 3.2 Operation log and state (FR-2xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-201 | The agent **shall** record every local mutation as an immutable, monotonically sequenced operation in a crash-safe, write-ahead-logged store. | M | 1 |
| FR-202 | Each operation **shall** carry a globally unique id, origin node id, type, path(s), metadata snapshot, content hash/manifest reference, and version vector. | M | 1 |
| FR-203 | The agent **shall** maintain a materialized current-state index per path including a per-subtree hash for reconciliation. | M | 2 |
| FR-204 | Deletions **shall** be recorded as tombstones retained until all peers acknowledge, plus a safety window, before garbage collection. | M | 2 |
| FR-205 | The agent **shall** assign each file a stable identity (UUID) at creation so renames are tracked as identity-preserving moves. | S | 3 |

### 3.3 Causality and conflict handling (FR-3xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-301 | The agent **shall** use per-file version vectors to determine causal ordering and **shall not** rely on wall-clock time for correctness. | M | 1 |
| FR-302 | On receiving a remote version that causally dominates the local version, the agent **shall** apply it; if dominated, ignore; if concurrent, treat as a conflict. | M | 1 |
| FR-303 | On conflict, the agent **shall** select a deterministic winner and **shall** preserve the losing version as a conflict copy; no write is silently discarded. | M | 3 |
| FR-304 | The agent **shall** apply explicit, documented resolution rules for delete-vs-modify, rename-vs-modify, rename-vs-rename, create-vs-create, and dir-delete-vs-child-create cases. | M | 3 |
| FR-305 | The agent **shall** expose a conflict counter and per-conflict log entry. | M | 3 |

### 3.4 Content transfer (FR-4xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-401 | The agent **shall** transfer only data the receiving peer lacks, identified by content hash. | M | 1 |
| FR-402 | The agent **shall** chunk files using content-defined chunking and hash chunks with a cryptographic hash, enabling deduplication. | S | 2 |
| FR-403 | A receiver **shall** fetch missing chunks in parallel from any peer advertising them, and **shall** verify each chunk against its hash on receipt. | S | 2 |
| FR-404 | Interrupted transfers **shall** resume without retransferring verified data. | M | 2 |
| FR-405 | The agent **may** support rsync-style delta against a known basis for small in-place changes. | C | 2 |

### 3.5 Transport (FR-5xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-501 | The agent **shall** use QUIC for all inter-agent communication, with a control stream and on-demand data streams. | M | 0 |
| FR-502 | The transport **shall** support a WAN-tuned congestion controller (e.g. BBR) and operate over links with high latency and packet loss. | M | 1 |
| FR-503 | The transport **shall** survive transient disconnects and resume the operation stream from the last acknowledged sequence. | M | 2 |
| FR-504 | The protocol **shall** be versioned and negotiated at connection setup to permit forward-compatible evolution. | M | 1 |

### 3.6 Topology and discovery (FR-6xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-601 | The agent **shall** support a static, configured peer list per share. | M | 1 |
| FR-602 | The agent **shall** maintain peer liveness detection and reconnect with backoff. | M | 2 |
| FR-603 | The agent **shall** support full-mesh replication for small peer counts and a relay/designated-link policy for larger fan-out. | S | 2 |
| FR-604 | The agent **may** support dynamic membership via a gossip protocol. | C | 4 |

### 3.7 Anti-entropy (FR-7xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-701 | The agent **shall** reconcile state with each peer using a Merkle tree over the share, descending only into differing subtrees. | M | 2 |
| FR-702 | Reconciliation **shall** run at startup, on peer reconnect, and on a configurable interval. | M | 2 |
| FR-703 | Reconciliation **shall** converge divergent replicas to a consistent state without data loss. | M | 2 |

### 3.8 Recovery and durability (FR-8xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-801 | The op-log **shall** be durable across process crash and power loss (fsync before peer acknowledgment). | M | 1 |
| FR-802 | Remote operations **shall** be applied idempotently; re-applying after a crash **shall** be a no-op. | M | 1 |
| FR-803 | File data **shall** be applied atomically (stage, verify full-file hash, atomic rename); partially written files **shall never** be visible to consumers. | M | 1 |
| FR-804 | Metadata, xattrs, and ACLs **shall** be applied only after file content is in place. | M | 3 |

### 3.9 Loop prevention (FR-9xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-901 | The agent **shall** dedup re-received operations via version vectors. | M | 1 |
| FR-902 | When applying a remote operation, the agent **shall** suppress the resulting local filesystem event so it is not re-emitted as a new operation. | M | 1 |
| FR-903 | The system **shall** demonstrate no replication loops or storms on a mesh of three or more nodes. | M | 2 |

### 3.10 Security (FR-10xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-1001 | All inter-agent traffic **shall** be encrypted and mutually authenticated (mTLS via QUIC/TLS 1.3). | M | 1 |
| FR-1002 | Each agent **shall** authenticate peers against an allowlist of pinned certificate identities. | M | 2 |
| FR-1003 | The admin interface **shall** require authentication and run with least privilege. | M | 3 |
| FR-1004 | The agent **may** support per-share encryption keys for dataset isolation. | C | 4 |

### 3.11 Observability, QoS, and administration (FR-11xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-1101 | The agent **shall** export metrics: per-peer replication lag, queue depth, bytes in/out, chunk cache hit rate, conflict count, reconcile events, apply errors. | M | 3 |
| FR-1102 | The agent **shall** emit structured logs and expose a health endpoint. | M | 2 |
| FR-1103 | The agent **shall** enforce configurable bandwidth limits (per-peer and global) with time-of-day scheduling. | M | 3 |
| FR-1104 | The agent **shall** prioritize control/metadata and small assets over bulk data. | S | 3 |
| FR-1105 | The agent **shall** provide an admin CLI/API: status, peers, pause/resume, force-resync, bandwidth control. | M | 3 |
| FR-1106 | The agent **shall** apply backpressure under slow/dead peers without unbounded memory growth. | M | 2 |
| FR-1107 | The agent **shall** refuse to exhaust local free space when applying replicated data, with a configurable reserve. | M | 3 |

### 3.12 Configuration (FR-12xx)

| ID | Requirement | Pri | Phase |
|---|---|---|---|
| FR-1201 | The agent **shall** read declarative configuration (shares, peers, keys, limits) from a versioned config file. | M | 1 |
| FR-1202 | The agent **shall** validate configuration at startup and fail fast with clear diagnostics on invalid config. | M | 2 |
| FR-1203 | The agent **should** support config reload without dropping in-flight transfers. | S | 3 |

---

## 4. Non-functional requirements

Targets are initial design goals and tunable. "Reference WAN" = 150 ms RTT, 1%
loss; "reference LAN" = sub-millisecond, lossless.

### 4.1 Performance (NFR-P)

| ID | Requirement | Target |
|---|---|---|
| NFR-P1 | Local I/O overhead from monitoring | < 5% throughput impact on watched writes |
| NFR-P2 | Metadata propagation latency, LAN, P95 | < 2 s from local commit to peer apply |
| NFR-P3 | Small-file (≤ 1 MB) end-to-end, LAN, P95 | < 5 s |
| NFR-P4 | Small-file end-to-end, reference WAN, P95 | < 15 s |
| NFR-P5 | Per-stream data throughput, LAN | ≥ 1 Gbps (bounded by disk/CPU) |
| NFR-P6 | WAN link utilization under loss | ≥ 80% of available bandwidth at 1% loss |

### 4.2 Reliability and availability (NFR-R)

| ID | Requirement | Target |
|---|---|---|
| NFR-R1 | Local read/write availability | Unaffected by agent or any peer being down (non-blocking, hard requirement) |
| NFR-R2 | Data integrity | Zero corruption / zero partial-file exposure under `kill -9` and power loss |
| NFR-R3 | Convergence after partition heal | Bounded, proportional to backlog; verified to converge |
| NFR-R4 | Data loss on single-node crash | None for acknowledged operations |

### 4.3 Scalability (NFR-S)

| ID | Requirement | Target (v1) | Design ceiling |
|---|---|---|---|
| NFR-S1 | Files per share | ≥ 10 million | higher |
| NFR-S2 | Peers per share | ≥ 16 (full mesh) | relay topology beyond |
| NFR-S3 | Sustained change rate | ≥ 1,000 ops/s/node | — |

### 4.4 Security (NFR-SEC)
- NFR-SEC1: All traffic encrypted (TLS 1.3) and mutually authenticated.
- NFR-SEC2: No secrets in logs; keys stored with restricted permissions.
- NFR-SEC3: Agent runs least-privilege; privileged capability isolated.

### 4.5 Operability (NFR-O)
- NFR-O1: Single static binary, systemd-managed, starts at boot, restarts on failure.
- NFR-O2: All operational state observable via metrics + CLI without a debugger.
- NFR-O3: Bounded memory footprint with configurable queue/cache limits.

### 4.6 Maintainability and portability (NFR-M)
- NFR-M1: Memory- and thread-safe implementation language to eliminate the
  use-after-free / data-race bug class.
- NFR-M2: Linux-portable across major distributions; kernel ≥ 5.9.
- NFR-M3: ≥ 80% automated test coverage on core logic (op-log, VV, reconcile, apply).

### 4.7 Constraints (NFR-C)
- NFR-C1: No central component in the data path.
- NFR-C2: No reliance on a hand-rolled UDP transport (build on QUIC).

---

## 5. Acceptance criteria

Replicore v1 is accepted when, against the reference test bed:

1. All **Must** requirements pass their verification tests.
2. A 3-node mesh replicates create/modify/delete/rename/xattr/ACL changes with
   no loops and full metadata fidelity.
3. `kill -9` during transfer and during apply leaves no corruption or partial
   files; the agent resumes correctly.
4. A multi-minute network partition with concurrent writes on both sides heals
   via reconciliation with deterministic conflict copies and no data loss.
5. On the reference WAN profile (`tc netem` 150 ms / 1% loss), NFR-P4/P6 targets
   are met.
6. Clock skew of several hours on one node does not produce incorrect ordering.
7. A one-week soak under synthetic IVR traffic shows no memory growth, no lag
   drift, and correct tombstone GC.

---

# Part II — Development Plan

## 1. Approach
Iterative, milestone-driven, vertical slices. Each phase delivers a working,
testable increment along the full pipeline rather than a horizontal layer. Test
infrastructure (especially fault injection) is built alongside features, not
deferred. Trunk-based development with short-lived branches and CI gating.

## 2. Technology decisions (locked)

| Area | Choice | Rationale |
|---|---|---|
| Language | Rust (Go acceptable alt.) | Eliminates UAF/race class on a long-lived networked daemon (NFR-M1) |
| Transport | QUIC (`quinn` / `quic-go`) + BBR | WAN performance, mTLS, multiplexing without reinventing a transport |
| Hashing | BLAKE3 | Fast, parallel, cryptographic |
| Chunking | FastCDC | Boundary-stable dedup |
| State store | SQLite (WAL) → RocksDB if needed | Crash-safe, simple to start |
| FS monitoring | fanotify (FID) + periodic Merkle scan | Scalable detection + correctness backstop |
| Serialization | CBOR or Protobuf, versioned | Forward-compatible wire protocol |
| Metrics | Prometheus | Standard operability |
| Membership (later) | SWIM gossip | Dynamic peers (Phase 4) |

## 3. Team and roles
Feasible solo for a senior systems engineer; faster with 2–3. Suggested role
split if staffed: core engine (op-log, VV, reconcile), transport/data plane,
and ops/observability/test. Solo: sequence by phase below.

## 4. Work breakdown (epics)

- **E1 Watcher**: fanotify FID setup, FID→path resolution, baseline scan,
  coalescing, overflow→rescan, metadata capture, filters.
- **E2 State**: op-log schema, materialized index, tombstones, file identity,
  durability/fsync discipline.
- **E3 Causality**: version vectors, apply decision, conflict policy + rules,
  conflict copies, counters.
- **E4 Data plane**: chunker, content store, manifest, missing-chunk diff,
  multi-source fetch, verify, resume, atomic staged apply.
- **E5 Transport**: QUIC connection/stream mgmt, mTLS, BBR, framing/versioning,
  resume from acked seq.
- **E6 Topology**: static peers, liveness/backoff, mesh + relay policy.
- **E7 Anti-entropy**: subtree hashing, Merkle exchange, descent, convergence.
- **E8 Recovery**: idempotent apply, atomic apply guarantees, catch-up replay.
- **E9 Loop prevention**: VV dedup + apply-suppression, mesh validation.
- **E10 Security**: cert provisioning, pinning/allowlist, admin authn.
- **E11 Ops**: metrics, structured logs, health, QoS/bandwidth scheduler,
  backpressure, free-space guard, admin CLI/API.
- **E12 Config**: declarative config, validation, reload.
- **E13 Test infra**: unit harness, integration test bed, `tc netem` fault
  injection, crash injection, soak rig.

## 5. Phases, milestones, and exit criteria

Effort ranges assume one experienced engineer; parallelize to compress.

| Phase | Milestone | Scope (epics) | Exit criteria | Est. effort |
|---|---|---|---|---|
| **0** | M0 — Spike | E1(min), E2(min), E5(min), E8(min) | One-way: a file written on node A appears intact on node B over QUIC, applied atomically | 1–2 wks |
| **1** | M1 — MVP (2-node bidirectional) | E1, E2, E3(core), E4(whole-file), E5, E6(static), E8, E9, E10(mTLS), E12 | Bidirectional sync of all op types between 2 nodes; VV correctness; loop-free; durable; partitioned-namespace operation | 4–8 wks |
| **2** | M2 — Mesh + self-healing | E4(CDC/multi-source), E6(mesh/relay), E7, E8(catch-up), E9(mesh), E11(health/backpressure) | N-node mesh; Merkle reconcile converges; resume after disconnect; no OOM under slow peer | 6–10 wks |
| **3** | M3 — Production hardening | E1(full fidelity), E3(full conflict rules), E10(admin authn), E11(metrics/QoS/CLI/free-space), E12(reload), E13(full) | All Must requirements pass; acceptance criteria §5 met; soak clean | 8–16 wks |
| **4** | M4 — Beyond (optional) | Distributed locking, gossip discovery, web UI, object-store targets | Per-feature acceptance | open-ended |

**Indicative total to production-grade (M3): ~6–12 months solo**, dominated by
Phase 3 hardening and testing. This is the realistic long tail; the happy path
(M0–M1) comes quickly, correctness-under-failure does not.

## 6. Deliverables per milestone
- Working agent binary + config sample.
- Test suite additions (unit + integration + fault-injection scenarios).
- Updated protocol/version notes.
- Operator notes (deploy, configure, recover) — grows into full docs at M3.

## 7. Risk register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| RK-1 | Conflict-resolution correctness (tree-level edge cases) | Med | High | Partition write ownership to avoid conflicts; property-based + adversarial tests; explicit documented rules (FR-304) |
| RK-2 | fanotify event loss / edge behavior | Med | High | Treat watcher as best-effort; mandatory Merkle backstop (FR-104, FR-701) |
| RK-3 | Metadata fidelity (xattr/ACL/uid mapping) underestimated | Med | Med | Dedicated Phase 3 epic; round-trip tests; explicit uid/gid policy |
| RK-4 | WAN performance below target under loss | Med | Med | BBR under QUIC; early `tc netem` benchmarking in M1 |
| RK-5 | Scope creep toward "beat Resilio" generality | High | High | Hold scope to IVR use case; defer Phase 4 features; MoSCoW discipline |
| RK-6 | Solo bus-factor / knowledge concentration | Med | High | Keep design docs current; high test coverage; readable code |
| RK-7 | Testing/hardening effort underestimated | High | Med | Build E13 in parallel from M0; budget Phase 3 generously |
| RK-8 | QUIC/library maturity for chosen language | Low | Med | Use established library (quinn/quic-go); pin versions; abstract behind a transport trait |

## 8. Quality assurance and testing

- **Unit**: op-log ordering, VV dominate/concurrent logic, conflict rules,
  manifest diff, chunk verify, atomic-apply state machine. Target ≥ 80% on core.
- **Property-based**: randomized operation sequences across N simulated nodes
  must converge to identical state (the strongest correctness check).
- **Integration**: multi-container test bed; full op-type matrix; metadata
  round-trip (xattr/ACL/hardlink/symlink/sparse).
- **Fault injection**: `tc netem` (loss/latency/partition); `kill -9` during
  transfer and apply; disk-full; clock skew; event-queue overflow.
- **Soak**: one week of synthetic IVR traffic; watch memory, lag, tombstone GC.
- **CI gate**: build + unit + integration on every push; fault-injection +
  soak on a nightly/pre-release pipeline.

## 9. CI/CD, versioning, release
- CI: format, lint, build, test on each commit; artifact build on tag.
- Release: semantic versioning; protocol version negotiated at handshake so
  agents of adjacent versions interoperate during rolling upgrades.
- Distribution: single static binary + systemd unit + signed checksums.

## 10. Documentation plan
- Architecture & build guide (exists; keep current).
- This RSD (kept as living baseline; changes via revision history).
- Operator guide (deploy/configure/recover) — authored through Phase 3.
- Protocol specification — versioned alongside the wire format.

## 11. Definition of Done
A requirement is Done when: implemented; covered by automated tests; observable
via metrics/logs where applicable; documented; and, for Must items, passing its
mapped acceptance criterion. A milestone is Done when all its requirements are
Done and its exit criteria are demonstrated on the test bed.

## 12. Traceability summary
Requirements map to phases via the Phase column in §3 and the milestone table in
§II.5; each Must requirement maps to an acceptance criterion in §I.5 and a test
class in §II.8. Maintain a living traceability matrix (requirement → phase →
test → status) in the project tracker.
