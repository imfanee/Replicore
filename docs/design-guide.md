# Building a Production-Grade Multipoint-to-Multipoint Replication Engine

A design and build guide for a LAN/WAN file-replication system, scoped for an
IVR/FreeSWITCH storage tier with partitionable write ownership, designed to be
stable, inspectable, license-free, and better than Resilio *for this use case*.

---

## 0. Scope and philosophy

You are not building a Resilio clone. You are building a log-structured,
eventually-consistent replicated-filesystem overlay that is:

- **Multi-master**: every node reads and writes its local storage; the engine
  observes and propagates.
- **Non-blocking**: local I/O never waits on the network. Replication is
  asynchronous.
- **LAN/WAN capable**: one transport (QUIC) that behaves well on both.
- **Correct under failure**: crashes, partitions, packet loss, and downtime
  heal without data loss or silent divergence.

Two reframings make this tractable:

1. **Design conflicts out of existence.** Partition write ownership by
   namespace per site. Concurrent writes to the *same* path then cannot happen,
   and conflict handling degrades to a cheap safety net rather than the hardest
   subsystem you own.
2. **Separate the metadata plane from the data plane.** Metadata is a small,
   ordered, causal operation log. Data is large, content-addressed, and
   idempotent. Replicate them differently. This is the central architectural
   decision; everything else follows from it.

### Where you can beat Resilio
- **Metadata fidelity**: full xattr + POSIX ACL + hardlink + sparse-file
  preservation as a first-class requirement, not an afterthought.
- **Purpose-fit simplicity**: optimized for write-once recordings and
  read-mostly prompts, so the hot path is dumb and rock-solid.
- **Inspectable + license-free**: you own every line and pay per nothing.

### Where you will *not* beat Resilio (accept this)
- Custom WAN congestion control (use QUIC+BBR instead — close enough).
- 250M-file single-job scale and a decade of edge-case hardening.
- A polished management console (build a CLI + metrics first; UI much later).

---

## 1. System architecture

Each node runs one **agent** daemon. Agents form a mesh. An agent has six
internal subsystems:

```
            +-------------------------------------------------+
            |                   AGENT (per node)              |
            |                                                 |
  fs events |  [1] Watcher  --->  [2] Op-Log / State Store    |
  --------> |   (fanotify)        (embedded DB, WAL)          |
            |       |                   |        ^            |
            |       v                   v        |            |
            |  [9] Apply-           [3] Causality &           |
            |  suppression          conflict engine          |
            |                           |                     |
            |  [4] Content store / chunker (BLAKE3, CDC)      |
            |                           |                     |
            |  [5] Transport (QUIC): control stream + data    |
            |       streams  <----  [6] Peer mgr / discovery  |
            |                           |                     |
            |  [7] Anti-entropy (Merkle reconcile)            |
            |  [8] Recovery / staging / atomic apply          |
            |  [11] Metrics, QoS, admin API                   |
            +-------------------------------------------------+
```

Control flows through a metadata channel; bulk bytes flow peer-to-peer as
content-addressed chunks, never through any central node.

---

## 2. Subsystem 1 — Change detection (the watcher)

### Use fanotify, not inotify
- **inotify** needs one watch per directory, added recursively. It races on
  newly created directories (events can occur between `mkdir` and you adding the
  watch — you must rescan a dir immediately after watching it), overflows under
  burst (`IN_Q_OVERFLOW`), and at millions of files the watch table is a memory
  and startup-time problem.
- **fanotify** with `FAN_REPORT_FID` / `FAN_REPORT_DFID_NAME` (kernel ≥ 5.1 /
  5.9) monitors an entire **mount** with a single descriptor and reports
  create/delete/move/modify/attrib with directory FID + filename. This is the
  correct primitive for whole-filesystem monitoring at scale.
  - Requires `CAP_SYS_ADMIN`.
  - Resolve FID → path with `open_by_handle_at(2)`; keep an inode→path cache.
  - It tells you *that* something changed; you then `lstat`/`lgetxattr` to
    capture the actual new state.

### The watcher is necessary but never sufficient
Events get lost: queue overflow, agent downtime, kernel quirks. **You must pair
real-time detection with a periodic full reconciliation scan** (Subsystem 7).
Treat the watcher as the low-latency path and Merkle reconciliation as the
correctness backstop. A system without the backstop will silently diverge — this
is the difference between a demo and "production grade."

### Coalescing and quiescence
A single `cp` of a large file is thousands of write events. Debounce: per-path,
hold a short quiescence timer (e.g. 200–500 ms of no further writes) before
emitting a `WRITE` op, so you hash and ship the file once it has settled. Bound
the coalescing buffer and spill or throttle under pressure (see backpressure).

### Metadata you must capture (production-grade fidelity)
- `mode`, `uid`, `gid`, `mtime` (ns), `size`
- **All xattrs** via `llistxattr`/`lgetxattr` across namespaces. Note POSIX
  ACLs *are* xattrs (`system.posix_acl_access`, `system.posix_acl_default`), so
  capturing every xattr captures ACLs — but you replicate them as raw xattr blobs
  and must `lsetxattr` them on apply, in the right order, with matching uid/gid
  mapping.
- **Hardlinks**: detect `st_nlink > 1`; key by `(st_dev, st_ino)`; replicate
  link relationships, not duplicate content.
- **Symlinks**: never follow; replicate the target string.
- **Special files**: FIFOs, device nodes, sockets — replicate type+metadata, no
  content.
- **Sparse files**: detect holes via `SEEK_HOLE`/`SEEK_DATA`; preserve sparseness
  on apply with `fallocate`/`ftruncate` to avoid inflating recordings.

---

## 3. Subsystem 2 — The operation log and state store

Every local mutation becomes an immutable, ordered record. This log is the
agent's authoritative statement of *what happened here* and is the unit of
replication.

Use an embedded, crash-safe store: **SQLite in WAL mode** (simplest, fine to
millions of rows) or **RocksDB/LMDB** (higher write throughput). Suggested
schema:

```sql
-- The append-only operation journal (this node's truth)
CREATE TABLE oplog (
  seq        INTEGER PRIMARY KEY,   -- monotonic, per-node
  op_id      BLOB UNIQUE,           -- globally unique (node_id + seq)
  node_id    BLOB,                  -- origin node
  op_type    INTEGER,               -- CREATE/WRITE/DELETE/RENAME/CHMOD/XATTR/...
  path       TEXT,
  path_old   TEXT,                  -- for RENAME/MOVE
  size       INTEGER,
  mode       INTEGER,
  uid        INTEGER,
  gid        INTEGER,
  mtime_ns   INTEGER,
  content_hash BLOB,                -- BLAKE3 of full content
  manifest_id  BLOB,                -- -> chunk manifest (see Subsystem 4)
  xattr_blob   BLOB,                -- serialized xattr set (incl. ACLs)
  vv           BLOB,                -- version vector at time of op
  created_at   INTEGER
);

-- Current materialized state per path (for fast lookups + reconciliation)
CREATE TABLE files (
  path         TEXT PRIMARY KEY,
  type         INTEGER,             -- file/dir/symlink/fifo/dev
  content_hash BLOB,
  manifest_id  BLOB,
  size         INTEGER,
  mode INTEGER, uid INTEGER, gid INTEGER, mtime_ns INTEGER,
  xattr_blob   BLOB,
  vv           BLOB,                -- version vector (per-file)
  tombstone    INTEGER DEFAULT 0,   -- deleted? keep for causality
  subtree_hash BLOB                 -- for Merkle anti-entropy
);

-- Per-peer replication cursor
CREATE TABLE peers (
  node_id      BLOB PRIMARY KEY,
  last_sent_seq    INTEGER,         -- our seq we've streamed to them
  last_acked_seq   INTEGER,         -- they confirmed durable
  last_recv_vv     BLOB             -- highest version vector seen from them
);

-- Idempotency: ops we've already applied (survives crash)
CREATE TABLE applied (op_id BLOB PRIMARY KEY);
```

**Tombstones**: never hard-delete a path's row on a `DELETE`. Keep a tombstone
with its version vector, or a late-arriving `WRITE` from a slow peer will
"resurrect" a deleted file. Garbage-collect tombstones only after all peers have
acknowledged the delete (and after a safety window).

---

## 4. Subsystem 3 — Causality and conflict resolution

This is the hardest distributed-systems part. Get it right and the system is
correct; get it wrong and you corrupt data subtly.

### Version vectors (per file)
Each file carries a vector `{node_id: counter}`. On local write, increment this
node's counter. When you receive a remote version `R` for a path with local
version `L`:

- `R` dominates `L` (R ≥ L on every component, > on at least one) → **apply R**.
- `L` dominates `R` → **ignore** (you're ahead).
- Neither dominates (concurrent) → **conflict**.

Wall-clock timestamps alone are *not* a substitute — clock skew makes LWW
silently wrong. Version vectors capture true causality.

### Conflict policy
For partitioned namespaces you should essentially never reach the concurrent
case. When you do, pick a deterministic strategy and stick to it:

- **Deterministic winner** by `(mtime_ns, node_id)` tiebreak, **and**
- **Preserve the loser** as a conflict copy (`name.sync-conflict-<node>-<ts>.ext`),
  Syncthing-style, so no write is ever silently destroyed.
- Emit a metric/alert so an operator notices conflicts are happening at all.

### The genuinely nasty tree-level cases (enumerate and decide explicitly)
- **delete vs. modify**: one site deletes `f`, another writes it concurrently.
  Default: modify wins (resurrect), or keep both as a conflict copy. Decide.
- **rename vs. modify**: `f`→`g` on A, write to `f` on B. Apply rename, then
  apply the write to `g` (track by file identity, not just path).
- **rename vs. rename** (same source, two targets): deterministic winner; loser
  becomes a copy.
- **create vs. create** (same path, different content): conflict copy.
- **directory delete vs. create-inside**: don't delete a non-empty directory if a
  concurrent create populated it; reparent or keep.

Track **file identity** (a stable per-file UUID assigned at create) in addition
to path, so renames are "same file, new path" rather than delete+create. This
single decision removes a large class of rename bugs.

---

## 5. Subsystem 4 — Content-addressed data transfer

### Chunking
Split files with **content-defined chunking** (FastCDC or a Rabin rolling hash),
not fixed-size blocks — so an insertion in the middle re-cuts only the local
region instead of shifting every subsequent boundary. Hash each chunk with
**BLAKE3** (fast, parallel, cryptographic). A file becomes an ordered list of
chunk hashes: its **manifest**.

For your IVR workload specifically, most files are write-once recordings, so the
common case is "transfer a whole new file" and the secondary case is
"append-only growth." You can start with whole-file hashing + simple append
detection and add CDC later; don't over-build chunking before you need it.

### Local content store
Maintain a chunk store keyed by hash (a content-addressed directory tree, or
RocksDB). This gives you dedup for free: identical chunks across files/sites are
stored and transferred once.

### Fetch protocol (multi-source, idempotent)
1. Receiver gets a manifest (chunk-hash list) via the op-log.
2. Receiver diffs against its chunk store → set of missing hashes.
3. Receiver requests missing chunks from any peer advertising them (parallel,
   BitTorrent-style — speed scales with peer count).
4. Each chunk is verified against its hash on receipt (corruption-proof,
   resumable). Idempotent: re-fetching after a crash is safe.

### Delta alternative
For the "small change to an existing file" case, the classic **rsync algorithm**
(rolling weak checksum + strong hash; `librsync`/`zsync`) against a known basis is
simpler than a global chunk store and is well battle-tested. Either works; CDC +
content store scales better to dedup across many files.

---

## 6. Subsystem 5 — Transport (QUIC)

**Do not write your own UDP reliability/congestion protocol.** Build on QUIC:

- UDP-based, NAT-friendly, single port.
- TLS 1.3 built in → encryption + mutual auth (mTLS).
- Stream multiplexing → no head-of-line blocking when shipping many files; each
  file/chunk transfer is its own stream.
- Connection migration, 0-RTT resumption, flow control, keepalive.
- **Pluggable congestion control** — run **BBR** for high-latency/lossy WAN
  links. This is your practical equivalent of ZGT's value proposition.

Libraries: `quinn` (Rust), `msquic` or `lsquic` (C), `quic-go` (Go).

### Channel design
- One **control stream** per peer connection: op-log records, manifests, chunk
  requests, acks, reconciliation messages. Ordered, reliable.
- N **data streams**: chunk payloads, opened on demand, closed when done.
- Pace data streams with a token-bucket rate limiter (QoS, below). Even though
  QUIC paces, you want an explicit cap because a UDP transport will otherwise
  starve other apps on a shared WAN link — the same caveat that bites Resilio's
  ZGT.

LAN: QUIC works fine; you may optionally prefer plain TCP for lowest overhead on
a clean LAN, but a single transport is simpler to operate. Recommend QUIC
everywhere.

---

## 7. Subsystem 6 — Discovery and topology

- **Static peer list** for fixed datacenters is the right starting point and may
  be all you ever need. Since your sites are already on a routable pfSense VPN,
  peers can address each other directly — no tracker, no relay, no NAT traversal
  for the inter-site path.
- For dynamic membership and failure detection later, add **SWIM gossip**
  (the HashiCorp `memberlist` design) — lightweight, scalable health detection.
- Topology: full mesh is O(n²) connections; fine for a handful of DCs. For many
  sites, designate inter-site links or a relay per region (Resilio's "network
  policy" idea) so you don't open n² WAN tunnels.

---

## 8. Subsystem 7 — Anti-entropy (Merkle reconciliation)

The correctness backstop for missed events, downtime, and partitions.

- Maintain a **Merkle tree** over the namespace: each file's leaf hash =
  `H(path, metadata, content_hash, vv)`; directory nodes hash their children
  (the `subtree_hash` column).
- To reconcile, two peers exchange root hashes. If equal, they're in sync — done
  in O(1). If not, descend recursively only into differing subtrees → cost is
  O(differences), not O(files).
- Run reconciliation: on agent startup (before trusting the live stream), on
  peer reconnect after a partition, and on a slow periodic timer.

This is standard Dynamo/Cassandra/Syncthing-style anti-entropy and is what makes
the system self-healing.

---

## 9. Subsystem 8 — Crash recovery and atomic apply

- **Durability**: op-log in WAL mode; `fsync` before acking a peer (tune the
  durability/throughput tradeoff per your RPO).
- **Idempotent apply**: every op has a unique `op_id`; record applied ids in the
  `applied` table; re-applying after a crash is a no-op.
- **Atomic data apply**: download chunks to a staging dir, assemble, verify the
  full-file hash, then `rename(2)` into final place (atomic within a filesystem).
  Never expose a partially-written file. Apply metadata/xattrs/ACLs *after* the
  content is in place.
- **Resumable streaming**: `last_acked_seq` per peer lets you resume the op
  stream exactly where it stopped after a restart.
- **Ordering on apply**: apply parent directory creation before children; apply
  renames before writes to the new path; apply deletes with tombstone semantics.

---

## 10. Subsystem 9 — Loop prevention (the mesh trap)

In a mesh, an op you apply locally will fire your own watcher and threaten to
re-emit as a new op → storms and loops. Two mechanisms, both required:

1. **Version-vector dedup**: a re-received op is recognized as already-known
   (its vv doesn't dominate local) and dropped. This handles the steady state.
2. **Apply-suppression set**: when *you* write a file because of a remote op,
   record `(path, expected_content_hash)` in a short-lived suppression set. When
   the watcher fires for that path with the matching hash, swallow it. This
   prevents the spurious local op at the source.

Without both, a 3-node mesh will melt under feedback.

---

## 11. Subsystem 11 — Security, QoS, observability (the "production grade" tax)

This is roughly half the real work and the part demos skip.

### Security
- mTLS via QUIC: per-agent certificate, allowlist/pin peer cert fingerprints.
- Optional per-share symmetric key for crypto isolation between datasets.
- Authn on the admin API; least-privilege for the daemon (it needs
  `CAP_SYS_ADMIN` for fanotify — isolate it).

### QoS / bandwidth scheduling
- Token-bucket rate limiter per peer and global, with time-of-day schedules
  (don't saturate the production WAN during call peaks).
- Priority lanes: prompts/config replicate ahead of bulk recordings.

### Backpressure
- Bounded queues everywhere. If a peer is slow, throttle the watcher or spill the
  coalescing buffer to disk — never grow unbounded and OOM the box.

### Observability
- Prometheus metrics: per-peer replication lag, queue depth, bytes in flight,
  chunk cache hit rate, conflict count, reconciliation events, apply errors.
- Structured logs, health endpoint, an admin CLI (`status`, `peers`, `resync`,
  `pause`, `bandwidth`).

---

## 12. Wire protocol sketch

Length-prefixed, versioned frames (CBOR or Protocol Buffers) on the control
stream:

```
HELLO        { node_id, version, shares[], cert_fingerprint }
OPLOG_PUSH   { ops: [OpRecord...] }          // metadata, causal
OPLOG_ACK    { up_to_seq }                    // durable confirmation
MANIFEST     { manifest_id, chunk_hashes[], file_meta }
CHUNK_REQ    { hashes[] }
CHUNK_DATA   { hash, bytes }                  // on a data stream; verified
WANT         { have_root_hash }               // anti-entropy: trade roots
TREE_NODE    { path_prefix, child_hashes[] }  // descend differing subtrees
PING/PONG    { ts }                           // liveness + RTT sample
```

Version every frame; negotiate in `HELLO` so you can evolve the protocol without
flag-day upgrades.

---

## 13. Production edge-case checklist

Tick these off before calling it "stable":

- [ ] fanotify queue overflow → trigger targeted rescan, don't drop silently
- [ ] Initial full scan to build baseline state before trusting live events
- [ ] xattr + POSIX ACL round-trip (incl. `system.posix_acl_default` on dirs)
- [ ] uid/gid mapping policy across hosts (numeric match? name map? preserve?)
- [ ] Hardlink preservation; symlink-as-target; FIFO/device/socket handling
- [ ] Sparse-file hole preservation
- [ ] Filename encoding / non-UTF-8 / very long paths / case-only renames
- [ ] Atomic apply (staging + rename); never expose partial files
- [ ] Tombstones + GC-after-all-peers-ack (no delete resurrection)
- [ ] Clock-skew safety (causality from version vectors, not wall clock)
- [ ] Loop suppression verified on a 3+ node mesh
- [ ] Resume after kill -9 mid-transfer with no corruption
- [ ] Partition + heal via Merkle reconcile converges
- [ ] Backpressure under a slow/dead peer (no OOM, no unbounded queue)
- [ ] Bandwidth cap actually honored on a shared WAN link
- [ ] Free-space guard: refuse to fill the disk replicating

---

## 14. Language and library recommendations

- **Rust** (recommended): memory/thread safety eliminates the use-after-free and
  data-race class entirely — the exact bugs that cost multiple review rounds in C
  concurrency work. Ecosystem: `quinn` (QUIC), `blake3`, `fastcdc`, `notify`/raw
  fanotify via `nix`, `rusqlite`/`rocksdb`, `prometheus`, `serde`/`ciborium`.
- **Go** (fastest to ship): great concurrency, `quic-go`, HashiCorp `memberlist`
  (SWIM), simple ops/static binaries. Slightly less control over memory/latency.
- **C/C++**: maximum control and embeddable, but you hand-roll all safety on a
  long-lived networked daemon — highest bug surface. Choose only to integrate
  into existing C infrastructure.

---

## 15. Phased roadmap

**Phase 0 — Spike (prove the pipe).**
One-directional, one watcher → one peer. fanotify → op → QUIC → atomic apply. No
conflicts, no chunking, whole files. Goal: see a file appear on the other side
reliably.

**Phase 1 — MVP (two-node bidirectional).**
Op-log + per-file version vectors, content-hash transfer (whole-file or
`librsync` delta), apply-suppression, tombstones, an initial full-scan baseline,
and a basic periodic rescan. Run with partitioned namespaces so conflicts can't
occur.

**Phase 2 — Mesh.**
N peers, static discovery, multi-source chunk fetch + content store + CDC,
Merkle anti-entropy, crash recovery, resumable streaming.

**Phase 3 — Production hardening.**
Full conflict policy, complete metadata fidelity (xattr/ACL/hardlink/symlink/
sparse), QoS/bandwidth scheduling, metrics/logging/admin CLI, mTLS, backpressure,
and the edge-case checklist. Soak-test with fault injection.

**Phase 4 — Beyond Resilio (only if needed).**
Distributed advisory locking for shared-write paths, a web console, edge/tiered
caching, S3/object back-end targets.

---

## 16. Validation: fault-injection test plan

You cannot call this production-grade without breaking it on purpose:

- **Packet loss / latency**: `tc qdisc add dev … netem loss 5% delay 150ms` on
  the inter-site link; verify throughput holds and nothing corrupts.
- **Hard kill**: `kill -9` the agent mid-transfer and mid-apply; verify
  idempotent resume, no partial files.
- **Partition**: drop the VPN for minutes under active writes on both sides;
  verify Merkle reconcile converges on reconnect, conflict copies appear where
  expected.
- **Burst**: untar a kernel tree (100k+ small files) into a watched dir; verify
  no overflow data loss (rescan kicks in), bounded memory.
- **Clock skew**: skew one node's clock by hours; verify causality still correct
  (this is the test that catches accidental LWW-by-wallclock bugs).
- **Soak**: run for a week with synthetic IVR traffic (write-once recordings +
  periodic prompt updates); watch for memory growth, lag drift, tombstone GC.

---

## 17. One-paragraph summary

Watch the filesystem with fanotify and back it with periodic Merkle
reconciliation. Turn every local change into an immutable, causally-ordered
operation in a WAL-backed log; replicate that log eagerly over a QUIC control
stream secured with mTLS. Ship file bytes separately as BLAKE3 content-addressed
chunks fetched multi-source and verified, applied atomically via staging +
rename. Use per-file version vectors for correctness and partition write
ownership by site so conflicts essentially never occur. Run BBR under QUIC for
WAN performance instead of inventing a transport. Prevent mesh loops with
version-vector dedup plus apply-suppression. Then spend half your effort on the
unglamorous production layer — backpressure, QoS, metrics, recovery, and a
fault-injection test suite — because that layer is what separates a working demo
from a system you can trust with production recordings.
