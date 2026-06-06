# M2 — Mesh + self-healing

> Paste into a fresh Claude Code session at the repo root (`/clear` first). Plan Mode.

## Read first
- `docs/RSD.md` §3.4, §3.6, §3.7, §3.11 (transfer, topology, anti-entropy, backpressure)
- `docs/design-guide.md` §5, §7, §8 (content transfer, Merkle reconcile, recovery)
- The M1 code (op-log, version vectors, control/data streams)

## Goal
Scale from two nodes to an **N-node mesh** that **self-heals**. Add
content-defined chunking with deduplicated, multi-source transfer; Merkle-tree
anti-entropy so replicas converge after missed events or downtime; resumable
streaming; and backpressure so a slow/dead peer never exhausts memory. Still
partitioned write ownership (no conflict resolution yet).

## In scope (RSD requirements)
- FR-402/403: content-defined chunking (fastcdc) + a content-addressed chunk
  store; receiver fetches only missing chunks, in parallel, from any peer that
  has them; verify each chunk on receipt.
- FR-404: resume interrupted transfers without re-sending verified chunks.
- FR-104: on fanotify queue overflow / detected gaps, trigger a targeted rescan.
- FR-602/603: peer liveness + reconnect with backoff; full mesh for small N,
  plus a relay/designated-link policy hook for larger fan-out.
- FR-701/702/703: Merkle tree over each share (per-subtree hashes); peers trade
  root hashes and descend only into differing subtrees; reconcile on startup, on
  reconnect, and on a timer; converge with no data loss.
- FR-803 (extend): apply still atomic when assembling from chunks (stage full
  file, verify whole-file hash, then rename).
- FR-1102/1106: health endpoint; bounded queues + backpressure (throttle the
  watcher or spill to disk under a slow peer; never grow unbounded).

## Out of scope
Conflict resolution/copies, full metadata fidelity, QoS scheduling, metrics
beyond a health endpoint, admin CLI, security beyond M1's mTLS. Gossip discovery
stays out (static + relay only).

## Mandated design (do not improvise)
- **Chunk identity = BLAKE3 of chunk bytes.** A file's manifest is the ordered
  list of chunk hashes; ship the manifest on the control stream, fetch missing
  chunks on data streams. Chunks are immutable and idempotent.
- **Merkle leaf = `H(path, metadata, content_hash, vv)`**; directory nodes hash
  their children. Reconciliation cost must be O(differences), not O(files) —
  if a subtree's hash matches, do not descend.
- **Reconcile is the correctness backstop, not an optimization.** It must run
  before a freshly-(re)started node trusts the live op stream.
- **Backpressure propagates to the source.** A blocked send must slow the
  watcher/coalescer; design bounded channels with explicit policy, not implicit
  unbounded growth.
- Reuse M1's op-log/VV/apply-suppression unchanged for the metadata plane; this
  milestone is about the data plane + anti-entropy, not redoing causality.

## Deliverables
- `chunk` module (fastcdc + content store + manifest), `fetch` (missing-chunk
  diff + multi-source parallel fetch + verify + resume), `merkle` (subtree hash
  maintenance + reconcile protocol), `peer` (liveness, reconnect, mesh/relay),
  backpressure wiring, health endpoint.
- Property test: divergent replicas (one node fed ops the other missed)
  reconcile to identical state. Integration test on a 3-node rig.

## Exit criteria (must be demonstrated)
1. 3-node mesh replicates create/modify/delete across all nodes.
2. Partition a node for minutes under writes elsewhere; on reconnect, Merkle
   reconcile converges it with no data loss and without re-transferring
   unchanged data.
3. Interrupt a large-file transfer; it resumes without re-sending verified chunks.
4. Identical chunks across files/nodes are stored/transferred once (dedup proven).
5. A dead/slow peer does not grow memory unbounded (backpressure observable).
6. `cargo clippy --all-targets -- -D warnings` clean.

## Reviewer checklist (human gate)
- [ ] Merkle descent truly prunes matching subtrees (confirm O(diff), e.g. by
      counting compared nodes on a near-identical pair).
- [ ] Chunk verification happens BEFORE a chunk is trusted/stored, every path.
- [ ] Assembled files are verified whole-file before the atomic rename.
- [ ] Reconcile runs and completes before a restarted node applies live ops
      (no window where it acts on a stale view).
- [ ] Resume logic cannot double-apply or skip a chunk after a mid-transfer kill.
- [ ] Backpressure path has no unbounded buffer; trace the slow-peer case.
- [ ] Reconnect backoff is bounded and jittered (no thundering herd on flap).
- [ ] Multi-source fetch tolerates a peer disappearing mid-fetch.
