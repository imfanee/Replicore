*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# M4 design — single-copy serving (eliminate steady-state storage amplification)

**Status:** proposed (design-first, per AGENTS.md §3). No code changes in this
document. Targets protocol **v5** (flag-day).

**One-line:** stop keeping a permanent, hash-addressed second copy of all
content; serve from the live tree and use the chunk store only as a *transient,
demand-scoped* working set, so steady-state on-disk footprint drops from ~2× the
dataset to ~1×.

---

## 1. Problem

Every node stores its data **twice**:

1. the live file tree in `share_dir`, and
2. a content-addressed chunk copy in the CAS.

This is not churn debris and not a default-path artifact — it is structural.
Confirmed in code:

- `src/ingest.rs:163` — every local **regular** file is `chunk_file_into_cas()`'d
  on write, copying every chunk into the CAS. The struct comment is explicit
  (`ingest.rs:48`): "Local writes are chunked into the CAS … so this node can
  serve its own content chunk-by-chunk."
- `src/net.rs:1272` — the **only** serve path is `cas.open_reader(&req.hash)`.
  Serving is keyed purely by chunk hash; there is no path that reads a live file
  to answer a fetch.
- `src/chunk.rs:18` — `// No GC in M2 — chunks are never deleted.` The chunks,
  once written, are permanent.

Consequence: replicating an *N*-byte dataset needs ~2N on each node (less only
where the CAS deduplicates identical chunks — `chunk.rs:511` proves dedup, so 2×
is an upper bound for distinct content; more than 2× over time for churning data,
since old versions are never reclaimed).

A 12 TB dataset needs ~24 TB per node. This is the reported defect.

### Root cause

The serve path **addresses content by hash, not by `(file, offset)`**. To answer
"give me chunk H," a node must have H physically present, so it keeps a permanent
hash-addressed mirror of everything it must be able to serve — i.e. everything it
holds. Crash-safe resume (`chunk.rs:101`, presence = a `stat`), bit-rot
self-heal (`chunk.rs:143-165`), and cross-file dedup all ride along on this
mirror, but none of them *require* a full permanent copy. The one property the
permanent CAS genuinely buys is **immutability under concurrent local writes**: a
chunk advertised in a manifest can be fetched minutes later, and the CAS
guarantees the exact advertised bytes still exist even if the live file was
rewritten meanwhile.

The incumbents in this space do **not** pay 2×: rsync keeps no persistent store
(reads live files on demand); Syncthing's database holds only the block *index*
(hashes + offsets), serving by reading the live file and re-hashing before send.
Both accept 1× and handle immutability by **verify-on-read + renegotiate** rather
than by snapshotting all bytes forever.

## 2. Goal / non-goals

**Goal.** Steady-state (converged mesh) footprint = ~1× the dataset on every
node. Extra storage is bounded by the **files actively in flight**, never by the
total dataset, and on a CoW filesystem approaches zero even during initial seed.

**Non-goals.**
- Not changing the receiver's atomic-apply discipline (invariant §2.2 stays
  verbatim: stage → fsync → verify BLAKE3 → `rename` → fsync parent).
- Not changing causality, conflict resolution, membership, or the reconcile gate.
- Not a dedup/compression project. (Cross-file dedup *weakens* under this design;
  see §6.7 — that is an accepted trade.)

## 3. Target model

> Extra storage = a transient working set of in-progress files, bounded by
> transfer concurrency — and on a CoW filesystem, only the bytes that change
> underneath an active transfer. Never a copy of all data.

- **Receiver:** always a single file. Inbound chunks are staging only, freed the
  instant the file is assembled + verified + renamed (`apply.rs:195`). No global
  "sync complete" needed — freeing is per-file at the existing publishing rename.
- **Sender:** no permanent chunk copy. Serve a file's chunks from the **live
  tree**; if the live file is being mutated during the transfer, fall back to a
  **stable snapshot** for the duration. The snapshot is reference-counted and
  dropped once every reachable member has acked that version.
- **Future / returning receiver:** re-materialize on demand at whatever the live
  version is then — possibly newer. Causally fine; version vectors guarantee a
  consistent current state, and anti-entropy re-derives what a returning node
  needs.

## 4. Design

### 4.1 Reverse index: `chunk_hash → (file_id, offset, len)`

We already persist per-file manifests (file → ordered chunk hashes + lengths;
offsets are prefix sums — `chunk.rs:36-45`). Add a DB-resident **reverse index**
mapping each chunk hash of *live* content to a location it can be read from:
`(file_id, offset, len, content_version)`.

- Populated in the same transaction that records a local write's manifest
  (`store.append_local`, the ingest path), replacing the CAS insert side effect.
- A chunk hash may map to multiple `(file, offset)` locations (cross-file
  identical chunks); any one is a valid read source.
- Rows for a `(file, version)` are removed when that version is superseded or the
  file is tombstoned — this is ordinary index maintenance, not the deferred CAS
  GC.

The reverse index replaces "is this chunk present?" (`fetch.rs:222`,
`chunk.rs:has`) for *locally-originated* content with "do I have a live byte range
that hashes to this chunk?"

### 4.2 Serve path (rewrite of `net.rs:1272`)

To serve chunk `H` to a peer:

1. Look up `H` in the reverse index → `(file, offset, len, version)`.
2. Read `len` bytes at `offset` from the live file in `share_dir`.
3. **Re-hash and compare to `H`** (verify-on-read). This is the safety pin:
   - match → stream the bytes.
   - mismatch (file changed/truncated/gone since advertise) → the chunk is
     **stale**; return a typed `STALE` response (§4.6), never bytes.

Verify-on-read means a stale serve can never corrupt a peer (the receiver
re-hashes anyway, invariant §2.2). Worst case is a re-fetch, not bad data.

### 4.3 Snapshot strategies (how the transient copy is made)

Reading live bytes is only safe if the file is stable for the transfer window. We
pick a strategy per file, by filesystem capability, cheapest first:

1. **CoW reflink snapshot** (`FICLONE`/`FICLONERANGE`) on XFS / Btrfs / ZFS /
   bcachefs. The snapshot shares physical extents — ~0 space, only bytes the app
   rewrites *during* the window cost anything. **Initial bulk seed stays ~1×.**
   Serve from the reflink; drop it when done.
2. **Optimistic serve-from-live, snapshot-on-contention.** No snapshot up front;
   serve from the live file with verify-on-read (§4.2). On the *first* `STALE`
   for a file (i.e. it is being written during its own transfer), materialize a
   snapshot of that one file (reflink if available, else copy) and restart its
   transfer from the snapshot. Zero overhead unless a file is hot during sync.
   This is the fallback for non-CoW filesystems and keeps **initial seed at 1×**
   (a cold seed has no concurrent writers).
3. **Full byte copy** of the in-flight file — last resort, FS-agnostic. Bounded
   by `max_concurrent_transfers` (default 8) × file size, never the dataset. Used
   only when a non-reflink file is provably hot and option 2 would livelock.

Capability is probed once at startup (attempt a tiny `FICLONE` in `cas_dir`'s
filesystem; cache the result) and logged loudly, like the fanotify degrade.

### 4.4 Snapshot lifecycle (reference-counted by the ack frontier)

A materialized snapshot exists only while some reachable peer still needs that
`(file, version)`. Reuse the existing **version-vector ack frontier** (M1
ack-frontier safety, invariant §2.4's "GC only after all peers acknowledge plus a
safety window" discipline):

- Key each snapshot by `(file_id, content_version)`; ref-count by the set of
  reachable members whose ack frontier does **not** yet cover the op that
  produced that version.
- Drop the snapshot when the frontier covers all **reachable** members, plus the
  same safety window already used for tombstone GC.
- **Partitioned / offline member:** do *not* hold the snapshot indefinitely. Drop
  once reachable peers ack. A returning node is the §3 "future receiver" case:
  re-materialize at the then-current version; anti-entropy drives it.

This is deliberately the *same* safety rule as tombstone GC (§2.4), so it inherits
a reviewed discipline rather than inventing a new one.

### 4.5 Receiver staging lifecycle

Inbound chunks land in a staging area (today the CAS; under M4 a dedicated
`staging_dir`, or the CAS demoted to staging-only). The moment `apply.rs:195`
assembles a file, verifies its whole-file BLAKE3, and renames it into place, the
staging chunks for that file are deleted. Crash-safety is unchanged: a partial
staging set after a kill is swept on startup (the existing
`sweep_orphan_temps` discipline, `chunk.rs:186`) and re-fetched — staging is
re-derivable, never authoritative.

### 4.6 Protocol: the `STALE` renegotiation case (v5, flag-day)

New typed serve response: `STALE { chunk_hash }` — "I advertised this but my live
bytes no longer match; re-pull the manifest." Receiver behavior:

1. On `STALE`, drop the in-flight file's manifest and re-request it from the
   peer (or another peer via multi-source `fetch.rs`).
2. Bounded retries with backoff; after *k* `STALE`s for one file, defer it to the
   next anti-entropy cycle rather than spin (no livelock — invariant §5, never
   trust/loop on network-driven state; bound everything).

This is the one genuinely new wire case and the main test surface. It must never
panic and must be bounded (invariant §5).

### 4.7 Self-heal & anti-entropy after copies are gone

With no permanent CAS, healing a bit-rotted *live* file = detect via Merkle
anti-entropy (unchanged), then re-fetch the affected chunks from a peer that
still has good live bytes (served via §4.2). Requires ≥1 peer with an intact live
copy — true in any ≥2-replica mesh. The `chunk.rs:read` "evict corrupt chunk for
re-fetch" self-heal moves to the staging path; live-file rot is caught by the
reverse-index verify-on-read (a mismatch on serve also flags local rot).

## 5. Invariant impact (AGENTS.md §2)

| Invariant | Impact |
|---|---|
| §2.2 Atomic apply | **Unchanged.** Receiver still stage→fsync→verify→rename. |
| §2.4 Tombstones, GC-after-ack+window | **Reused** as the snapshot-drop rule (§4.4). |
| §2.5 Never trust network input | New `STALE` path must be bounded, no panics (§4.6). |
| §2.7 One write path to files | **Unchanged.** Serve path is read-only; no new file writer. |
| Reconcile gate | **Unchanged.** Anti-entropy ordering untouched. |
| §2.1 Causality from VVs | **Unchanged**; snapshot versioning keys off VV, not clock. |

No invariant is weakened. Two are *reused* (§2.4 for snapshot GC, §2.2 verify
discipline extended to serve-side verify-on-read).

## 6. Config & migration

- **Config:** `cas_dir` is reinterpreted as `staging_dir` (transient). Optional
  `serve_mode = "auto" | "reflink" | "live" | "copy"` (default `auto` = probe).
  `reserve_bytes` semantics unchanged but the guard now protects the much smaller
  staging working set.
- **Flag-day to v5.** Per project doctrine the whole mesh runs one protocol
  version; `PROTO_VERSION` 4 → 5, ALPN `replicore/5`. A v4↔v5 node pair will not
  interoperate. Rollout = drain, upgrade all nodes, restart (documented in the
  upgrade runbook).
- **On-disk migration:** first v5 boot builds the reverse index from existing
  manifests, then deletes the permanent CAS contents (reclaiming the 2×). This is
  a one-way, idempotent, resumable migration; the live tree is the source of
  truth so a crash mid-migration just re-derives.

## 7. Edge cases

- **File rewritten mid-serve** → `STALE` → renegotiate (§4.6).
- **File deleted mid-serve** → reverse-index lookup misses or read ENOENT →
  `STALE`; tombstone propagates normally.
- **Sparse files** → serve path must preserve the hole semantics already in
  `assemble_from_cas` (`chunk.rs:295`, all-zero chunk = seek, not write).
- **Non-CoW + persistently hot file** → option 3 full copy of that one file;
  logged; bounded by transfer concurrency.
- **Fan-out (1→many push)** → only the origin holds a transient copy, so multi-
  source degrades toward single-source. Optional mitigation: a mid-sync receiver
  swarms chunks it already holds to peers before freeing staging. Performance
  only; correctness independent.
- **Whole-mesh cold start** → cold files have no writers → option 2 stays at 1×.

## 8. Test & soak plan

This touches a high-risk subsystem (serve/fetch); design-first + full re-soak
required.

1. **Unit:** reverse-index round-trip; verify-on-read match/mismatch; `STALE`
   bound/backoff; reflink-capability probe true/false paths; sparse serve.
2. **Property:** convergence property tests (existing) must pass unchanged with
   the live serve path. Add: "file mutated during its own transfer always
   converges" (random write injection mid-fetch).
3. **Integration (rig):** initial seed of a multi-GB tree measured at ~1× peak
   disk on both CoW and ext4; hot-file-during-seed exercises options 2/3.
4. **Migration:** v4 store with permanent CAS → v5 boot → assert reverse index
   complete, CAS reclaimed, no data loss, crash-resume mid-migration.
5. **Soak:** the existing chaos soak (kill -9 cadence) re-run for ≥48 h, with an
   added invariant assertion: **peak disk per node ≤ 1× dataset + bounded
   in-flight working set** across the whole run, plus the existing byte-identical
   convergence proof.

## 9. Risks & open decisions

- **R1 — serve-side CPU/IO.** Re-reading + re-hashing live bytes per fetch costs
  more than streaming a ready chunk, heaviest during initial seed. Mitigation: a
  small hot LRU of recently-served chunk bytes; reflink avoids re-read. *Decision:
  acceptable? measure on the rig before committing.*
- **R2 — dedup loss.** Cross-file "free" dedup from the CAS weakens (a chunk is
  served from one live location; identical content elsewhere is not coalesced on
  disk — the live tree already stores it once per file regardless). Net disk is
  still ≤ live-tree size, so this only forgoes a *bonus*, never regresses below
  1×. *Decision: confirm no workload depends on CAS dedup as a space win.*
- **R3 — fan-out throughput** (§7). *Decision: ship single-source first, add
  receiver swarming only if the rig shows a regression.*
- **R4 — protocol churn** on the most safety-critical subsystem, requiring a
  flag-day and re-soak. This is the real cost; it is a milestone, not a patch.

## 10. Work breakdown (rough)

1. Reverse-index schema + ingest population + manifest-on-write migration off CAS.
2. Serve path rewrite (`net.rs`) with verify-on-read + `STALE`.
3. Snapshot strategies + FS-capability probe (reflink / live / copy).
4. Snapshot lifecycle ref-counted on the ack frontier.
5. Receiver staging-delete-after-assembly.
6. v5 protocol bump + flag-day; v4→v5 on-disk migration.
7. Test matrix (§8) + ≥48 h re-soak with the disk-amplification assertion.

Steps 1–2 are the core; 3–4 are where the design earns its 1×; 6–7 are the
release gate.
