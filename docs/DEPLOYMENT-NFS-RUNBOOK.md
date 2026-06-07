# DEPLOYMENT-NFS-RUNBOOK.md — operator runbook for NFS-fronted Replicore nodes

For the person standing up the three DRC/Marseille-class nodes. Each node owns
local storage, runs the agent, and NFS-exports that storage to LAN app servers;
nodes are joined over WAN. These constraints are **correctness-critical and NOT
enforced by code** — you enforce them at deploy time. The *why* and the theory
live in `docs/DEPLOYMENT-NFS.md`; this is the checklist you act on.

```
  Site A app servers        Site B app servers        Site C app servers
        | NFS (LAN)               | NFS (LAN)               | NFS (LAN)
        v                         v                         v
   [ Node-A ]  <===== WAN =====> [ Node-B ] <===== WAN =====> [ Node-C ]
   local fs + agent          local fs + agent           local fs + agent
   exports /rec              exports /rec               exports /rec
```

The agent watches each node's **local filesystem only**. NFS is just the LAN
delivery path to consumers.

---

## The rules (enforce every one at deploy time)

**R1 — Disjoint writable namespace per site. NEVER export a shared, mutable,
lock-coordinated directory across sites.**
WHY: NFS locks (NLM/NFSv4) are per-server and do NOT cross the WAN, and
Replicore provides no cross-site locking — two sites writing one path race with
no arbiter.
DO: give each site its own writable subtree and let clients write only their
own. E.g. site A app servers write `/rec/dc-a/**` only; `/rec/dc-b`, `/rec/dc-c`
are read-only to them. Replication makes every node's `/rec/dc-*` a complete
read view; writes stay site-local. This is the hard rule — if you enforce
nothing else, enforce this.

**R2 — The rescan is authoritative for NFS-client writes; size its interval to
your tolerable detection latency.**
WHY: fanotify is best-effort for changes arriving via `nfsd` (kernel-internal,
not always delivered to the watcher); the periodic Merkle rescan is the
backstop that actually catches them.
DO: set `scan_interval_secs` to the longest detection delay you can tolerate for
exported shares (default `5`). CONSEQUENCE TO WRITE DOWN: **NFS-client-write
propagation latency ≈ rescan interval, not real-time.** A 30 s rescan means a
client write can take up to ~30 s before the agent even begins replicating it.

**R3 — Export with `sync` (or require app-level fsync).**
WHY: with `async`, an NFS write is acked to the client before it is durable on
the node; a node crash between the ack and detection silently drops it.
DO: put `sync` in every export option line, OR mandate the writing apps `fsync()`
before they treat a write as committed. `sync` is the safe default.

**R4 — uid/gid identity consistent across ALL nodes and clients; `owner_policy`
mesh-uniform.**
WHY: metadata replication carries ownership, so a uid that means "recorder" on
one node and "nobody" on another corrupts perceived ownership mesh-wide.
DO: matching numeric uid/gid everywhere, OR NFSv4 idmapping with one shared
domain across every node and client. Set the SAME `owner_policy` on every node.
`owner_policy = "numeric"` (the default) replicates uid/gid and **requires the
daemon to have CAP_CHOWN — it refuses to boot without it**; if you cannot run it
privileged, set `owner_policy = "skip"` on EVERY node (uniform). RESIDUAL: NFS
`root_squash` remaps client root to `nobody`, so root-owned files written via
NFS land squashed before the agent ever sees them — decide squash policy
deliberately; it is upstream of replication.

**R5 — Know the cross-site consistency window; do not put read-your-writes apps
across sites on this.**
WHY: a consumer at another site sees a write only after three delays compose.
STATE IT: `consumer-visible window = NFS attr cache (acregmin/acdirmin) + WAN
replication lag + (for client writes) the R2 rescan interval`. This is
eventually-consistent across sites. Any app needing read-your-writes ACROSS
sites must talk to its own site's node, not a remote one.

**R6 — Never run the agent watching an NFS *client* mount.**
WHY: the agent is the authority for the local storage it watches; pointed at a
client mount it would re-import another node's already-replicated data as if
local — a replication loop and false authorship.
DO: `share_dir` must be a local block-backed path (disk/LVM/NVMe), never an NFS
mountpoint. One agent owns one local tree; clients reach it over NFS, the agent
never reaches back over NFS.

---

## Pre-deploy checklist (tick every box, per node)

Namespace & exports
- [ ] Each site has its own writable subtree; clients can write ONLY their
      site's subtree (`/rec/dc-<site>`), all others exported read-only. (R1)
- [ ] No directory is writable by clients at more than one site. (R1)
- [ ] Every export line includes `sync`. (R3)
- [ ] `root_squash`/`no_root_squash` chosen deliberately and identically. (R4)

Agent config (`replicore.toml`, every node)
- [ ] `share_dir` is a LOCAL block-backed path, NOT an NFS mount. (R6)
- [ ] `scan_interval_secs` set to the agreed detection latency for the share;
      operators know "client-write propagation ≈ this value." (R2)
- [ ] `owner_policy` is the SAME on all three nodes. (R4)
- [ ] If `owner_policy = "numeric"`: the daemon runs with CAP_CHOWN (it will
      refuse to boot otherwise) — verified by a successful start. (R4)

Identity
- [ ] uid/gid scheme identical across all nodes AND all app-server clients
      (matching numeric IDs, or NFSv4 idmapping with one shared domain). (R4)

Acceptance (before going live)
- [ ] Documented consistency window = attr cache + WAN lag + rescan interval;
      signed off that no cross-site read-your-writes app is deployed here. (R5)
- [ ] Write a file via NFS at site A → confirm it appears on B and C within
      (rescan interval + WAN lag); confirm a file written via NFS at site B does
      NOT need site A to write the same path (disjoint namespaces hold). (R1/R2)
- [ ] `kill -9` a node during an active NFS write burst → confirm no committed
      (fsync'd / `sync`-exported) write is lost after restart. (R3)

---

## What breaks if you ignore each rule

- **R1 (shared writable path across sites):** two sites write the same path with
  no lock either can see; the writes are concurrent, resolve to one winner with
  the loser kept as a conflict copy, and your apps silently disagree about
  "the" file forever. The one rule whose violation cannot be cleaned up after.
- **R2 (rescan interval too long / assumed real-time):** NFS-client writes that
  fanotify misses sit undetected until the next rescan; apps that assume
  near-real-time propagation see stale data for up to the interval and may act
  on it.
- **R3 (`async` exports, no fsync):** a node that crashes between acking an NFS
  write and detecting it loses that write entirely — it was never durable and
  never replicated; the client believes it succeeded.
- **R4 (uid/gid skew or mixed `owner_policy`):** replicated ownership becomes
  meaningless across the mesh (files "owned" by the wrong principal); under
  `numeric` without CAP_CHOWN the daemon won't start at all, and a node with a
  different uid space than its peers churns ownership metadata.
- **R5 (deploying read-your-writes across sites):** an app that writes at site A
  and immediately reads from site B gets a miss or a stale version — the data is
  in flight across the window — and treats correct eventual consistency as data
  loss.
- **R6 (agent on an NFS client mount):** the agent re-ingests peers' replicated
  data as local writes, claiming authorship and looping it back into the mesh —
  a self-amplifying storm and corrupted provenance.
