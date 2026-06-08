*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Deployment Runbook — NFS-fronted Replicore nodes

For the operator standing up the three DRC/Marseille-class nodes (~150 ms RTT
WAN). Each node owns **local** block-backed storage, runs the agent, and
NFS-exports that storage to its **local-site** app servers. Nodes replicate to
each other over the WAN.

```
  Site A app servers        Site B app servers        Site C app servers
        | NFS (LAN)               | NFS (LAN)               | NFS (LAN)
        v                         v                         v
   [ Node-A ]  <===== WAN =====> [ Node-B ] <===== WAN =====> [ Node-C ]
   local fs + agent          local fs + agent           local fs + agent
   exports /rec              exports /rec               exports /rec
        ~150 ms RTT between any two sites
```

The agent watches each node's **local filesystem only**. NFS is just the LAN
delivery path to consumers. The rules below are **correctness-critical and NOT
enforced by code** — you enforce them at deploy time. Theory and the deeper
"why" live in [`DEPLOYMENT-NFS.md`](DEPLOYMENT-NFS.md); this is what you act on.

---

## The rules

### R1 — Never export a shared, mutable, lock-coordinated directory across sites. Keep each site's writable namespace disjoint. **(HARD RULE)**

- **WHY:** NFS locks (NLM/NFSv4) are per-server and do not cross the WAN, and
  Replicore provides no cross-site locking — two sites writing one path race with
  no arbiter either can see.
- **DO:** each site writes ONLY its own subtree — site A writes `/rec/dc-a/**`,
  site B `/rec/dc-b/**`, site C `/rec/dc-c/**`; the other two subtrees are
  exported read-only at each site. Replication makes every node a complete read
  view of all three; writes stay site-local.
- **WHAT BREAKS IF IGNORED:** two sites write the same path with no lock either
  can see; the writes are concurrent, resolve to one deterministic winner with
  the loser kept as a conflict copy, and your apps silently disagree about "the"
  file. This is the one violation that cannot be cleaned up after the fact.

### R2 — The Merkle rescan is AUTHORITATIVE for NFS-client writes; size its interval to your tolerable detection latency.

- **WHY:** fanotify is best-effort for changes arriving via `nfsd`
  (kernel-internal, not reliably delivered to the watcher); the periodic rescan
  is the backstop that actually catches them.
- **DO:** set `scan_interval_secs` to the longest detection delay you can tolerate
  for exported shares. **State plainly: client-write propagation latency ≈ rescan
  interval + WAN lag, NOT real-time.** A 10 s rescan means a client write can sit
  up to ~10 s before the agent even begins replicating it.
- **WHAT BREAKS IF IGNORED:** if the interval is too long (or assumed
  real-time), NFS-client writes that fanotify misses stay undetected until the
  next rescan; apps that expect near-real-time propagation read stale data and
  may act on it.

### R3 — Export `sync` (or require app-level `fsync`).

- **WHY:** with `async`, an NFS write is acked to the client *before* it is
  durable on the node; a crash between the ack and detection silently drops it.
- **DO:** put `sync` in every export option line, OR mandate that writing apps
  `fsync()` before they treat a write as committed. `sync` is the safe default.
- **WHAT BREAKS IF IGNORED:** a node that crashes between acking an NFS write and
  detecting it loses that write entirely — never durable, never replicated — while
  the client believes it succeeded.

### R4 — uid/gid identity consistent across ALL nodes and clients; `owner_policy` mesh-uniform.

- **WHY:** metadata replication carries ownership, so a uid that means "recorder"
  on one node and "nobody" on another corrupts perceived ownership mesh-wide.
- **DO:** matching numeric uid/gid everywhere, OR NFSv4 idmapping with one shared
  domain across every node and client. Set the SAME `owner_policy` on all three
  nodes. `owner_policy = "numeric"` (the default) replicates uid/gid and
  **requires the daemon to have `CAP_CHOWN` — it refuses to boot without it**; if
  you cannot run it with that capability, set `owner_policy = "skip"` on EVERY
  node (uniform). **RESIDUAL — root_squash:** NFS `root_squash` remaps client root
  to `nobody`, so root-owned files written via NFS land squashed *before* the
  agent ever sees them — decide squash policy deliberately and identically; it is
  upstream of replication.
- **WHAT BREAKS IF IGNORED:** replicated ownership becomes meaningless across the
  mesh (files "owned" by the wrong principal); under `numeric` without
  `CAP_CHOWN` the daemon won't start at all; a node with a different uid space
  than its peers churns ownership metadata.

### R5 — Know the cross-site consistency window; do not deploy read-your-writes-across-sites apps here.

- **WHY:** a consumer at another site sees a write only after three delays
  compose.
- **DO:** write it down and design around it —
  **`consumer-visible window = NFS attr cache (acregmin/acdirmin) + WAN
  replication lag + (for client writes) the R2 rescan interval`.** This is
  eventually-consistent across sites. Any app needing read-your-writes must talk
  to its OWN site's node, never a remote one.
- **WHAT BREAKS IF IGNORED:** an app that writes at site A and immediately reads
  from site B gets a miss or a stale version — the data is still in flight across
  the window — and mistakes correct eventual consistency for data loss.

### R6 — Never run the agent watching an NFS *client* mount.

- **WHY:** the agent is the authority for the local storage it watches; pointed at
  a client mount it would re-import another node's already-replicated data as if
  it were a fresh local write.
- **DO:** `share_dir` must be a local block-backed path (disk/LVM/NVMe), never an
  NFS mountpoint. One agent owns one local tree; clients reach it over NFS, the
  agent never reaches back over NFS.
- **WHAT BREAKS IF IGNORED:** the agent re-ingests peers' replicated data as local
  writes, claiming authorship and looping it back into the mesh — a
  self-amplifying storm and corrupted provenance.

---

## Config knobs & recommended values (3-node DRC/Marseille, ~150 ms RTT)

### Agent — `replicore.toml` (identical on all three nodes except identity/paths)

```toml
share_dir               = "/rec"      # LOCAL block-backed (R6). Site A owns /rec/dc-a, B /rec/dc-b, C /rec/dc-c (R1)
scan_interval_secs      = 10          # exported-share detection floor (R2): propagation ≈ 10s + WAN lag
reconcile_interval_secs = 300         # periodic WAN anti-entropy backstop per peer
owner_policy            = "numeric"   # SAME on all 3 (R4); needs CAP_CHOWN, else "skip" on ALL three
# db_path / cas_dir / cert_path / key_path MUST be outside share_dir (and on local disk)
```

| Knob | Recommended | Rationale |
|---|---|---|
| `scan_interval_secs` | **10** (range 5–15) | Sets the NFS-client-write detection floor (R2). Lower = faster detection, more scan CPU/IO; 10 s is a sane LAN-app tolerance. Default is 5. |
| `reconcile_interval_secs` | **300** | Periodic anti-entropy heals anything missed; 5 min is ample for a 3-node WAN. |
| `owner_policy` | **"numeric"**, uniform | Replicates uid/gid (R4). Requires `CAP_CHOWN` (daemon refuses boot otherwise). If you can't grant it, use **"skip"** — but on ALL three nodes. |
| `reserve_bytes` | **default (256 MiB)** or higher | Free-space guard stops inbound data before the disk fills; raise for large shares. |

### Exports — `/etc/exports` (per node; example shown for Node-A)

```
# Site A's OWN writable subtree — rw to SITE A app servers only (R1, R3)
/rec/dc-a   10.10.0.0/24(rw,sync,no_subtree_check,root_squash)

# The other two sites' subtrees are READ-ONLY at site A (R1)
/rec/dc-b   10.10.0.0/24(ro,sync,no_subtree_check,root_squash)
/rec/dc-c   10.10.0.0/24(ro,sync,no_subtree_check,root_squash)
```

| Export option | Recommended | Rationale |
|---|---|---|
| `sync` | **always** | Write durable on the node before the client is acked (R3). |
| `rw` vs `ro` | `rw` **only** on the site's own subtree; `ro` on the other two | Enforces the disjoint writable namespace (R1). |
| `root_squash` | **on** (chosen deliberately, identical everywhere) | Avoids remote root writing root-owned files; note the residual (R4). |
| `no_subtree_check` | **on** | Standard correctness/stability for subtree exports. |

### Client mount (app servers) — bound the attr-cache term of the window (R5)

```
mount -t nfs4 nodeA:/rec/dc-a /mnt/rec/dc-a -o acregmin=3,acdirmin=3,hard
```

`acregmin`/`acdirmin` set the lower bound of attribute-cache freshness — the first
term of the R5 consistency window. Keep them small if consumers need timely
visibility of same-site writes; they cannot fix cross-site lag (use the same-site
node for read-your-writes).

---

## Pre-deploy checklist (tick every box, per node)

**Namespace & exports**
- [ ] Each site has its own writable subtree; clients write ONLY their site's
      subtree (`/rec/dc-<site>`), the other two exported `ro`. (R1)
- [ ] No directory is writable by clients at more than one site. (R1)
- [ ] Every export line includes `sync`. (R3)
- [ ] `root_squash`/`no_root_squash` chosen deliberately and set identically. (R4)

**Agent config (`replicore.toml`, every node)**
- [ ] `share_dir` is a LOCAL block-backed path, NOT an NFS mount. (R6)
- [ ] `db_path`, `cas_dir`, cert, and key are outside `share_dir` and on local disk.
- [ ] `scan_interval_secs` set to the agreed detection latency (recommended 10);
      operators know "client-write propagation ≈ this + WAN lag." (R2)
- [ ] `owner_policy` is the SAME on all three nodes. (R4)
- [ ] If `owner_policy = "numeric"`: the daemon has `CAP_CHOWN` and started
      successfully (it refuses to boot otherwise). (R4)

**Identity**
- [ ] uid/gid scheme identical across all nodes AND all app-server clients
      (matching numeric IDs, or NFSv4 idmapping with one shared domain). (R4)

**Acceptance (before going live)**
- [ ] Documented consistency window = attr cache + WAN lag + rescan interval;
      signed off that no cross-site read-your-writes app is deployed here. (R5)
- [ ] Write a file via NFS at site A → confirm it appears on B and C within
      (rescan interval + WAN lag); confirm a file written via NFS at site B does
      NOT require site A to touch the same path (disjoint namespaces hold). (R1/R2)
- [ ] `kill -9` a node during an active NFS write burst → confirm no committed
      (`sync`-exported / fsync'd) write is lost after restart. (R3)
