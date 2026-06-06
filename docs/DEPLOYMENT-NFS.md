# DEPLOYMENT-NFS.md — Replicore nodes fronting LAN app servers over NFS

This document captures the operational and policy constraints for the supported
topology where each Replicore node owns local storage (disk/LVM/NVMe), runs the
agent, **and** NFS-exports that storage to LAN app servers for read/write, with
nodes connected over WAN.

These are **deployment rules enforced by humans**, not features the agent
implements. They exist because moving the writers off the node and onto NFS
clients changes the consistency model. Ignoring them is how a setup that works on
one NAS corrupts shared state once that NAS becomes three replicated nodes.

## The architecture (supported)

```
  Site A app servers        Site B app servers        Site C app servers
        |  NFS (LAN)               |  NFS (LAN)               |  NFS (LAN)
        v                          v                          v
   [ Replicore Node-A ] <==WAN==> [ Replicore Node-B ] <==WAN==> [ Node-C ]
   local fs + agent           local fs + agent            local fs + agent
```

The agent watches each node's **local filesystem**. NFS is only the LAN delivery
path to consumers. The agent must **never** watch an NFS *client* mount.

## Hard constraints

1. **Never export a shared, mutable, lock-coordinated directory across sites.**
   NFS locks (NLM / NFSv4) are scoped to a single server — a lock taken by a
   client at one site is invisible to clients at another. Replicore does not
   provide cross-site locking (that is Phase 4). An application relying on file
   locking for mutual exclusion can therefore corrupt shared state across sites.
   **Keep each site's writable namespace disjoint** (e.g. `/rec/dc-a/…` written
   only at Site A). This also keeps you conflict-free.

2. **The rescan is the authoritative detector for NFS-client writes.** Writes
   arriving via `nfsd` are not reliably delivered to the server's fanotify, so
   real-time detection is best-effort for exported shares. Set the Merkle rescan
   interval on exported shares to your tolerable detection latency. Real-time
   (sub-second) latency applies to node-local writes, not NFS-client writes.

3. **Export with `sync` (or require app-level fsync).** Otherwise a client write
   may be acknowledged before it is durable on the node's local disk, and a node
   crash between the NFS ack and detection can drop the write.

4. **Keep uid/gid identity consistent across all nodes and their clients.** Use
   matching numeric IDs or NFSv4 idmapping with a shared domain. Once M3
   replicates ownership (FR-106), inconsistent IDs surface as wrong ownership
   when files are re-exported at another site.

## Consistency the application must tolerate

A consumer at one site reading a file just written at another sees the old
version (or nothing) until replication converges. The observable staleness is the
sum of:

- the NFS client's attribute cache (`actimeo`), plus
- Replicore's WAN propagation lag, plus
- (for NFS-client-originated writes) the rescan interval.

This is fine for write-once, site-locally-consumed data (e.g. IVR recordings).
It is **not** fine for a workload expecting read-your-writes across sites.

## What works in your favor

- Replicore's atomic apply (stage → fsync → verify → `rename`) plays well with
  NFS close-to-open consistency: the rename swaps in a new inode, so a consumer
  re-stats on next open and gets the complete new file — no torn/partial reads
  while a file is being updated by replication.
- A consumer holding a file open across a replication-driven replacement keeps
  reading the old inode until it reopens. This is standard NFS behavior, not a
  Replicore fault — just expected.

## Fit for the IVR use case

This topology suits the IVR workload because that workload sidesteps the hazards:
writes are site-local and uniquely named (no conflicts), recordings are not
lock-coordinated across sites (no cross-WAN locking need), and consumers read
their own site's data (eventual consistency is invisible). The constraint that
always applies is detection latency for client writes — handled by tuning the
rescan interval. The pattern to prohibit by policy is exporting a **shared,
mutable, lock-coordinated** directory across sites.
