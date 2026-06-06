# Replicore RSD — Addendum A: Cluster Membership & Management Plane

| | |
|---|---|
| **Extends** | Replicore RSD v1.0 → **v1.1** |
| **Status** | For review |
| **Adds** | §3.13 Cluster membership (FR-13xx), §3.14 Management & control plane (FR-14xx), new NFRs, new acceptance criteria |
| **Amends** | FR-604 (Could→Must), FR-1203 (Should→Must), FR-1105 (expanded) |
| **Delivered by** | New milestone **M2.5** (between M2 mesh and M3 hardening) |

This addendum makes membership dynamic and adds an operator control plane. It is
additive: nothing in v1.0 is rearchitected. Membership is foundational, so it is
specified before hardening rather than retrofitted after.

---

## 1. Rationale and amendments

The v1.0 mesh assumed a static, hand-configured peer list (FR-601) and treated
dynamic membership and config reload as low-priority. Operating Replicore as a
live multi-site cluster — adding and removing nodes without downtime, from any
node, safely — requires elevating those:

- **FR-604** (dynamic membership): **Could → Must**, delivered in M2.5.
- **FR-1203** (config reload without restart): **Should → Must**, extended with
  validation, diff, and atomic semantics (now FR-1404/1405/1406).
- **FR-1105** (admin CLI): expanded into the full control plane (§3.14).

Static config (FR-601) remains valid as the bootstrap seed; the dynamic roster
is layered on top of it.

---

## 2. §3.13 — Cluster membership (FR-13xx)

| ID | Requirement | Pri |
|---|---|---|
| FR-1301 | Nodes **shall** be added to or removed from the cluster without restarting the daemon or interrupting local I/O or in-flight transfers; changes take effect on `reload`. | M |
| FR-1302 | Operator-intent configuration (human-edited: local identity, shares, limits, trust anchors, seed peers) **shall** be stored separately from the agent-managed **roster** (dynamically learned membership). The daemon **shall never** write to the intent file. | M |
| FR-1303 | The roster **shall** be modeled as a versioned add/remove set: each entry carries an epoch; removals leave tombstones. Concurrent membership changes from different nodes **shall** converge deterministically, and a removed node **shall not** be silently re-added by stale state. | M |
| FR-1304 | Membership and liveness **shall** be disseminated via a gossip protocol (SWIM-style) combined with the versioned roster for identity, converging across all reachable nodes. | M |
| FR-1305 | A peer **shall** be admitted to the data path only if its certificate chains to a configured trust anchor (or matches an explicitly approved fingerprint); membership-changing operations **shall** be authenticated against an admin key. Being announced by an existing node is **not** sufficient to be trusted. | M |
| FR-1306 | When a node is added at one node and comes online (mTLS-validated), that node **shall** disseminate the candidate member to peers, and **shall** provide the verified peer set to the new node. Each receiving peer **shall** independently verify trust (FR-1305) before establishing connectivity. | M |
| FR-1307 | A node **shall** progress through lifecycle states `JOINING → SYNCING → ACTIVE`. It **shall** serve its own namespace immediately on join, but **shall not** be treated as authoritative for shared reconciliation until `ACTIVE`. | M |
| FR-1308 | Node removal **shall** be graceful: the node is no longer contacted, a tombstone prevents re-add from stale gossip, and the disposition of its owned data (retain vs. drop) **shall** follow documented policy. | S |

### New-node bootstrap (elevates M2 reconcile to the join case)

| ID | Requirement | Pri |
|---|---|---|
| FR-1310 | On join, a node **shall** compare its local file inventory (name, content hash, mtime, size, metadata) against the mesh via Merkle reconciliation to compute the initial **bidirectional** sync set — what to pull from peers and what to push to them. | M |
| FR-1311 | During initial sync, the node **shall** continue to capture and replicate new local writes in parallel. The join **shall** use a version-vector **frontier**: bulk catch-up brings the node to the frontier; live operations beyond the frontier apply on top; operations already included in the bootstrap are deduplicated by op-id / version vector. No write **shall** be lost or double-applied across the frontier. | M |

---

## 3. §3.14 — Management & control plane (FR-14xx)

| ID | Requirement | Pri |
|---|---|---|
| FR-1401 | Replicore **shall** provide a CLI (`replicorectl`) communicating with the local agent over an authenticated local IPC socket (Unix domain socket). | M |
| FR-1402 | Read commands **shall** include: `status`, `members`, `peers`, `shares`, `lag`, `conflicts`, `transfers`, `version`. | M |
| FR-1403 | Control commands **shall** include: `config validate`, `config diff`, `config reload`, `member add`, `member remove`, `resync`, `pause`, `resume`, `bandwidth`. | M |
| FR-1404 | `config validate` **shall** check syntax and semantics of a candidate configuration without applying it, reporting all errors. | M |
| FR-1405 | `config diff` **shall** compare a candidate configuration against the running configuration, enumerate added/removed/changed entries, classify each change as **hot-appliable** vs **restart-required**, and report syntax/semantic errors. | M |
| FR-1406 | `config reload` **shall** be atomic: an invalid candidate is rejected and the running configuration is left untouched; a valid candidate is applied without restart. Partial application is **prohibited**. | M |
| FR-1407 | Any node **shall** be able to query the status and details of all nodes: the local agent fans the request out over the authenticated mesh control channel, aggregates responses, and returns **partial results** (clearly marking unreachable nodes) within a bounded timeout. | M |
| FR-1408 | Read/query commands **shall** offer machine-readable output (`--json`). | S |
| FR-1409 | Remote **control** commands (as opposed to read/query) **shall** be separately authenticated/authorized and audit-logged. | S |

---

## 4. New non-functional requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-CM1 | Membership convergence | After a change with no further changes, all reachable nodes converge to the same roster within a bounded time (e.g. < 30 s for ≤ 16 nodes) |
| NFR-CM2 | Membership authentication | No node enters the data path without trust-anchor validation; no unauthenticated membership change is accepted |
| NFR-CM3 | Zero-downtime change | Add/remove + reload interrupts neither local I/O nor in-flight transfers; no daemon restart |
| NFR-CP1 | Control-plane resilience | A status/query fan-out returns partial results under partition within a bounded timeout; it never hangs indefinitely |

---

## 5. New acceptance criteria (append to RSD §I.5)

8. Adding a node to one node's intent config and reloading causes the node to
   join, propagate, and all peers to converge their roster and establish
   connectivity — with **zero interruption** to ongoing replication or local I/O.
9. A joining node bootstraps via reconciliation while concurrently accepting and
   replicating live writes; the final state converges with **no lost or
   duplicated** operations across the bootstrap frontier.
10. `config diff` correctly reports added/removed/changed peers; a syntactically
    or semantically invalid candidate is rejected on `reload` with the running
    configuration intact.
11. A peer presenting a certificate that does not chain to the trust anchor is
    **refused** admission to the data path even when announced by an existing,
    trusted node.
12. `replicorectl status --all` issued from any node aggregates all nodes and
    degrades to clearly-marked partial results under a network partition.
