# CLAUDE.md — Replicore

Replicore is an agent-based, eventually-consistent, **multi-master** file
replication engine for LAN and WAN. One daemon per node; nodes form a dynamic
mesh; each node reads/writes local storage normally and the engine propagates
changes without blocking local I/O. Read `docs/RSD.md`,
`docs/RSD-addendum-membership.md`, and `docs/design-guide.md` before non-trivial
work — they are the source of truth. This file is the short version Claude Code
must keep in mind every session.

## Non-negotiable invariants (violating any of these is a defect, not a style nit)

**Replication core**
1. **Causality comes from version vectors, never wall-clock time.** Wall-clock
   may only break ties between already-concurrent versions. (FR-301)
2. **Apply is atomic.** Stage in the destination dir → fsync → verify BLAKE3 →
   `rename(2)` → fsync parent. Never expose a partial/unverified file. (FR-803)
3. **Loop prevention requires BOTH** version-vector dedup AND apply-suppression
   of our own apply's fs event. One alone storms a mesh. (FR-901/902)
4. **Tombstones, not hard deletes**; GC only after all peers ack + safety window.
   Never resurrect a deleted file via a late write. (FR-204)
5. **Never trust network input.** No panics on malformed/hostile peer data;
   bound every buffer; reject path escapes.
6. **The SPIKE-ONLY `AcceptAny` cert verifier must be deleted, never shipped.**
   Production uses mutual TLS with a pinned peer-cert allowlist. (FR-1001/1002)

**Cluster membership & control plane (M2.5+)**
7. **Intent config is human-owned; the roster is agent-owned.** The daemon
   **never writes** the intent file (`replicore.toml`); dynamically-learned
   membership lives in the separate agent-managed roster. (FR-1302)
8. **Announcement is not authorization.** A peer enters the data path only after
   its cert validates against the trust anchor; membership changes are
   admin-signed. A node being vouched-for by a peer is not trust. (FR-1305/1306)
9. **Config reload is atomic.** Invalid candidate → reject, running config
   untouched. Partial application is prohibited. (FR-1406)
10. **Membership converges, never diverges.** The roster is a versioned OR-Set
    (epochs + tombstones); concurrent add/remove from different nodes must
    converge deterministically. (FR-1303)
11. **Join uses a version-vector frontier.** Bulk bootstrap + parallel live ops
    must compose with no lost or double-applied ops across the frontier.
    (FR-1311)

If a rule here cannot afford to be "mostly followed," it is also enforced in CI /
pre-commit — do not rely on prose alone.

## Tech stack (locked — do not substitute without raising it first)

- Language: **Rust**. Async: **tokio**.
- Transport: **quinn** (QUIC, pluggable CC; `quiche` is the approved BBR
  fallback). Never hand-roll a UDP reliability/congestion layer.
- Hash: **blake3**. Chunking: **fastcdc**.
- FS monitoring: **fanotify** via `libc` (FID reporting) + periodic Merkle scan
  as the correctness backstop.
- State store: **rusqlite** (WAL) or **redb**. Prefer pure-Rust deps.
- Membership: SWIM-style gossip + versioned roster (no Raft for small clusters).
- Serialization: **serde** + versioned binary (`bincode`/`postcard`).
- Metrics: **prometheus**. Logging: **tracing**. CLI: `replicorectl` over a
  Unix domain socket.

## Commands

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings   # MUST be clean before "done"
cargo fmt --all

# operator CLI (talks to the local agent over a UDS):
replicorectl status [--all] [--json]        # --all fans out across the mesh
replicorectl members | peers | shares | lag | conflicts | transfers
replicorectl config validate <file>
replicorectl config diff <file>             # candidate vs running, classified
replicorectl config reload                  # atomic; reject-on-invalid
replicorectl member add|remove <node>
replicorectl resync | pause | resume | bandwidth ...

# two-node + emulated-WAN integration rig (root + sch_netem on host):
sudo scripts/wan-testbed.sh up | status | down
```

## Conventions

- Errors: `thiserror` for library enums, `anyhow` only at binary boundaries.
  **No `unwrap`/`expect`/`panic!`** in non-test code except on a documented,
  locally-proven invariant.
- Prefer message-passing over shared `Mutex` state. `unsafe` needs a `// SAFETY:`
  comment and review.
- Every fallible I/O path handles partial writes, short reads, disconnects.
- Correctness-critical logic (version vectors, conflict rules, reconcile, apply,
  roster convergence, join frontier) MUST have property-based tests.

## Workflow

- One milestone at a time (`prompts/`): M1 → M2 → **M2.5** → M3.
- Correctness-critical subsystems: **use Plan Mode**, propose the plan, wait for
  human approval before writing code.
- Definition of Done: implemented + `clippy` clean + unit/property tests pass +
  milestone integration test passes on the rig + mapped RSD exit criterion
  demonstrated. Commit in logical units.
- When unsure about a correctness decision, **stop and ask** rather than guess.

## Deployment constraint (NFS-fronted nodes)

If nodes NFS-export to LAN app servers, read `docs/DEPLOYMENT-NFS.md`. Key rule
for the agent's assumptions: the watcher is **best-effort** for writes arriving
via `nfsd`; the **rescan is authoritative** for NFS-exported shares. Do not weaken
the rescan path on the assumption that fanotify catches everything.

## Toolchain note

`Cargo.toml` pins `time` and `blake3` only for the older apt `cargo` (Rust 1.75).
Remove those pins on a current toolchain.
