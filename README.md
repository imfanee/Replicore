*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Replicore

**Replicore** is a production-grade, agent-based, eventually-consistent,
**multi-master** file replication engine for LAN and WAN. One daemon
(`replicored`) runs per node; nodes form a dynamic, self-healing mesh; each node
reads and writes its local storage normally and the engine propagates every
change to all peers **without blocking local I/O**.

- **Multi-master, not primary/replica.** Every node accepts writes. Causality is
  tracked with **version vectors** (never wall-clock time); concurrent edits are
  resolved deterministically and the loser is preserved as a conflict copy — no
  silent data loss.
- **Atomic apply.** A replicated file is staged, fsync'd, BLAKE3-verified, then
  `rename(2)`'d into place. A partial or unverified file is never exposed.
- **Self-healing.** Metadata replicates as a causally-ordered operation log; file
  data replicates as content-addressed **FastCDC chunks**; any divergence is
  detected and repaired by **Merkle anti-entropy**.
- **Dynamic membership.** Nodes join and leave a live cluster with zero downtime.
  Membership is an epoch-versioned register that converges deterministically;
  every peer is admitted only after mutual-TLS validation against a pinned trust
  anchor, and membership changes are admin-signed.
- **Operable.** A local `replicorectl` CLI (over a Unix domain socket) exposes
  status, lag, conflicts, transfers, live config reload, bandwidth control, and
  membership management. Prometheus `/metrics` and a `/healthz` endpoint are
  built in.

## Status

**M3 — production hardening — complete.** The engine implements the full
correctness core (op-log, version vectors, apply-suppression, conflict
resolution, metadata fidelity), the self-healing mesh (chunking, multi-source
fetch, Merkle anti-entropy), dynamic cluster membership with a signed control
plane, and production concerns (QoS/bandwidth shaping, free-space guard, metrics,
BBR congestion control). It is under long-duration soak validation on the
emulated-WAN rig.

## Documentation

| Document | Audience | What it covers |
|---|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Everyone | How Replicore works: op-log, version vectors, chunks, anti-entropy, membership |
| [docs/DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md) | DevOps / SRE | Install, provision identities, configure, run under systemd, firewall, upgrade, back up |
| [docs/ADMIN-GUIDE.md](docs/ADMIN-GUIDE.md) | Cluster admins | Day-2 ops: `replicorectl`, membership, monitoring, conflicts, config reload, troubleshooting |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | DevOps / admins | Every configuration field, defaults, and hot-reload vs restart-required |
| [docs/SECURITY.md](docs/SECURITY.md) | Security / DevOps | Trust model, mutual TLS, admin signing, control-socket auth |
| [docs/DEPLOYMENT-NFS.md](docs/DEPLOYMENT-NFS.md) | DevOps | Theory for NFS-fronted topologies |
| [docs/DEPLOYMENT-NFS-RUNBOOK.md](docs/DEPLOYMENT-NFS-RUNBOOK.md) | DevOps | Actionable deploy-time runbook for NFS-fronted nodes |
| [CHANGELOG.md](CHANGELOG.md) | Everyone | Milestone history and notable fixes |
| [AGENTS.md](AGENTS.md) | Engineers / AI agents | The single source of project memory and build guidance: non-negotiable invariants, build order, and the session protocol |

## Quick start (three-node mesh)

```sh
cargo build --release

# 1. On each node, generate its identity (prints the cert fingerprint to pin):
./target/release/replicored gen-cert --out-dir /etc/replicore --name node-a

# 2. Generate ONE cluster admin keypair (kept off the daemons; used to sign
#    membership changes):
./target/release/replicored gen-admin-key --out /secure/replicore-admin.key

# 3. Write each node's replicore.toml (see replicore.example.toml and
#    docs/CONFIGURATION.md), pinning every peer's fingerprint.

# 4. Run the daemon on each node:
./target/release/replicored run --config /etc/replicore/replicore.toml

# 5. Operate from any node:
./target/release/replicorectl status --all
./target/release/replicorectl members
```

See **[docs/DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md)** for the full
production procedure.

## Build, test, lint

```sh
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings   # must be clean
cargo fmt --all
```

## Emulated-WAN test rig

```sh
sudo modprobe sch_netem
sudo scripts/wan-testbed.sh up        # netns + tc netem: ~150ms RTT, ~1% loss
sudo scripts/wan-testbed.sh status
sudo scripts/wan-testbed.sh down
```

## Tech stack

Rust + **tokio**. Transport: **quinn** (QUIC) with **BBR** congestion control.
Hashing: **blake3**. Chunking: **fastcdc**. FS monitoring: **fanotify** (FID) +
periodic Merkle rescan as the correctness backstop. State: **rusqlite** (WAL).
Membership: SWIM-style gossip + a versioned roster. Serialization: **serde** +
versioned binary. Metrics: **prometheus**. Logging: **tracing**.

## Working on this repo with an AI agent

[`AGENTS.md`](AGENTS.md) is the **single source of project memory and build
guidance** for this repository — it carries the non-negotiable correctness
invariants, the highest-risk subsystems, the milestone build order and
definition-of-done, and the current build state. It is vendor-neutral; any coding
agent can load it.

- **Starting a session:** point the agent at `AGENTS.md` and have it read the
  file in full first, so it inherits the invariants (Section 2) as hard
  constraints and picks up the current milestone state (Section 6).
- **Closing a session:** ask the agent to update `AGENTS.md` — appending any new
  invariant, decision, or gotcha it learned and refreshing the current build
  state — so the next session inherits it. The file's own Section 5 ("Session
  Protocol") spells out both steps.
- Keep `AGENTS.md` factual and append-oriented; it is the handoff between
  sessions, not a scratchpad. There is no other agent-memory file in the repo.
