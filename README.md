# Replicore

A production-grade, multi-master file replication engine for LAN and WAN. One
agent per node; nodes form a dynamic mesh; each node reads/writes local storage
normally and the engine propagates changes without blocking local I/O. Metadata
replicates as a causally-ordered operation log; file data replicates as
content-addressed chunks; divergence heals via Merkle anti-entropy.

This repository is the single source of truth: specification, milestone build
prompts, the working M0 spike, and the test rig — all version-aligned.

## Layout

```
Replicore/
├── README.md                 # this file
├── CLAUDE.md                 # project memory for Claude Code (loaded every session)
├── Cargo.toml, Cargo.lock    # M0 spike build (pinned, reproducible)
├── src/                      # M0 spike: watcher + QUIC transport + atomic apply
│   ├── main.rs  proto.rs  watch.rs  net.rs  apply.rs
├── docs/
│   ├── RSD.md                        # requirements + development plan (v1.0)
│   ├── RSD-addendum-membership.md    # v1.1: cluster membership + control plane
│   ├── design-guide.md               # architecture & build guide
│   ├── DEPLOYMENT-NFS.md             # operator rules for NFS-fronted nodes
│   └── M0-spike.md                   # what M0 does / omits, mapped to requirements
├── prompts/                  # one brief per milestone, for Claude Code
│   ├── README.md
│   ├── M1-mvp-bidirectional.md
│   ├── M2-mesh-selfheal.md
│   ├── M2.5-cluster-membership.md
│   └── M3-production-hardening.md
└── scripts/
    └── wan-testbed.sh        # two-node + emulated-WAN (netns + tc netem) rig
```

## Status

**M0 spike — complete and verified.** Compiles on stock Ubuntu `cargo` (Rust
1.75) and replicates files one-directionally over QUIC with atomic apply. It is
the proof that fanotify + QUIC + atomic apply compose; it is **not** Replicore
yet — the correctness core (op-log, version vectors, conflict handling, mesh,
membership) lands in the milestones below.

## Milestone order

```
M1  bidirectional correctness core (op-log, version vectors, apply-suppression, mTLS)
M2  mesh + self-healing (chunking, multi-source fetch, Merkle anti-entropy)
M2.5 cluster membership + management plane (zero-downtime add/remove, replicorectl)
M3  production hardening (conflict rules, metadata fidelity, QoS, metrics, soak)
```

M2.5 precedes M3 deliberately, so hardening hardens a dynamic cluster.

## Build & run the M0 spike

```sh
cargo build --release
# localhost smoke test:
mkdir -p /tmp/a /tmp/b
./target/release/replicored sink   --listen 127.0.0.1:7000 --dir /tmp/b &
./target/release/replicored source --peer 127.0.0.1:7000   --dir /tmp/a &
sleep 2; echo hello > /tmp/a/t.txt; sleep 2
cmp /tmp/a/t.txt /tmp/b/t.txt && echo "M0 OK"
```

The `Cargo.toml` pins `time` and `blake3` to specific versions so the build is
reproducible on both the older apt toolchain (Rust 1.75) and current Rust. On a
current toolchain you may relax them (`time` unpinned, `blake3 = "1"`), but the
pinned set is the configuration that has actually been compiled and tested —
leave it as-is unless you have a reason to change it.

## Two-node + emulated-WAN testing

```sh
sudo modprobe sch_netem
sudo scripts/wan-testbed.sh up        # ~150ms RTT, ~1% loss (tunable via env)
sudo scripts/wan-testbed.sh status
sudo scripts/wan-testbed.sh down
```

## Developing with Claude Code

Open a Claude Code session at this repo root (so `CLAUDE.md` loads). Do **not**
run `/init` — `CLAUDE.md` is already curated. Work one milestone per session in
Plan Mode: paste the milestone prompt from `prompts/`, review the plan against
its "Mandated design" section, let it implement and test, then complete the
prompt's "Reviewer checklist" yourself before committing. `/clear` between
milestones. See `docs/` for the full spec and the human-review gates.

## The two highest-risk subsystems

When the agent reaches them, review by hand rather than trusting tests:

1. **Version vectors + apply-suppression (M1)** — the causality and loop-control
   core; plausible-looking code here causes silent corruption or mesh storms.
2. **Join frontier (M2.5)** — "keep syncing live writes while initial sync runs"
   loses or double-applies writes at the boundary if coded carelessly, and won't
   show up in a casual demo.
