*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# AGENTS.md — Replicore

The single source of project memory and build guidance for **any** coding agent
or engineer working on this repository. It is vendor-neutral: load it at the
start of every session, treat Section 2 as hard constraints, and update Section 6
at the end of every session. There is no other agent-memory file.

---

## 1. Project purpose and tech stack

**Purpose.** Replicore is an agent-based, eventually-consistent, **multi-master**
file replication engine for LAN and WAN. One daemon (`replicored`) runs per node;
nodes form a dynamic, self-healing mesh; each node reads and writes its local
storage normally and the engine propagates every change to all peers **without
blocking local I/O**. Metadata replicates as a causally-ordered operation log;
file data replicates as content-addressed chunks; divergence heals via Merkle
anti-entropy; cluster membership is dynamic and admin-signed. The shipped
behavior is documented in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — build
toward that.

**Tech stack (locked — raise it for discussion before substituting).** Language
**Rust**, async runtime **tokio**. Transport is **quinn** (QUIC) with its native
**BBR** congestion control (a `quiche` BBR fallback was once considered but is
**not used** — quinn's BBR holds 80–83% utilization at 1% loss on the rig). Never
hand-roll a UDP reliability/congestion layer. Hashing is **blake3**; chunking is
**fastcdc**. Filesystem monitoring is **fanotify** (FID reporting) via `libc`,
backed by a periodic **Merkle rescan** that is the correctness backstop. State is
**rusqlite** (WAL) — chosen over redb. Membership is **SWIM-style gossip** plus a
versioned roster (no Raft). Serialization is **serde** + versioned binary;
metrics **prometheus**; logging **tracing**; the operator CLI is `replicorectl`
over a Unix domain socket.

---

## 2. THE NON-NEGOTIABLE INVARIANTS

Violating any of these is a **defect, not a style nit**. They are the guardrails
that caught real bugs across M1–M3. Each is binding; the italic line is what
breaks if it is violated. If a rule here cannot afford to be "mostly followed," it
is also enforced in CI / pre-commit — do not rely on prose alone.

### Replication core

1. **Causality comes from version vectors, never wall-clock time.** Wall-clock
   may only break ties between already-concurrent versions.
   *Breaks: a clock skew silently makes a newer write lose to an older one — silent data loss.*
2. **Apply is atomic:** stage in the destination directory → fsync → verify
   BLAKE3 against the manifest → `rename(2)` → fsync the parent. Never expose a
   partial or unverified file.
   *Breaks: readers observe a torn/unverified file; a crash mid-write exposes corruption.*
3. **Loop prevention requires BOTH** version-vector dedup **and**
   apply-suppression of the engine's own filesystem event. One alone is
   insufficient.
   *Breaks: the engine re-broadcasts its own applies and the mesh storms.*
4. **Tombstones, not hard deletes;** GC only after all peers acknowledge plus a
   safety window. A late write must never resurrect a deleted file.
   *Breaks: a delete fails to propagate, or a stale write revives deleted content.*
5. **Never trust network input.** No panics on malformed or hostile peer data;
   bound every buffer; reject path escapes.
   *Breaks: a crafted peer frame panics the node or overruns a buffer.*
6. **Production uses mutual TLS with a pinned peer-certificate allowlist.** The
   development-only "accept-any" certificate verifier must never be compiled into
   a production build.
   *Breaks: any host can join the data path and inject or read replicated data.*

### Conflict resolution & metadata

7. **There is exactly one write path to files — no third path.** Both the
   winner-apply and conflict-copy staging route through the single re-validated
   committing transaction (`resolve_rows`). A CI gate
   (`tests/write_path_gate.rs`) greps that nothing else writes the `files` table.
   *Breaks: an unguarded writer races the committing transaction → divergent or lost state.*
8. **Conflict resolution derives the winner from the maximal antichain of the
   path's history, never from pairwise contests.** Winner = max over
   `(kind_rank, content_hash, meta_hash)`.
   *Breaks: pairwise contests are non-confluent — different nodes pick different winners and never converge.*
9. **Conflict copies are derived locally (never emitted as ops) and named by a
   stable, node-agnostic key** (losing content hash + a durable metadata subset,
   excluding mtime/uid/gid); the synthetic copy version-vector is a pure function
   of the copy path.
   *Breaks: emitting copies as ops loops the mesh; node-local naming makes the same conflict produce different files per node.*
10. **The no-storm metadata law:** every captured `metadata::Meta` field must be
    node-independent or applied verbatim; `owner_policy` must be uniform across
    the mesh; apply order is content → xattrs → owner → mode → mtime, on the
    staged temp, before the publishing rename.
    *Breaks: a field a node cannot reproduce re-emits an op forever (a metadata storm); a non-uniform owner_policy churns ownership.*

### Cluster membership & control plane

11. **Intent config is human-owned; the roster is agent-owned.** The daemon
    **never writes** the intent file (`replicore.toml`); dynamically-learned
    membership lives in the separate agent-managed roster.
    *Breaks: the daemon clobbers an operator's file, or learned state leaks into human config.*
12. **Announcement is not authorization.** A peer enters the data path only after
    its certificate validates against the trust anchor; membership changes are
    admin-signed (signed client-side; the daemon never holds the admin secret).
    Being vouched-for by a peer is not trust.
    *Breaks: an unauthorized node joins the data path by merely announcing itself.*
13. **Config reload is atomic:** an invalid candidate is rejected and the running
    config is left untouched. Partial application is prohibited.
    *Breaks: a half-applied config leaves the daemon in an inconsistent state.*
14. **Membership converges, never diverges.** The roster is an epoch-versioned
    register (merge winner = `max(epoch, rank(kind), blake3(canonical bytes))`);
    the tie-break hashes canonical bytes, **never the signature**.
    *Breaks: concurrent add/remove from different nodes diverge and nodes disagree on the roster forever.*
15. **Join uses a version-vector frontier.** Bulk bootstrap and parallel live ops
    must compose with no lost or double-applied ops across the frontier; the live
    stream resumes from the post-reconcile resume map, not the pre-gate hello.
    *Breaks: writes at the bootstrap/live boundary are lost or double-applied.*

### Ordering rule that underpins the above

- **The reconcile gate:** a node never applies a peer's *live* ops before
  completing an anti-entropy session with that peer. Do not weaken this ordering.

---

## 3. The two highest-risk subsystems — review by hand, do not trust tests alone

1. **Version vectors + apply-suppression (M1)** — the causality and loop-control
   core. Plausible-looking code here causes silent corruption or mesh storms.
2. **Join frontier (M2.5)** — "keep syncing live writes while initial sync runs"
   loses or double-applies writes at the boundary if coded carelessly, and will
   not show up in a casual demo.

For these, and for the M3 conflict-decision and metadata-apply paths: **design
first** — propose a written plan and get human approval before writing code.

---

## 4. Build order, definition of done, and conventions

Build, test on the rig, and review each milestone before starting the next.

- **M0 — Spike (done, superseded).** Prove fanotify + QUIC + atomic apply
  compose: one-directional replication over QUIC.
- **M1 — Bidirectional correctness core.** Op-log, version vectors,
  apply-suppression, mutual TLS with pinned certs, local-change pipeline (ingest +
  authoritative scanner + watcher), atomic suppressed apply, convergence property
  tests, poison-op quarantine.
- **M2 — Mesh + self-healing.** FastCDC chunking + persistent content-addressed
  store, multi-source fetch, streamed atomic assembly, Merkle anti-entropy with
  the reconcile gate, peer registries + jittered reconnect, `/healthz`, transfer
  bounds. Protocol v2 (flag-day).
- **M2.5 — Cluster membership + management plane.** Admin trust primitives +
  `gen-admin-key`, admin-signed epoch-versioned membership with deterministic
  convergence, join via a version-vector frontier (protocol v3), intent/roster
  split, per-handshake dynamic TLS allowlist, SWIM roster gossip, `replicorectl`
  over a UDS. M2.5 precedes M3 deliberately, so hardening hardens a *dynamic*
  cluster.
- **M3 — Production hardening.** Deterministic confluent conflict resolution,
  file identity + renames, full POSIX metadata fidelity (protocol v4), fanotify
  FID watcher, QoS, Prometheus metrics, free-space guard, BBR, then a
  long-duration soak.
- **M4 — Single-copy serving (proposed).** Eliminate steady-state storage
  amplification: serve chunks from the live tree (reverse index + verify-on-read)
  instead of from a permanent hash-addressed CAS, so the CAS becomes a transient,
  ack-frontier-scoped working set and per-node footprint drops from ~2× to ~1× the
  dataset. Flag-day to protocol v5; touches the high-risk serve/fetch path, so
  design-first + full re-soak. Design: [docs/design-m4-single-copy-serving.md](docs/design-m4-single-copy-serving.md).

**Definition of Done (per milestone):** implemented + `cargo clippy --all-targets
-- -D warnings` clean + unit/property tests pass + the milestone integration test
passes on the emulated-WAN rig + the milestone exit criterion demonstrated.
Commit in logical units. When unsure about a correctness decision, **stop and
ask** rather than guess.

**Conventions.** Errors: `thiserror` for library enums, `anyhow` only at binary
boundaries. **No `unwrap`/`expect`/`panic!`** in non-test code except on a
documented, locally-proven invariant (with a `// SAFETY:`-style justification).
Prefer message-passing over shared `Mutex` state; `unsafe` needs a `// SAFETY:`
comment and review. Every fallible I/O path handles partial writes, short reads,
and disconnects. Correctness-critical logic (version vectors, conflict rules,
reconcile, apply, roster convergence, join frontier) **must** have property-based
tests.

**Commands.**
```sh
cargo build --release
cargo test                                  # NOTE: integration_wan + the m3 suite use the rig
cargo clippy --all-targets -- -D warnings   # MUST be clean before "done"
cargo fmt --all

# emulated-WAN rig (root + sch_netem on host) — owns /srv/replicore:
sudo scripts/wan-testbed.sh up | status | certs | run-a | run-b | run-c | down

# operator CLI (talks to the local daemon over a UDS):
replicorectl status [--all] [--json] | members | peers | lag | conflicts | transfers
replicorectl config validate|diff|reload <file>
replicorectl member add|remove <node> --admin-key <path>
replicorectl pause | resume | resync | bandwidth [set <global> <per_peer>]
```

---

## 5. SESSION PROTOCOL

**At session START:**
- Read this file fully before doing non-trivial work.
- Treat the Section 2 invariants as **hard constraints** on everything you do
  this session. If a task appears to require violating one, stop and raise it.
- Read Section 6 to inherit the current build/milestone state and any
  recently-learned gotchas.

**At session END:**
- Append to this file any new invariant, decision, or gotcha you learned, and
  update the current build/milestone state in Section 6.
- Keep it **factual and append-oriented**. Do not rewrite history or delete prior
  entries; add dated notes so the next session inherits an accurate record.
- This file is the handoff. If it is stale, the next session starts blind.

---

## 6. Current state (living section — update at session end)

**Milestone:** M3 (production hardening) **complete**, plus post-M3 remediation
(S1 meta-only conflict loss; S4 membership race + roster persist; S5 CAP_CHOWN
boot gate; S6 poison dir-op quarantine; atomic manifest persist; stable
metadata-subset conflict-copy naming — proven). Currently under **long-duration
soak validation** on the emulated-WAN rig.

**Protocol / wire:** flag-day **v4** (ALPN `replicore/4`). Merkle leaf =
`blake3(path ‖ 0x00 ‖ tombstone ‖ content_hash ‖ uuid ‖ meta_hash ‖ vv)`. Upgrade
the whole mesh as a unit; mixed-version meshes are refused at the handshake. DB
columns migrate at open (PRAGMA-guarded ALTERs); pre-v4 rows get UUIDs minted as a
pure function of the path (agrees across nodes).

**Settled decisions:** rusqlite over redb; quinn native BBR (the quiche fallback
is unnecessary and unused); renames are identity-lite (one op, two path-effects;
a concurrent write to the source resurrects it — modify wins); removed-node data
is RETAINED (drop policy deferred); `config reload` applies only the hot
peer/trust/bandwidth/reserve view — everything else is honestly
restart-required.

**Open seams (grep `SEAM(` in source):** refcounted CAS GC; cross-path rename
redirect; hardlinks-as-links; directory metadata / default ACLs on dirs; indirect
ping-req gossip; remote CONTROL over the mesh (only read-side `status --all` fans
out today); per-share encryption.

**Operational note:** a long soak owns the rig and `/srv/replicore` — do not run
the integration suite (`integration_wan`, `integration_m3`) or `scripts/*.sh`
while it is live; they contend for the rig flock. Unit/property tests on
`:memory:` are safe.
