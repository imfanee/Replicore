*Architected & Developed By:- Faisal Hanif | imfanee@gmail.com*

# Production Acceptance Record — Replicore (NFS-fronted IVR deployment)

**Status: DRAFT — NOT FINAL until SOAK PASS is recorded in the sign-off below.**
Scope: the three DRC/Marseille-class nodes fronting LAN app servers over NFS,
running the IVR write-once recording workload. This record captures the
acceptance decision for each reviewed risk (R-01…R-07) against the stated
deployment assumptions (A1–A5).

> Items tagged **[DRAFT — RECONSTRUCTED; CONFIRM]** were rebuilt from the project
> docs (the M3 review records and the NFS deployment guides) because no prior
> register survived in the repo. Confirm or correct their wording; the *decisions*
> for R-01/R-02/R-03/R-06/R-07 are as directed.

---

## Deployment assumptions (A1–A5)

These are the conditions the acceptance below is predicated on. If any ceases to
hold, the affected R-items must be re-evaluated.

- **A1 — Disjoint per-site writable namespace.** Each site writes ONLY its own
  subtree (`/rec/dc-a` at site A, etc.); the other subtrees are exported
  read-only. No shared, mutable, lock-coordinated directory is exported across
  sites. *(Source: DEPLOYMENT-NFS.md §Hard constraints 1; runbook R1.)*
  **[DRAFT — RECONSTRUCTED; CONFIRM]**
- **A2 — IVR write-once workload.** Writes are site-local, uniquely named, and
  consumed at their own site; no read-your-writes across sites, no cross-site lock
  coordination, no hardlinks in the recorded data. *(Source: DEPLOYMENT-NFS.md
  §Fit for the IVR use case.)* **[DRAFT — RECONSTRUCTED; CONFIRM]**
- **A3 — Consistent identity.** uid/gid identical across all nodes and clients
  (matching numeric IDs or NFSv4 idmapping with one shared domain); `owner_policy`
  uniform mesh-wide; under `numeric` the daemon runs with `CAP_CHOWN` (it refuses
  to boot otherwise). *(Source: runbook R4; review-3c-metadata.md.)*
  **[DRAFT — RECONSTRUCTED; CONFIRM]**
- **A4 — Durable, local storage path.** Exports use `sync` (or apps fsync before
  treating a write as committed); each node's `share_dir` is local block-backed
  storage; the agent never watches an NFS *client* mount. *(Source: runbook
  R3/R6.)* **[DRAFT — RECONSTRUCTED; CONFIRM]**
- **A5 — Single protocol version.** The whole mesh runs one flag-day protocol
  version (`replicore/4`); upgrades roll the entire mesh as a unit. *(Source:
  AGENTS.md §6; ARCHITECTURE.md §13.)* **[DRAFT — RECONSTRUCTED; CONFIRM]**

---

## Risk decisions (R-01 … R-07)

### R-01 — Deterministic, clock-free conflict-copy coalescing — **ACCEPT**

**Risk.** When concurrent losers of a conflict share byte-identical content and
differ only in skew-prone metadata (mtime/uid/gid), they coalesce to a single
conflict copy rather than producing one copy per metadata variant.

**Decision: ACCEPT.** This is the intended behavior. Conflict resolution is
deterministic and derives entirely from version vectors and content/durable-meta
hashes — never wall-clock time — so every node computes the same winner and the
same set of copies. **Content is never lost**: the surviving copy always stores
the loser's full metadata in its row; only redundant near-duplicate *files* under
pure timestamp/owner skew are avoided.

**Considered and rejected:** a wall-clock / "latest mtime wins" winner rule. It is
rejected because it **violates the VV-only-causality invariant** (Invariant 1):
clock skew between nodes would let an older write beat a newer one and would
diverge nodes that observed events in different orders. Determinism must come from
causality, not timestamps.

**Optional future work (feature, not a fix, not a blocker):** preserve the
discarded metadata snapshots of coalesced losers in the surviving copy's xattrs,
so an operator can recover the alternate ownership/mtime views. This adds fidelity
without changing the determinism guarantee. *(Source: review-copy-naming.md;
notes-m3-followups.md §2.)*

### R-02 — `owner_policy=numeric` under NFS `root_squash` — **VERIFY-THEN-MITIGATE → likely Accept-with-verification**

**Risk.** Root-owned writes arriving from NFS clients are squashed by the node's
`nfsd` before the agent observes them; with `owner_policy=numeric` the agent then
replicates the squashed ownership.

**Verdict (code-grounded read-only investigation): DEPENDS ON X**, where **X =
"does the IVR application (or any NFS client) write files as root (uid 0) into an
exported subtree?"** The question decomposes into two distinct claims, and the
code lets us separate them:

1. **The dangerous op-storm residual → NOT PRESENT (closed in code, independent
   of X).** `src/main.rs:79–89` refuses to boot under `owner_policy = "numeric"`
   without `CAP_CHOWN` (`bail!`). The ping-pong/op-storm residual described in
   `review-3c-metadata.md` requires EPERM-on-apply, which requires *no* CAP_CHOWN
   — unreachable under the mandated config. With CAP_CHOWN, `apply_meta`'s
   `lchown(meta.uid, meta.gid)` (`src/metadata.rs:340`) succeeds for *any* target
   uid including `nobody`/65534 — no EPERM, no skip, no ping-pong.

2. **The ownership-fidelity squash (root → nobody before capture) → real
   mechanism, fires only if X is true.** The intended exports set `root_squash`
   on all three export lines (`DEPLOYMENT-NFS-RUNBOOK.md:135/138/139`), with no
   `anonuid` override (→ default 65534). `root_squash` is an `nfsd`-layer remap
   applied **before** the byte reaches local disk, so it affects **only** writes
   performed as root; non-root uids pass through unchanged. `Meta::capture` under
   `Numeric` reads `st.uid()/st.gid()` from local disk
   (`src/metadata.rs:211`) — i.e. the **already-squashed** owner; the agent
   provably never sees uid 0. So if a client writes a root-owned file it lands as
   `nobody` before capture and replicates as `nobody`. **No divergence or
   data-loss even when it fires:** the squash is deterministic and per-server, and
   under A1 only one site writes a given path, so every peer applies the same
   ownership and content is intact — a fidelity gap, not a correctness bug.

**Decision: VERIFY-THEN-MITIGATE.**
- **If X is false** (IVR recorder writes as a non-root service account — the
  expected case under A2): the squash never engages, captured ownership is
  faithful, and **R-02 downgrades to Accept-with-verification — no code fix, the
  current soak continues.** Record the writer uid and the per-export `root_squash`
  setting as the verification evidence.
- **If X is true** (root-owned NFS-client writes genuinely occur): this is **not
  fixable by an agent code change** — the squash is upstream of the local write,
  so no capture-time code can recover uid 0. The remedy is at the **export layer**
  (`no_root_squash` for the trusted writer, or an `anonuid` mapping) or
  operational. A soak restart on a fixed commit is warranted **only** if you elect
  a capture-side pinning change; the dangerous storm residual stays closed (1)
  regardless.

**Verification action:** confirm X by checking the uid the IVR recorder writes as,
and the per-export squash setting. Expected resolution given the documented
non-root write-once workload: **Accept-with-verification, no fix, soak continues.**
*(Sources: `src/main.rs:79–89` boot gate; `src/metadata.rs:211` capture / `:340`
lchown; `DEPLOYMENT-NFS-RUNBOOK.md` R4 + exports; `review-3c-metadata.md` residual.)*

### R-03 — Hardlinks not preserved as links — **ACCEPT (schedule M4)**

**Risk.** A hardlinked file replicates as independent content-identical copies,
not as linked inodes; link identity is not preserved across the mesh.

**Decision: ACCEPT** for the IVR write-once-media workload, which does not
hardlink (A2). **Schedule hardlink-as-link fidelity as future M4 work** — it is
not a pre-production blocker.

**Considered and rejected:** "mitigate now." Rejected because it means **building
an as-yet-unbuilt subsystem** (storm-free hardlink grouping; the design is
sketched in `metadata.rs` and the node-local dev/ino exclusion is deliberate) for
a workload that never exercises it. *(Source: review-3c-metadata.md §2 supporting
invariants; AGENTS.md §6 open seams.)*

### R-04 — Directory metadata / default ACLs on directories not replicated — **ACCEPT** **[DRAFT — RECONSTRUCTED; CONFIRM]**

**Risk (reconstructed).** Directories carry no op-log row, so directory mode,
ownership, and **default (inheritable) POSIX ACLs on directories** are not
replicated — the documented dir-metadata SEAM. File-level ACLs ride as xattrs and
DO round-trip.

**Decision: ACCEPT.** The IVR workload writes files into pre-provisioned directory
trees that are created and permissioned by deployment automation at each site, not
by replication; directory-level ACL propagation is not required for the workload.
Revisit with R-03 under M4 dir-lifecycle work. *(Source: review-3c-metadata.md §3,
line 133 "default ACLs on directories remain the documented dir-meta SEAM.")*

### R-05 — Crash-recovery scanner re-attribution — **ACCEPT** **[DRAFT — RECONSTRUCTED; CONFIRM]**

**Risk (reconstructed).** A node killed mid-apply (`kill -9` after a staged
`rename` but before the op commits, or during manifest persist) could re-observe
the orphaned-but-correct file as a fresh local write, clobber content, or wedge.

**Decision: ACCEPT — verified deterministic.** A fully-committed file re-observed
is a no-op; an orphaned-but-correct file re-attributes to exactly **one bounded
op**, never clobbers content, and converges byte-identically with the redelivered
op (zero loss; op count reaches a fixed point). The related partial-manifest
crash-wedge was found and fixed (atomic persist + self-healing read). Pinned by
`tests/crash_reattribution.rs` and `tests/manifest_crash.rs`. *(Source:
notes-m3-followups.md §3 and §4.)*

### R-06 — External xattr/ACL fidelity cross-check — **MITIGATE POST-SOAK**

**Risk.** Replicore's own metadata round-trip is verified by internal
hash-equality (`tests/metadata_fidelity.rs`), but there is no **independent,
external** confirmation (e.g. `getfattr`/`getfacl` byte-comparison across nodes)
that replicated xattrs/ACLs match on disk.

**Decision: MITIGATE POST-SOAK.** Add an external `getfattr` cross-check across the
three nodes as a verification step. **Deferred until the soak completes** because
it touches the rig / `/srv/replicore`, which the running soak owns. This is a
verification addition, not an engine change. *(Source: review-3c-metadata.md §3.)*

### R-07 — Detection latency for NFS-client writes (`scan_interval_secs = 10`) — **ACCEPT (decided)**

**Risk.** fanotify is best-effort for `nfsd`-originated writes; the Merkle rescan
is the authoritative detector, so NFS-client-write propagation latency ≈ rescan
interval + WAN lag, not real-time.

**Decision: ACCEPT.** `scan_interval_secs = 10` is the decided value: a 10 s
detection floor is within the IVR workload's tolerance (write-once recordings,
site-local consumption — A2), and the consistency window is documented for
operators. *(Source: runbook R2 + config table; DEPLOYMENT-NFS.md §Hard
constraints 2.)*

---

## R-02 finding (Task-1 read-only investigation)

**Question.** Do the intended exports use `root_squash` in a way that would cause
root-owned NFS-client writes to land squashed before the agent captures them?

**Method.** Read-only review of the export configuration and ownership policy in
`docs/DEPLOYMENT-NFS-RUNBOOK.md` (recommended `/etc/exports`, R4) and
`docs/DEPLOYMENT-NFS.md`, **plus the source itself**: the capture/apply ownership
handling in `src/metadata.rs` (`capture` at `:211`, `apply_meta` lchown at `:340`)
and the `CAP_CHOWN` boot gate in `src/main.rs:79–89`, cross-referenced with
`docs/review-3c-metadata.md`. No code or config changed; the rig was not touched.
See the R-02 decision above for the two-claim decomposition (storm residual closed
by the boot gate; fidelity squash depends on X).

**Finding — TRIGGER PRESENT AT CONFIG LAYER, EFFECT DEPENDS ON WORKLOAD:**

1. The recommended exports set **`root_squash` on every export line** (runbook
   `/etc/exports`, lines for `/rec/dc-{a,b,c}`), and `owner_policy = "numeric"`
   is the recommended/default policy (replicates observed uid/gid).
2. Under `root_squash`, the node's `nfsd` remaps an NFS-client write performed as
   **root (uid 0)** to `nobody:nogroup` (anonuid/anongid) **before** the bytes are
   written to local disk. The agent's authoritative scanner therefore captures the
   already-squashed ownership and replicates `nobody`, never uid 0. No agent-side
   code can recover ownership discarded upstream of the local write.
3. **Only root-owned client writes are affected.** `root_squash` is a no-op for
   non-root uids — they pass through unchanged. The documented IVR workload (A2)
   writes recordings as a service/application account, not root, so under the
   intended workload **R-02 does not fire**.
4. **No divergence or data loss in any case.** The squash is deterministic and
   per-server; under A1 only one site writes a given path, so every peer applies
   the same squashed ownership. Content is intact. The historical
   `owner_policy=numeric` op-storm corner requires *no* `CAP_CHOWN`, which the boot
   gate (A3) refuses — so it is not reachable under the mandated config.

**Plain verdict:** **DEPENDS-ON-X**, X = "does any client write root-owned files
into an exported subtree?" Config trigger present; behavioral trigger absent for a
non-root IVR writer. **Action for the deployment:** confirm the IVR writer's uid
and the per-export `root_squash` setting. If the writer is non-root →
Accept-with-verification (no code change). If root-owned writes are genuinely
required → R-02's "mitigate post-soak" path applies, at the export layer or via
capture-side pinning.

---

## Sign-off

This record is **NOT FINAL** until the row below is completed. The current 7-day
soak must report **PASS** against its stop-conditions (no unbounded op growth, no
copy proliferation beyond threshold, no convergence-timeout / wedge, lag within
bound) before production acceptance is granted.

| Gate | Required | Status |
|---|---|---|
| 7-day soak verdict | **PASS** | ⬜ pending (soak running) |
| R-02 trigger verification (writer uid / export squash) | recorded | ⬜ pending |
| A1–A5 assumptions confirmed for the live deployment | confirmed | ⬜ pending |
| R-06 external getfattr cross-check (post-soak) | scheduled | ⬜ pending (post-soak) |

- Accepted risks at draft time: **R-01, R-03, R-04, R-05, R-07.**
- Conditional: **R-02** (verify-then-mitigate), **R-06** (mitigate post-soak).

**Acceptance authority:** ______________________  **Date:** ____________
**Soak verdict reference:** ______________________
