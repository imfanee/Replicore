# M3 follow-up notes (for decision — no code changes here)

## 1. BBR is the active congestion controller (confirmed)

`Engine::build_endpoint` sets it unconditionally on the shared
`TransportConfig`, so every QUIC connection (inbound and outbound) uses it:

```
src/net.rs:653
transport.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
```

There is no config knob and no fallback branch — it is not negotiated, not
conditional on the WAN profile. This is what carries NFR-P6 (≥80% link
utilization at 1% loss): loss-based Cubic measured 66–83% and flapped the
gate; BBR holds 80–83% across runs (evidence in the M3-3f commit and
`tests/integration_m3.rs::nfr_p6_*`). The CLAUDE.md "quiche BBR fallback"
note is therefore moot — the native quinn BBR is in use.

## 2. Conflict-copy names include mtime — soak-watch item + a tradeoff for you

### What the code does today

`conflict::copy_path_for(path, loser_content_hash, loser_meta_hash)` derives
the copy name from `blake3(content_hash ‖ meta_hash)[..8]`
(`src/conflict.rs:362`). `meta_hash = blake3(bincode(Meta))`
(`src/metadata.rs:117`), and `Meta` includes `mtime_s` + `mtime_ns`
(`:86–87`). So the copy name is a function of the loser's **content AND its
full metadata, including mtime**.

This was deliberate: it is the S1 fix. Two concurrent **metadata-only**
losers of the same bytes (e.g. different xattrs/owner/mode) must be
preserved as *distinct* snapshots, so they need distinct names — content
alone would collide them and silently drop one (the FR-303 violation S1
closed).

### The watch item

Because mtime is in the name, two nodes that lose **the same bytes under
different mtimes** mint **different** copy names. Metadata skew that changes
mtime without changing bytes — clock differences between nodes, `touch`,
editors that rewrite-in-place, backup/restore — can therefore produce
*multiple* conflict copies of byte-identical content. Under sustained skew
this is copy proliferation.

**Soak-watch**: the soak's copy-bloat stop-condition (`copies/live > 0.5`,
or +50 copies/hour) is the tripwire. If a real deployment shows copy counts
climbing without genuine content conflicts, this naming is the first
suspect.

### The tradeoff (your decision — NOT changed)

- **Current (content ‖ meta naming)**: never silently drops a divergent
  *metadata* snapshot (S1-safe); cost is potential copy proliferation under
  pure metadata/mtime skew.
- **Content-only naming**: one copy per losing *content* (coalesces
  mtime-only variants), at the cost of dropping the divergent-metadata
  snapshot of a loser — i.e. reopening a narrowed form of the S1 class
  (metadata-only loss, this time only between two *losers* of one
  resolution that share bytes but differ in metadata).

A middle option exists if proliferation proves real: name by
`content ‖ hash(stable-meta-subset)` where the subset excludes mtime (keep
mode/owner/xattrs, drop the timestamp). That preserves "different *durable*
metadata ⇒ different copy" while coalescing pure mtime skew. It is a
behavior change to a determinism-critical, cross-node-agreed function, so
it needs its own proptest pass — hence deferred to your call, not bundled
here.

Recommendation: leave as-is until the soak (or a deployment) shows actual
copy proliferation; if it does, prefer the mtime-excluded middle option
over full content-only (it keeps the S1 guarantee for durable metadata).

## 3. integration_wan findings 1 & 2 — verdict: rig-contention artifacts

Both QA failures were reproduced and diagnosed (task report has the full
trace):

- **Clean isolated rig**: combined `integration_wan --ignored` passed
  **15/15**. Neither finding reproduces from the tests' own writes.
- **Deliberate contention**: re-running the kill-loop test with a background
  writer scribbling `/srv/replicore/a/{prompts,recordings}` (exactly what
  the orphaned soak does) **reproduced Finding 2's exact assertion** ("op
  counts kept growing after the kill loop") — the external files were
  legitimately ingested by A during the quiescence window.
- **Finding 1's `prompts/menu.txt`** is a path NO `integration_wan` test
  writes; it is a soak-only path. The QA ran the suite while the one-week
  soak was alive; `setup()` tore down the soak's netns (the soak's recorded
  `node-a-exited-unexpectedly` verdict) and `rm`'d `DIR_A`, but the soak
  *script* kept re-creating `prompts/menu.txt` with changing content in the
  dir the test asserted on → `got≠expected`.

Root cause: the soak and the rig tests shared one host rig with only an
**in-process** `RIG_LOCK`. Fixes (test/tooling, not product):
- a **cross-process flock** on `/srv/replicore/.rig.lock`, acquired
  non-blocking by both `setup()` and `soak.sh` — a second rig process now
  fails LOUD instead of corrupting a shared run;
- the soak gates traffic writes on daemon liveness (cannot scribble a dir
  whose rig vanished);
- the two op-count "storm" guards now assert the TRUE invariant — op counts
  reach a **fixed point** (poll-until-stable) rather than being identical at
  two arbitrary instants 8 s apart, which is robust to a bounded
  crash-recovery re-attribution op that may still be settling at a sample.

Neither finding was a product bug. The real product *class* they pointed at
— crash-recovery scanner re-attribution / false-delete / stale-write-clobber
— is now pinned deterministically by `tests/crash_reattribution.rs`: a
fully-committed file re-observed is a no-op; an orphaned-but-correct file
(crash after rename, before commit) re-attributes to ONE bounded op, never
clobbers content, and converges byte-identically with the redelivered op
(zero loss, op count reaches a fixed point).

## 4. A real bug the 15× clean loop surfaced: partial-manifest wedge (FIXED)

Running the combined suite 15× clean (to confirm findings 1–2 don't recur)
turned up a genuine, separate product bug at 1/10–1/15: a node killed -9
during the receiver's manifest persist left a partial manifest, and
`manifest_for` then returned a hard `Corrupt` on every read — the node
wedged in a permanent reconnect loop and never re-converged (the
`kill_during` convergence timeout). The standalone `put_manifest` path was
non-atomic (separate autocommit statements). Fixed: atomic persist +
self-healing read (commit `36022fa`, `tests/manifest_crash.rs`); 1/10 wedge
→ 12/12 pass. This is the kind of crash-injection bug the QA findings
were adjacent to — found by treating the nondeterministic failure as real
and looping hard, exactly as instructed.
