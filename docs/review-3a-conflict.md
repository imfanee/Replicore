# Review 3a — antichain conflict resolution (the deferred M3 review diff)

Scope: `src/conflict.rs` (`antichain` :157, `plan_candidates` :200,
`copy_path_for` :324, `copy_vv` :352), `src/oplog.rs` (`ops_as_candidates`
:1259, `resolve_rows` :1331, the coverage branch :1356–:1365). Analysis of
the code as committed at `cfd3754`; no changes made.

**Verdict: PASS.** No correctness defect found. Two invariant dependencies
are named below (§1.3, §2.4) — both hold today and both would be silent
landmines if a future change broke them; they belong in any future touch of
these files.

---

## 1. The maximal-antichain computation is order-independent

### 1.1 What the scan computes

`antichain` (`conflict.rs:157`) is a single-pass dominance-elimination scan:
each candidate `c` is compared against every kept element; `c` is skipped if
any kept element dominates-or-equals it (`:163`), kept elements strictly
dominated by `c` are removed (`:164–166`), mutual concurrency keeps both
(`:167`).

**Claim: `keep` ends as exactly the set of maximal elements of the input,
for every input order.**

- *No non-maximal element survives.* Let `x` be dominated by some candidate
  `y`. If `y` (or any transitive dominator of `x`) is in `keep` when `x`
  arrives, `x` is skipped at `:163`. If every dominator of `x` was itself
  removed before `x` arrived, each removal was by a strict dominator;
  strict VV dominance is transitive (`tests/vv_proptest.rs::
  dominance_transitive`), so the removal chain terminates at a maximal
  element that dominates `x` and that nothing can remove — it is present
  when `x` arrives, and `x` is skipped. If `y` arrives *after* `x`, `y`'s
  inner loop finds `x` and removes it (`:164`).
- *Every maximal element survives.* A maximal `m` is never skipped (skipping
  needs a kept dominator-or-equal; no dominator exists — for the Equal case
  see §1.3) and never removed (removal needs a strict dominator).

So membership in `keep` is a property of the candidate **set**, not the
scan order.

### 1.2 ≥3 mutually concurrent candidates

With all pairs `Concurrent`, the inner loop only ever executes `i += 1`:
nothing is skipped, nothing is removed, all candidates survive in arrival
order — then `keep.sort_by_key(|v| Reverse(v.key()))` (`:172`) normalizes
that residual arrival order away. The winner is `keep[0] = max(key)` and
the loser list (`plan_candidates` `:233` iterates `maximal[1..]` in sorted
order), so **every downstream artifact — winner row, copy order, copy
chain — is a pure function of the candidate set**. The unit test
`plan_is_order_independent` pins a 3-way mixed case; the proptest hammers
it at scale.

### 1.3 Invariant dependency: equal VVs ⇒ identical content

`Ord3::Dominated | Ord3::Equal => continue` (`:163`) keeps the **first** of
two equal-VV candidates. This is order-independent only because two
versions with equal VVs carry identical `(kind, content, meta)`:

- two ops never share a VV: an op's VV is its predecessor state plus an
  increment of its own origin's component (`oplog.rs::append_local`,
  `append_local_rename`), so same-origin ops are strictly ordered and
  different-origin ops differ in the incremented component;
- the row equals an op's VV only when it materialized exactly that op (or a
  reconcile leaf copied from a row satisfying the same induction), carrying
  that op's content;
- duplicates of the *same* op (redelivery, the explicit `remote` candidate
  vs its own oplog record at `resolve_rows:1354`) are byte-identical by
  construction (`op_id` keyed).

This is the same "Eq coincides with causal equality" contract `vv.rs`
states in its header. **If a future change ever lets two distinct contents
share a VV, the first-wins dedup becomes an ordering hazard** — that change
must not happen (it would break far more than this scan).

---

## 2. The coverage branch (`oplog.rs:1356–:1365`) — the hardest question

```rust
let mut candidates = ops_as_candidates(&tx, path)?;   // every op touching path
candidates.push(remote.clone());
let mut coverage = VV::new();
for c in &candidates { coverage.merge(&c.vv); }
match coverage.compare(&local_row.vv) {
    Dominates | Equal => {}                       // row excluded
    _ => candidates.push(Version::from_row(&local_row)),  // row included
}
```

### 2.1 Per-node determinism: the branch cannot flip on arrival order

The branch condition is `merge(vvs of ops∪remote)` vs `row.vv` — both pure
functions of the node's current **state** (the op set in `oplog`, the
`files` row, the remote being resolved). Arrival order influenced how that
state was *reached*, not what it *is*: `ops_as_candidates` (`:1259`) is an
unordered `WHERE path = ?1 OR path_old = ?1` scan, and `antichain`
normalizes the rest (§1). Two evaluations on identical state take the same
branch and derive the same plan. The committing re-check makes this
operational: the plan is re-derived **inside the transaction** against the
state being committed against, and any mismatch with the staged plan
returns `Stale` (`:1373`) — nothing commits against a state the derivation
didn't see.

A stronger property falls out of the *exclusion* arm: when the ops fully
cover the row, the row is **ignored**, so two nodes whose rows transiently
differ (different delivery orders mid-flight) but whose op sets agree
derive the *identical* plan from the op set alone. The branch doesn't just
tolerate order variance — in the common case it erases it.

### 2.2 Cross-node asymmetric knowledge: where plans CAN differ

Two nodes with **different op subsets** (a join-bootstrapped node holds
rows without history; the frontier handoff deliberately never backfills old
ops; quarantined ops are recorded but their VVs never merged into the row)
can derive different plans for the same conflict. This is real and
unavoidable — the resolution can only be a function of what a node knows.
The question is whether it heals or deadlocks like the pairwise bug.

### 2.3 The healing lemma (verified in code, exercised by tests)

**Lemma: every committed resolution row's VV ⊇ `row.vv ∪ remote.vv`.**
`plan_candidates` merges **all** candidates' VVs into the winner row
(`conflict.rs:204–207`), not just the antichain's. In the include arm the
row is a candidate, so plan-VV ⊇ row.vv directly; in the exclude arm the
branch condition itself guarantees `coverage ⊇ row.vv`, and plan-VV =
coverage. `remote` is always a candidate (`:1354`). ∎

Consequences:

- **Rows never regress**: re-resolution commits a VV ⊇ the current row's,
  so per-path row VVs are monotone. (This is also what makes redelivery a
  no-op: the merged row dominates the recorded op → `NotConcurrent(Ignore)`,
  pinned by `tests/conflict_race.rs`.)
- **Full-vs-partial heals by dominance**: a full-history node's candidate
  VVs include everything a partial node's row derives from, so its plan VV
  ⊇ the partial node's. When their contents differ (the full node saw a
  contender the partial node never will), reconcile presents the dominating
  row to the partial node as a plain `Apply` — adoption, not a tie. The
  equal-VV/different-content deadlock that killed the pairwise design
  **cannot form**, because the side with more knowledge has a strictly (or
  equally, with then-equal content per §1.3) larger VV, never an equal VV
  with different content.
- **Partial-vs-partial converges by re-resolution**: if two partial nodes'
  plan VVs are incomparable, each reconcile presents the other's row as a
  new remote candidate; candidate sets grow monotonically toward the union;
  `max(key)` over a growing set is monotone in the set order, so repeated
  exchange reaches the fixed point `max(union)` — the lattice argument the
  proptest executes literally (`tests/conflict_proptest.rs::
  reconcile_to_fixpoint`, byte-identity asserted at the fixed point at up
  to 20 000 cases).

Targeted executable witnesses: `tests/partial_history_resolution.rs`
(added with this review) constructs the bootstrap case directly — a node
holding the row with an **empty oplog** (the include arm, proven via
`op_count == 0`) resolves identically to a full-history node in the
symmetric case, and is healed by dominance in the asymmetric case.

### 2.4 Invariant dependency: rows derive from replicated history

The dominance argument assumes a partial node's row state derives from
*some* replicated history (applies, resolutions, reconcile leaves) — true
for every write path (`tests/write_path_gate.rs` enforces that no other
write path exists). A hypothetical future path that writes `files` rows
with fabricated VV components outside replicated history would break the
"full ⊇ partial" inclusion. The grep-gate is the guard.

### 2.5 The quarantined-op subtlety

Quarantined ops are inserted into `oplog` but their VVs are deliberately
never merged into the row (`apply_remote`, downgrade comment). They thus
appear as candidates on nodes that hold them and are absent on
join-bootstrapped nodes forever. Same shape as §2.3: the holder's plan VV
strictly contains the quarantined components; heals by dominance. A
quarantined op *winning* a resolution re-attempts its content fetch through
the staging path — if still unfetchable, staging fails permanently and the
resolution is deferred to reconcile (`net.rs::resolve_concurrent_at`,
permanent-error arm), never silently dropped.

---

## 3. `max` algebra and copy-chain termination

- **Total order**: `Version::key` (`conflict.rs:101`) is a lexicographic
  tuple `(u8, [u8;32], [u8;32])` — `Ord` on tuples of `Ord` types is a
  total order, hence `max` over it is associative, commutative, and
  idempotent; "winner = max over the set" is well-defined independent of
  grouping or order, which is the algebraic core of §1–§2.
- **Copy-chain termination**: each collision link moves from `cp` to
  `copy_path_for(cp, loser_hash, loser_meta_hash)` — a pure function of
  (previous name, losing content, losing metadata), so the chain itself is
  deterministic; *(naming gained the meta component with the S1 remediation:
  meta-only losers are preserved under their own derived names)*;
  the explicit depth counter refuses at `MAX_COPY_DEPTH = 4` (`:245–248`)
  with `Ok(None)` → `ResolveOutcome::Unresolvable` (`oplog.rs:1370`), which
  every caller handles as detected-but-unresolved (logged, retried by the
  next reconcile session). Termination is by construction, not by hope; the
  refusal is deterministic too (same chain ⇒ same refusal on every node).
- One self-collision case is handled before the lookup: two losers with
  identical content hash map to the same copy path; the
  `rows.iter().find(|r| r.path == cp)` check (`:251–254`) breaks the chain
  with a `debug_assert` that the contents agree (they must — the name is a
  pure function of the content hash).

## 4. Reviewer-checklist cross-reference

- Commit-path: resolution mutates `files` only inside `resolve_rows`'s
  transaction, plan re-derived under the same transaction (`:1366–:1369`),
  staged-vs-derived equality required (`:1373`). `write_path_gate` greps
  that no other path exists. ✓
- Stale-decision on the conflict path: `tests/conflict_race.rs` — a local
  write between plan and commit returns `Stale`, nothing committed. ✓
- Determinism inputs: no wall-clock, no node id, no op `(origin, seq)` in
  `key`, `copy_path_for`, or `copy_vv` — all are functions of replicated
  content/metadata/paths. ✓ *(Post-S1: copy names = f(content_hash ‖
  meta_hash); metadata is replicated state, so cross-node determinism is
  unchanged.)*
