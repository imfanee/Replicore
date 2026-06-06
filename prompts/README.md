# Milestone prompts for Claude Code

Each file here is a self-contained brief for one Replicore milestone. Use them
one at a time, in order, in a Claude Code session opened at the repo root (so
`CLAUDE.md` loads automatically).

## How to run a milestone

1. Start fresh: `cd <repo> && claude`. Confirm `CLAUDE.md` is loaded.
2. Paste the milestone prompt (e.g. the contents of `M1-mvp-bidirectional.md`).
3. Let it run in **Plan Mode first** — review the plan against the "Mandated
   design" section before approving any code.
4. When it reports done, work through the **Reviewer checklist** yourself. This
   is the human gate; the agent's tests passing is necessary but not sufficient
   for distributed-systems correctness.
5. Only then move to the next milestone. Use `/clear` between milestones to keep
   the context window clean.

## Why one milestone per session

These build on each other but each is a large, coherent unit. Running them
separately keeps the agent's context focused, makes the diff reviewable, and
maps each commit cleanly to an RSD milestone and its exit criteria.

## The reviewer checklists matter most

The agent is good at breadth and the build/test loop. The places it can produce
plausible-but-wrong code are exactly the correctness-critical subsystems
(causality, conflict resolution, anti-entropy, atomic apply, loop suppression).
The checklists target those. Do not skip them.
