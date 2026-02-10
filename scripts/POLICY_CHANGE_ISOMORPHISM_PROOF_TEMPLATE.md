# Policy-Change Isomorphism Proof (Template)

This template is required for **any runtime policy change** that can affect:
- `RuntimeMathKernel::decide(...)` routing (`Fast` vs `Full`)
- `MembraneAction` selection (`Allow | FullValidate | Repair | Deny`)
- healing strategy selection in hardened mode
- kernel snapshot golden outputs
- perf-gate metrics

Fill this out in the bead comments and/or the PR description.

## Change Summary

- Change:
- Motivation:
- Bead:
- Mode(s) affected: `strict | hardened | both`

## Behavioral Isomorphism

- Ordering preserved? `yes/no`
  - Why:
- Tie-breaking unchanged? `yes/no`
  - Why:
- Floating-point identical / avoided? `identical / avoided / changed`
  - Why:
- RNG/determinism preserved? `yes/no`
  - Why:
- Any new cadence gating? `yes/no`
  - Interval(s) + rationale:
- Any new caching/atomics? `yes/no`
  - Invariants:

## Golden Evidence

- Snapshot gate:
  - `scripts/snapshot_gate.sh`: `PASS/FAIL`
- If snapshots intentionally changed:
  - `scripts/update_golden_snapshots.sh` executed: `yes/no`
  - `tests/runtime_math/golden/sha256sums.txt` verified: `yes/no`
  - Brief explanation of diff:

## Perf Evidence

- Perf gate:
  - `scripts/perf_gate.sh`: `PASS/FAIL`
- Bench deltas (p50/p95/p99):
  - `runtime_math/decide/<mode>`:
  - `runtime_math/observe_fast/<mode>`:
  - `runtime_math/decide_observe/<mode>`:
  - `membrane/validate_known/<mode>`:

## Safety / Risk Bound Rationale (If Applicable)

- What unsafe/failure class is being reduced?
- Which runtime-math kernels justify the change?
  - Include at least 3 math families for major milestones (see `AGENTS.md`).

## Rollback Plan

- `git revert <sha>` (or equivalent):
- Expected rollback effects:

