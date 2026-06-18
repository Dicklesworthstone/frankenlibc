# bd-2g7oyh.479 runtime design stack candidates

Date: 2026-06-18
Agent: BlackThrush / cod-b
Status: code-first batch-test pending

## Target

- Bead: `bd-2g7oyh.479`
- Source: `crates/frankenlibc-membrane/src/runtime_math/design.rs`
- Benchmark target: `frankenlibc-bench` `runtime_math_kernels_bench`
  `runtime_math_kernels/design_choose_plan/strict`
- Downstream guard: `runtime_math_bench` `observe_fast`

## Routing Evidence

The runtime math profile pack
`tests/artifacts/perf/20260601-perf-26a69011/runtime_math_bench.summary.md`
ranked `design_choose_plan` as the largest per-kernel runtime-math cost:

- `design_choose_plan`: p50 `1008.7 ns`, p95 `1131.7 ns`
- `observe_fast`: p50 `1953.0 ns`
- `decide`: p50 `98.9 ns`

Closed bead `bd-wvxyzs` kept the matrix-determinant-lemma route and reported
`design_choose_plan` p50 `1747.061 ns -> 432.283 ns`. The current source still
paid a per-call heap `Vec<(Probe, f64, u64)>` allocation and sort for a fixed
`Probe::COUNT == 17` candidate set.

## Lever

Replace the heap candidate container with a fixed stack array:

- `ProbeCandidate { probe, score, cost_ns }`
- `[ProbeCandidate::EMPTY; Probe::COUNT]`
- initialized prefix slice sorted with the same stable `sort_by` comparator

This is a cache/layout lever only. It preserves the existing determinant-lemma
gain calculation, risk gates, budget accounting, probe costs, and probe order.

## Negative-Evidence Ledger

- Do not retry `bd-wvxyzs`: determinant-lemma/logdet work is already a closed
  keep.
- Do not retry `bd-x9lb9g`: SOS quarantine polynomial evaluation is already a
  closed keep.
- Do not mutate runtime controller cadence or risk thresholds in this bead.
- This attempt only removes fixed-size candidate heap/container overhead left
  after the prior keeps.

## Behavior Guard

Added `candidate_sort_preserves_equal_score_probe_order` to prove that equal
candidate scores retain the same stable order as the previous `Vec::sort_by`
path. Existing design tests continue to guard budget, risk, probe inclusion,
submodular selection, and determinant-lemma gain equivalence.

## Validation

Campaign instruction for this batch permits only:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-membrane
```

Benchmark and full conformance verdict: pending batch test.
