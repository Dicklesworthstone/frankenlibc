# bd-2g7oyh.479 runtime design stack candidates measured reject

Date: 2026-06-19
Agent: BlackThrush / cod-a
Status: measured reject; source reverted

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
`design_choose_plan` p50 `1747.061 ns -> 432.283 ns`. This bead tested whether
the remaining fixed-size `Vec<(Probe, f64, u64)>` candidate list could be
profitably moved to a stack array.

## Lever

Rejected lever: replace the heap candidate container with a fixed stack array:

- `ProbeCandidate { probe, score, cost_ns }`
- `[ProbeCandidate::EMPTY; Probe::COUNT]`
- initialized prefix slice sorted with the same stable `sort_by` comparator

This is a cache/layout lever only. It preserves the existing determinant-lemma
gain calculation, risk gates, budget accounting, probe costs, and probe order.

## Negative-Evidence Ledger

- Verdict: **LOSS/REVERT**. The stack array did not improve p50 and regressed
  custom mean and tails on the same worker.
- Retry predicate: only retry candidate-container layout if the candidate count
  grows substantially, allocation shows up again in a fresh profile, or the
  sort can be removed entirely. Do not retry another fixed `[ProbeCandidate; 17]`
  shape.
- Do not retry `bd-wvxyzs`: determinant-lemma/logdet work is already a closed
  keep.
- Do not retry `bd-x9lb9g`: SOS quarantine polynomial evaluation is already a
  closed keep.
- Do not mutate runtime controller cadence or risk thresholds in this bead.

## Behavior Guard

The code-first attempt added `candidate_sort_preserves_equal_score_probe_order`
to prove equal candidate scores retained the same stable order as the previous
`Vec::sort_by` path. Because the measured perf gate failed, the helper and that
test were reverted with the stack-array source. Existing design tests continue
to guard budget, risk, probe inclusion, submodular selection, and
determinant-lemma gain equivalence.

## Same-Worker Benchmark Verdict

Command shape:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-bd479-{baseline,candidate} \
CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-a/criterion-bd479-* \
RCH_REQUIRE_REMOTE=1 rch exec -- \
cargo bench -p frankenlibc-bench --bench runtime_math_kernels_bench -- \
runtime_math_kernels/design_choose_plan/strict --noplot \
--sample-size 80 --warm-up-time 1 --measurement-time 3
```

Decisive comparable rows were both remote `hz2`:

| Source | Worker | Criterion mean interval | p50 | p95 | p99 | custom mean | Verdict |
|---|---|---:|---:|---:|---:|---:|---|
| Baseline `46ea5e33` heap `Vec` | `hz2` | `[369.52 ns, 372.32 ns, 375.56 ns]` | 367.188 ns | 418.648 ns | 438.791 ns | 372.889 ns | baseline |
| Candidate `6340e047` stack array | `hz2` | `[369.72 ns, 374.93 ns, 381.75 ns]` | 370.153 ns | 1058.839 ns | 1356.561 ns | 471.061 ns | reject |

Ratios candidate/baseline:

- p50: `1.008x` slower, neutral/slight loss.
- Criterion mean midpoint: `1.007x` slower, neutral.
- custom mean: `1.263x` slower, loss.
- p95: `2.529x` slower, loss.
- p99: `3.092x` slower, loss.

Non-decisive worker-selection note: the first candidate rerun selected remote
`hz1` despite a preferred `hz2` environment and produced p50 `771.485 ns`.
That row is recorded only as non-comparable routing noise.

## Revert Action

Restored the heap-backed candidate list:

```rust
let mut candidates: Vec<(Probe, f64, u64)> = Vec::with_capacity(Probe::COUNT);
...
candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
```

The source now matches the measured faster baseline shape. The stack
`ProbeCandidate` struct, prefix-slice sort helper, and equal-score helper test
were removed as part of the revert.

## Validation

Passed:

```bash
rustfmt --check --edition 2024 crates/frankenlibc-membrane/src/runtime_math/design.rs
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-local cargo check -p frankenlibc-membrane --lib
git diff --check -- crates/frankenlibc-membrane/src/runtime_math/design.rs tests/artifacts/perf/bd-2g7oyh.479-runtime-design-stack-candidates.md docs/RELEASE_READINESS_SCORECARD.md .beads/issues.jsonl
```

Blocked by pre-existing external packaging issue:

```bash
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p frankenlibc-membrane runtime_math::design::tests -- --nocapture
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p frankenlibc-membrane --lib runtime_math::design::tests -- --nocapture
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-local cargo check --workspace --all-targets
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a-local cargo clippy --workspace --all-targets -- -D warnings
```

All four failed before this module's test assertions because
`asupersync-conformance 0.3.4` on crates.io is missing
`artifacts/conformance_registry_contract_v1.json` and
`src/raptorq/rfc6330_systematic_index_table.inc`. Workspace
`cargo fmt --check` remains blocked by broad pre-existing formatting drift in
ABI/core generated math, iconv tables, pwd/stdio/wide tests, and related files.
