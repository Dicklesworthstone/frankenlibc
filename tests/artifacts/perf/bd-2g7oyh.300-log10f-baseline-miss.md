# bd-2g7oyh.300 log10f focused baseline miss

Status: no-code rejected.
Date: 2026-06-09.
Agent: BoldFalcon.
Base commit: `95a7e8c4f54f252cf2b35c997820cf8ba77c5a2e`.

## Target

The pass-30 broad RCH profile on `ovh-a` showed a possible f32 log-family
residual:

- `log10f` FrankenLibC p50 `462.507 ns/op`, mean `419.068 ns/op`.
- `log10f` host glibc p50 `304.980 ns/op`, mean `337.735 ns/op`.

The focused target used Criterion through RCH:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_BUILD_SLOTS=3 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass30-log10f-baseline-20260609 cargo bench -j 2 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/log10f --noplot --sample-size 60 --warm-up-time 1 --measurement-time 4
```

## Focused Baseline

Same-worker focused baseline on `ovh-a`:

- FrankenLibC p50 `326.672 ns/op`, mean `329.064 ns/op`, p95 `339.228 ns/op`, p99 `381.000 ns/op`.
- Host glibc p50 `318.793 ns/op`, mean `345.811 ns/op`, p95 `449.455 ns/op`, p99 `454.248 ns/op`.

The broad profile gap collapsed to `1.025x` by p50, and FrankenLibC was faster
by mean. That is not a valid optimization target under the profile-backed gate.

## Behavior Proof

No source was edited. Ordering, tie-breaking, floating-point special-case
routing, rounding behavior, and RNG behavior are unchanged by construction.
Golden fixture content is unchanged because no code or fixture was modified.

## Verdict

NO-CODE REJECTED, Score `0.0`.

Next route: continue from the same broad profile with a focused `erf`/`erfc`
baseline. Do not route f32 log-family work through the previously rejected f64
intermediate path; if a focused `log10f` gap reappears, use a true f32-native
minimax/table primitive with ULP replay.
