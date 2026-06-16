# bd-2g7oyh.432 / Pass 150 exp10f focused gate

Date: 2026-06-16
Agent: BoldFalcon
Worker: ovh-a
Head: 88499267000d9822c29757b572b73d6da7bd8c22
Status: no source change, focused gate collapsed/reversed

## Route Basis

Pass 148 broad routing on `ovh-a` showed a possible `exp10f` residual:

- FrankenLibC p50/mean: `381.091 / 382.223 ns`
- host glibc p50/mean: `332.390 / 334.713 ns`

Prior no-retry families already cover surface `exp10f` table/profile-band edits and f32 `exp2f(x * LOG2_10)` ULP-nudge variants. A source edit was allowed only if a clean focused same-worker gate reproduced a material gap, and then only for a generated underlying `exp2`/range-reduction primitive.

## Focused Baseline

Clean detached worktree:

```text
/data/projects/.scratch/frankenlibc-pass150-exp10f-20260616T2025
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass150-exp10f-baseline-target-20260616T2025 \
CRITERION_HOME=/data/tmp/frankenlibc-pass150-exp10f-baseline-criterion-20260616T2025 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'glibc_baseline_math/exp10f' --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

| Impl | Criterion | p50/mean | p95/p99 |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[237.12 ns 238.80 ns 240.99 ns]` | `239.633 / 246.042 ns` | `299.538 / 313.869 ns` |
| host glibc | `[308.00 ns 316.81 ns 329.12 ns]` | `320.550 / 321.909 ns` | `339.284 / 655.920 ns` |

The focused same-worker gate did not reproduce the broad residual. FrankenLibC is faster by `1.338x` p50 and `1.308x` mean.

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

No source changed. The current `exp10f` table/residual profile-band kernel remains the active implementation, and the existing 4-ULP contract plus golden SHA are unchanged by construction.

Behavior proof is identity: floating-point routing, special cases, exact integer `powi` path, profile-band table/residual path, fallback f64 `exp2` path, RNG, allocation, errno, and locale behavior are unchanged.

## Next Route

Do not edit `exp10f` from this worker's focused evidence. Continue with a different current-head residual; if returning to decimal exponentials, run a fresh focused `exp10` gate and require a generated underlying `exp2`/range-reduction primitive before source work.
