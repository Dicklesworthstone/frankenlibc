# bd-2g7oyh.433 / Pass 151 exp10 focused gate

Date: 2026-06-16
Agent: BoldFalcon
Worker: ovh-a
Head: f62dbcc86efdf40cb3b327aa8d4fcdd3074e3a59
Status: no source change, focused gate collapsed

## Route Basis

Pass 148 broad routing on `ovh-a` showed a possible `exp10` residual:

- FrankenLibC p50/mean: `504.262 / 535.975 ns`
- host glibc p50/mean: `403.961 / 416.626 ns`

Prior no-retry families already include surface `exp10` table/Horner variants, a 1/64 residual table, and dispatch-screen/classifier ordering. A source edit was allowed only if a clean focused same-worker gate reproduced a material gap, and then only for a generated proof-carrying underlying `exp2`/range-reduction primitive.

## Focused Baseline

Clean detached worktree:

```text
/data/projects/.scratch/frankenlibc-pass151-exp10-20260616T2031
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass151-exp10-baseline-target-20260616T2031 \
CRITERION_HOME=/data/tmp/frankenlibc-pass151-exp10-baseline-criterion-20260616T2031 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'glibc_baseline_math/exp10' --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

The filter also matched `exp10f`; that extra row was not used as the `exp10` decision except as a sanity check.

Results:

| Impl | Criterion | p50/mean | p95/p99 |
| --- | ---: | ---: | ---: |
| FrankenLibC `exp10` | `[289.79 ns 289.98 ns 290.18 ns]` | `290.192 / 297.891 ns` | `301.533 / 391.000 ns` |
| host glibc `exp10` | `[286.74 ns 287.19 ns 287.63 ns]` | `287.814 / 291.122 ns` | `313.125 / 346.120 ns` |

The focused same-worker row collapsed to a small `1.008x` p50 and `1.023x` mean difference, not a profile-backed source target.

Extra sanity row:

- FrankenLibC `exp10f` p50/mean `228.747 / 229.483 ns`
- host glibc `exp10f` p50/mean `278.900 / 282.777 ns`

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

No source changed. The current compensated f64 `exp2` fast path remains active, and the existing 4-ULP/golden-output contracts are unchanged by construction.

Behavior proof is identity: floating-point routing, exact integer `powi` path, compensated `exp2` path, out-of-range `libm::exp10` fallback, RNG, allocation, errno, and locale behavior are unchanged.

## Next Route

Do not edit `exp10` from this focused evidence. Continue with a different current-head residual.
