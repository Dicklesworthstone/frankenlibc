# bd-2g7oyh.434 / Pass 152 erfc focused gate

Date: 2026-06-16
Agent: BoldFalcon
Worker: ovh-a
Head: 5bbf0563c9fd544c244edf6b7a19cda3609caf34
Status: no source change, focused gate collapsed

## Route Basis

Pass 148 broad routing on `ovh-a` showed a possible `erfc` residual:

- FrankenLibC p50/mean: `1124.625 / 1027.994 ns`
- host glibc p50/mean: `686.272 / 698.632 ns`

Prior `bd-2g7oyh.426` focused `erfc` on `ovh-a` had already collapsed to about a 3% gap. This pass required a fresh clean same-worker gate before any source edit; a source lever would need a generated minimax/rational/range-split primitive, not another retune of the existing profile-grid tail.

## Focused Baseline

Clean detached worktree:

```text
/data/projects/.scratch/frankenlibc-pass152-erfc-20260616T2036
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass152-erfc-baseline-target-20260616T2036 \
CRITERION_HOME=/data/tmp/frankenlibc-pass152-erfc-baseline-criterion-20260616T2036 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'^glibc_baseline_math/erfc/' --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

| Impl | Criterion | p50/mean | p95/p99 |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[686.47 ns 691.04 ns 697.44 ns]` | `689.295 / 695.235 ns` | `731.000 / 771.883 ns` |
| host glibc | `[662.53 ns 664.31 ns 666.52 ns]` | `664.020 / 670.548 ns` | `691.299 / 802.323 ns` |

The focused same-worker row collapsed to a small `1.038x` p50 and `1.037x` mean gap.

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

No source changed. The existing `erfc` profile-grid tail and libm fallback remain active, and the existing math golden/differential contracts are unchanged by construction.

Behavior proof is identity: floating-point value behavior, special-case ordering, errno/fenv behavior, RNG, allocation, locale, and existing fixture outputs are unchanged.

## Next Route

Do not edit `erfc` from this focused evidence. Continue with a different current-head residual.
