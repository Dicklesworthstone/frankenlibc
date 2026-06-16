# bd-2g7oyh.443 erfc focused no-code closeout

Date: 2026-06-16
Agent: BoldFalcon
Worker: RCH `ovh-a`
Base commit: `09026f0b4`
Profile target: `glibc_baseline_math/erfc`

## Route

Pass 148 broad routing on `ovh-a` still showed an apparent `erfc` residual on
the current-head math sweep:

- FrankenLibC p50/mean: `1124.625/1027.994 ns`
- host glibc p50/mean: `686.272/698.632 ns`

Prior erfc history includes the kept exact profile-grid tail route and a later
focused collapse, so the broad row was treated as routing evidence only.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a
RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass153-erfc-baseline-target-20260616T2042
CRITERION_HOME=/data/tmp/frankenlibc-pass153-erfc-baseline-criterion-20260616T2042
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_math/erfc --noplot --sample-size 80 --warm-up-time 1
--measurement-time 3
```

Focused same-worker result:

| row | impl | Criterion interval | p50 ns | mean ns |
| --- | --- | --- | ---: | ---: |
| `erfc` | FrankenLibC | `[707.83 ns 712.71 ns 719.10 ns]` | 706.938 | 727.895 |
| `erfc` | host glibc | `[679.56 ns 682.50 ns 686.60 ns]` | 685.258 | 733.703 |

The focused gap collapsed again: FrankenLibC was only about `3.2%` slower by
p50 and slightly faster by mean.

## Candidate Screen

No source edit was made. The focused result does not justify another
special-function source lever, and the next admissible erfc attempt remains a
new proof-carrying range-split or approximation primitive only after a fresh
material focused gap.

## Isomorphism

Production source is unchanged. Floating-point behavior, special-case ordering,
errno/fenv side effects, RNG, allocation, locale, and golden fixture outputs are
unchanged by construction.

## Verdict

NO-CODE REJECTED. Score: `0.0`.

Next route: continue with another current-head residual. Do not retry erfc
without a fresh material focused same-worker gap and a different proof-carrying
primitive from the kept profile-grid route.
