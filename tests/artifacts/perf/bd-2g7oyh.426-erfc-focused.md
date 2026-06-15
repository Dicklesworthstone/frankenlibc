# bd-2g7oyh.426 erfc focused no-code closeout

Date: 2026-06-15
Agent: BoldFalcon
Worker: RCH `ovh-a`
Base commit: `679c7d542`
Profile target ID: `bd-2g7oyh.426`

## Route

Pass 126 broad RCH routing on `ovh-a` showed a possible
`glibc_baseline_math/erfc` residual:

- FrankenLibC broad p50/mean: `1112.826/1043.831 ns`
- host glibc broad p50/mean: `696.754/801.204 ns`

The lane had recent profile-grid history, so a focused same-worker gate was
required before any source edit.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-426-erfc-baseline CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-426-erfc-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/erfc --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Focused same-worker result:

- FrankenLibC Criterion interval: `[696.47 ns 698.41 ns 700.21 ns]`
- FrankenLibC p50/mean: `701.732/702.823 ns`
- host glibc Criterion interval: `[678.53 ns 680.60 ns 682.62 ns]`
- host glibc p50/mean: `680.948/683.580 ns`

The broad residual did not reproduce materially. Focused p50 and mean were only
about `3%` behind host.

## Candidate Screen

No source edit was made. The focused gap was too small to justify another
special-function source lever, especially given prior erfc profile-grid
screening.

## Behavior Proof

Production source is unchanged. Floating-point value behavior, special-case
ordering, errno/fenv behavior, RNG, allocation, locale, and existing math
fixture outputs are unchanged by construction.

## Verdict

NO-CODE REJECTED. Score: `0.0`.

## Reroute

Do not return to `erfc` without a fresh focused same-worker material gap and a
new proof-carrying approximation/range-split primitive. The next pass should
focus a different residual from the current-head broad profile.
