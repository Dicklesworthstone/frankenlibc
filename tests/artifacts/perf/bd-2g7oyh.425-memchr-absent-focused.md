# bd-2g7oyh.425 memchr_absent focused no-code closeout

Date: 2026-06-15
Agent: BoldFalcon
Worker: RCH `ovh-a`
Base commit: `7ea7083ea`
Profile target ID: `bd-2g7oyh.425`

## Route

Pass 126 broad RCH routing on `ovh-a` selected
`glibc_baseline_memchr_absent/memchr_absent` as the largest clean string
residual not already faster than host:

- FrankenLibC broad p50/mean: `27.853/29.684 ns`
- host glibc broad p50/mean: `17.060/19.158 ns`

This lane was admissible only for a materially different generated-code or
backend-dispatch primitive. Prior no-retry families include panel-width changes,
wider folded blocks, indexed folded scans, SWAR word-group scans, and resolver
retuning.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-baseline CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-425-memchr-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Focused same-worker result:

- FrankenLibC Criterion interval: `[20.674 ns 20.799 ns 20.942 ns]`
- FrankenLibC p50/mean: `20.620/22.018 ns`
- host glibc Criterion interval: `[19.002 ns 19.162 ns 19.337 ns]`
- host glibc p50/mean: `19.045/22.744 ns`

The broad gap did not reproduce materially: p50 was only `1.08x` behind host
and mean flipped slightly in FrankenLibC's favor.

## Candidate Screen

No source edit was made. A new `memchr_absent` source lever would have repeated
an exhausted family unless the focused gate showed a material p50 and mean gap.

## Behavior Proof

Production source is unchanged. First-match ordering, absent-result semantics,
null/length handling, golden outputs, FP, RNG, allocation, errno, and locale
behavior are unchanged by construction.

## Verdict

NO-CODE REJECTED. Score: `0.0`.

## Reroute

Do not return to `memchr_absent` without a fresh focused same-worker material
gap and a non-repeat generated-code/backend-dispatch primitive. The next pass
should focus a different reproduced residual from the same current-head broad
profile.
