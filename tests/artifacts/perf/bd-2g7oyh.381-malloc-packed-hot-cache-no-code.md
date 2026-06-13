# bd-2g7oyh.381 malloc packed hot-cache/slab no-code closeout

Date: 2026-06-13
Agent: BoldFalcon
Current commit: `f8636147`

## Target

`bd-2g7oyh.381` proposed a packed hot-cache/slab state-machine only if a
fresh focused same-worker baseline reproduced a material `malloc_free_64` and
`malloc_free_256` residual after the kept `bd-2g7oyh.380` lazy-accounting
commit.

Alien-graveyard grounding for the candidate family was §7.9 Modern Allocator
Design (mimalloc/TLSF/slab): profile allocation fast-path hit rate before
changing internals, then prove alignment, non-overlap, zero-size, and oversized
request behavior across all allocation paths. No source lever was attempted
because the required focused gate collapsed.

## Remote Baseline Attempt

The first same-worker attempt on `vmi1153651` did not execute:

```text
RCH-E324 dependency preflight blocked remote execution; RCH_REQUIRE_REMOTE=1
refused local fallback.
```

This run is routing/tooling context only, not benchmark evidence.

## Focused Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

RCH selected worker: `ovh-a` (requested `vmi1227854`)

Rows:

- `malloc_free_64/frankenlibc_core_state`: Criterion `[4.6425 ns 4.9022 ns 5.2349 ns]`, p50 `4.561 ns`, p95 `7.500 ns`, p99 `25.000 ns`, mean `5.735 ns`
- `malloc_free_64/host_glibc`: Criterion `[4.4230 ns 4.4493 ns 4.4777 ns]`, p50 `4.519 ns`, p95 `7.500 ns`, p99 `15.000 ns`, mean `5.255 ns`
- `malloc_free_256/frankenlibc_core_state`: Criterion `[4.3951 ns 4.4319 ns 4.4695 ns]`, p50 `4.315 ns`, p95 `5.344 ns`, p99 `20.000 ns`, mean `4.817 ns`
- `malloc_free_256/host_glibc`: Criterion `[4.5515 ns 4.5785 ns 4.6143 ns]`, p50 `4.557 ns`, p95 `11.250 ns`, p99 `25.000 ns`, mean `6.160 ns`
- `malloc_free_large/frankenlibc_core_state`: Criterion `[7.6129 ns 7.8536 ns 8.0586 ns]`, p50 `7.601 ns`, p95 `10.000 ns`, p99 `25.000 ns`, mean `8.043 ns`
- `malloc_free_large/host_glibc`: Criterion `[36.326 ns 36.659 ns 36.922 ns]`, p50 `36.912 ns`, p95 `48.260 ns`, p99 `92.859 ns`, mean `42.167 ns`

## Verdict

REJECTED no-code. The profile-backed allocator residual did not reproduce on
the current source:

- `malloc_free_64` was effectively tied on p50 (`4.561 ns` FrankenLibC vs
  `4.519 ns` host) with only a small middle-estimate deficit.
- `malloc_free_256` was faster than host on Criterion middle, p50, p95, p99,
  and mean.
- The large guard was already much faster than host.

No allocator source was changed, so behavior is unchanged by construction.
Ordering, LIFO/central-bin/elimination tie-breaking, public counters, pointer
zero/null behavior, floating point, and RNG were not touched.

Next route: reprofile broad residuals after `f8636147`; only return to malloc
if a fresh focused gate reproduces a material residual on the current source.
