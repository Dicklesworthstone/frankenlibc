# bd-2g7oyh.401 memcpy_4096 focused gate

Date: 2026-06-14
Agent: BoldFalcon
Worker: `vmi1227854`
Status: NO-CODE REJECTED

## Routing Evidence

Fresh broad `glibc_baseline_bench` on current head selected `memcpy_4096` as
the strongest residual row:

| row | impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| broad `memcpy_4096` | FrankenLibC | 54.283 | 57.590 | 75.191 | 130.000 |
| broad `memcpy_4096` | host glibc | 30.654 | 33.360 | 37.500 | 131.000 |

Command:

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-broad-refresh-target-20260614T0540
CRITERION_HOME=/data/tmp/frankenlibc-broad-refresh-criterion-20260614T0540
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
--noplot --sample-size 20 --warm-up-time 1 --measurement-time 2
```

## Focused Gate

```text
RCH_BUILD_SLOTS=1 RCH_WORKERS=vmi1227854 RCH_WORKER=vmi1227854
RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec --
env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd401-memcpy4096-baseline-target-20260614T0554
CRITERION_HOME=/data/tmp/frankenlibc-bd401-memcpy4096-baseline-criterion-20260614T0554
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memcpy_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 4
```

Focused result:

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `[30.638 ns 30.999 ns 31.389 ns]` | 31.935 | 33.355 | 35.000 | 70.000 |
| host glibc | `[28.061 ns 28.520 ns 29.076 ns]` | 29.049 | 32.652 | 35.000 | 60.000 |

## Isomorphism

No source code changed.

- Copied byte count `min(n, dest.len(), src.len())`: unchanged by construction.
- Destination byte order, destination tail behavior, and return count: unchanged.
- Ordering, tie-breaking, floating point, and RNG behavior: not involved.
- Golden outputs: unchanged by construction.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused same-worker gate collapsed the broad gap to a p50 ratio of `1.099x`
and mean ratio of `1.022x`. This is below the source-edit gate for a lane with
prior rejected full-slice, portable-SIMD tile, and copy-codegen families.

Next route: reprofile and choose a different reproduced residual. Do not touch
`memcpy_4096` again without a fresh material focused same-worker gap and a
disassembly-backed primitive that changes copy lowering or alignment behavior.
