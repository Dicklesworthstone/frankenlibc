# bd-2g7oyh.390 malloc_free_64 focused allocator gate

Date: 2026-06-13
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Post-`bd-2g7oyh.389` broad non-math profile on RCH `vmi1227854` showed a
fresh allocator residual:

| row | FrankenLibC p50 ns | host p50 ns | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: |
| broad `malloc_free_64` | 6.076 | 3.562 | 7.505 | 5.112 |

The allocator lane has extensive prior history. Recent no-retry families
include exact-size/cache shortcuts, Trace lifecycle gates, fixed magazine/plain
storage swaps, certificate/log micro-specialization, hot-slot metadata tweaks,
lazy-accounting retunes, and bitmap-only hot-slot representation changes.

The only admissible source route would have been a deeper allocator primitive:
segregated slab/LIFO refill or intrusive per-size-class hot-list layout with
lazy materialized observability and exact lifecycle/golden preservation.

## Focused Baseline Attempts

Two initial RCH attempts with `RCH_REQUIRE_REMOTE=1` refused local fallback and
produced no usable evidence:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 ...
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_malloc_free_(64|256|large)'
```

```text
RCH_REQUIRE_REMOTE=1 ...
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_malloc_free_(64|256|large)'
```

Both returned:

```text
[RCH] local (no admissible workers: critical_pressure=1,insufficient_slots=2,hard_preflight=9)
[RCH] remote required; refusing local fallback (no worker assigned)
```

## Focused RCH Gate

The valid focused gate used an explicit one-slot remote request:

```text
RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd390-malloc-focused-baseline-target-20260613T2144 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_malloc_free_64 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `[5.8978 ns 6.1722 ns 6.3740 ns]` | 4.989 | 6.027 | 7.500 | 25.000 |
| host glibc | `[3.8424 ns 3.9830 ns 4.1575 ns]` | 4.238 | 11.317 | 5.704 | 170.000 |

## Isomorphism

No source code changed.

- Allocation size-class mapping, LIFO ordering, hot-slot behavior, central-bin
  spill order, large-allocation fast slot, and elimination semantics are
  unchanged by construction.
- `active_count`, `total_allocated`, lifecycle logs, and trace/certificate rows
  are unchanged by construction.
- Floating point and RNG are not involved.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused p50 gap collapsed to `1.177x` with only `0.751 ns` absolute gap, and
the mean comparison reversed in FrankenLibC's favor because host glibc had a
tail outlier. That is below the edit gate for a heavily mined allocator lane.

Next route: reprofile or continue from the current broad table with a different
focused residual. Only return to allocator with a material focused same-worker
gap and a true slab/LIFO or intrusive-list primitive, not another hot-slot
metadata or observability micro-lever.
