# bd-2g7oyh.396 memcpy_4096 focused gate

Date: 2026-06-13
Agent: BoldFalcon
Worker: `vmi1227854`
Status: NO-CODE REJECTED

## Target

Current broad profile on `vmi1227854` selected `memcpy_4096`:

| row | FrankenLibC p50 ns | host p50 ns | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: |
| broad `memcpy_4096` | 40.812 | 30.495 | 42.555 | 33.920 |

Prior no-retry families for this lane:

- exact full-slice branch before the clamped prefix-copy path
- exact 4096-byte safe portable-SIMD tiled copy

Any source edit therefore required a materially different codegen, alignment,
or no-overlap primitive.

## Focused Gate

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd396-memcpy4096-baseline-target-20260613T2356
CRITERION_HOME=/data/tmp/frankenlibc-bd396-memcpy4096-baseline-criterion-20260613T2356
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memcpy_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 4
```

RCH selected `vmi1227854`. Remote duration: `233.5s`.

| implementation | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[26.743 ns 27.077 ns 27.457 ns]` | 27.867 | 29.766 | 31.938 | 70.000 |
| host glibc | `[27.696 ns 28.187 ns 28.739 ns]` | 27.028 | 28.612 | 32.078 | 61.000 |

## Isomorphism

No source code changed.

- Copied prefix count `min(n, dest.len(), src.len())`: unchanged by
  construction.
- Destination tail behavior, non-overlap `memcpy` contract, return value, and
  byte order: unchanged by construction.
- Ordering/tie-breaking are not involved.
- Floating point and RNG are not involved.
- Golden outputs are unchanged by construction.

`git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs
crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` passed before this
artifact was written.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused same-worker broad gap collapsed to a p50 ratio of `1.031x`
(`0.839 ns` absolute) and mean ratio of `1.040x` (`1.154 ns` absolute). That is
below the edit gate, especially for a lane with prior rejected copy-panel and
full-slice branch families.

Next route: do not touch `memcpy_4096` without a fresh material focused gap and
a disassembly-backed primitive that changes compiler lowering, alignment
dispatch, or ABI-level no-overlap classification.
