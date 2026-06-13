# bd-2g7oyh.391 memmove_4096 focused copy-codegen gate

Date: 2026-06-13
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Post-`bd-2g7oyh.389` broad non-math profile on RCH `vmi1227854` showed a
fresh `memmove_4096` residual:

| row | FrankenLibC p50 ns | host p50 ns | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: |
| broad `memmove_4096` | 35.831 | 27.725 | 37.441 | 29.024 |

Prior no-ship families are explicit:

- exact 4096 safe-SIMD copy panels under `bd-2g7oyh.346`;
- general safe portable-SIMD copy panels under `bd-2g7oyh.304`;
- inline-only `memmove` hinting under `bd-2g7oyh.157`;
- related exact 4096 `memcpy` copy-panel/full-slice branchbacks.

Any source edit therefore required a materially different codegen, alignment, or
no-overlap primitive. No source edit was attempted in this pass.

## Focused RCH Gate

Command:

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd391-memmove-focused-baseline-target-20260613T2145 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memmove_4096 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `[33.701 ns 34.193 ns 34.727 ns]` | 34.521 | 34.938 | 37.016 | 50.000 |
| host glibc | `[26.673 ns 27.185 ns 27.776 ns]` | 27.575 | 31.903 | 34.207 | 70.000 |

The focused p50 gap reproduced at `1.252x` / `6.946 ns`; mean gap was smaller
at `1.095x` / `3.035 ns`.

## Isomorphism

No source code changed.

- Prefix-copy length, bounded `n`, overlap behavior, destination suffix
  preservation, byte order, and return value are unchanged by construction.
- Ordering/tie-breaking do not apply.
- Floating point and RNG are not involved.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The target is real enough to keep in the routing table, but every obvious
source-level copy-panel or inline lever is already rejected. Shipping another
manual safe-SIMD copy loop would repeat the wrong family.

Next route: build or reuse an RCH-compatible assembly/codegen extraction
artifact for safe string/memory kernels, then return only with a primitive that
changes generated copy lowering materially: alignment-aware safe-slice dispatch,
array-reference copy lowering with assembly proof, or an ABI-level raw-pointer
classification lane that preserves the safe core contract.
