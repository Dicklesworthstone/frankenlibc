# bd-2g7oyh.314 memmove_4096 focused baseline gate

Date: 2026-06-10
Agent: BoldFalcon
Scope: no source edit

## Target

`bd-2g7oyh.314` was created after the pass-39 `memchr_absent` closeout
routed to the next unowned measured residual, `memmove_4096`.

Prior context: pass 33 already rejected/restored the safe portable-SIMD
copy-panel family for core `memmove`, so this bead required a fresh focused
same-worker baseline before any new source edit. A kept candidate would have
needed a materially different primitive, not another SIMD copy-panel loop.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd314-memmove-baseline-target-20260610T052155Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd314-memmove-baseline-criterion-20260610T052155Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memmove_4096 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 32.918 | 36.460 | 39.983 | 70.000 |
| host glibc | 29.801 | 36.251 | 40.250 | 65.000 |

The focused p50 gap is `1.10x` with a `3.117 ns` absolute delta, and the
means are effectively tied (`1.006x`). This is below the Score>=2.0 edit gate,
especially after the prior rejected safe-SIMD copy-panel family.

## Isomorphism

No source changed. Overlap direction, byte order, exact copied prefix,
bounded `n` behavior, floating-point state, and RNG state are unchanged by
construction. Golden output SHA is unchanged by construction.

## Verdict

No-code rejected, Score `0.0`.

Next route: reprofile and attack a different measured residual. If
`memmove_4096` reappears with a material focused same-worker gap, use a
disassembly/codegen-backed safe-Rust copy-shape primitive rather than retrying
portable-SIMD copy panels.
