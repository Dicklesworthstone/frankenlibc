# bd-2g7oyh.431 / Pass 149 strlen_4096 focused gate

Date: 2026-06-16
Agent: BoldFalcon
Worker: ovh-a
Head: 3afb463dabe618f1af1785f3ff94bd90154c2e16
Status: no source change, focused gap reproduced, codegen route blocked

## Baseline

Clean detached worktree:

```text
/data/projects/.scratch/frankenlibc-pass149-strlen-20260616T2010
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a \
RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass149-strlen-baseline-target-20260616T2010 \
CRITERION_HOME=/data/tmp/frankenlibc-pass149-strlen-baseline-criterion-20260616T2010 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_strlen_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

| Impl | Criterion | p50/mean | p95/p99 |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[24.670 ns 24.741 ns 24.807 ns]` | `24.860 / 27.022 ns` | `31.312 / 70.000 ns` |
| host glibc | `[17.785 ns 17.848 ns 17.911 ns]` | `17.908 / 18.862 ns` | `19.375 / 40.500 ns` |

The same-worker focused gap reproduced: `1.388x` p50 and `1.433x` mean.

## Prior No-Retry Families

The current source already includes the previous retained `#[inline(always)]` public-wrapper keep plus the 512-byte folded NUL detector. Prior rejected `strlen_4096` families include:

- page-scale / 4096-byte NUL-free certificates,
- dual-512 loop structure,
- exact `4096 + NUL` terminal fast path,
- 32-byte-lane folded AVX2-width scan reshaping,
- public-wrapper inlining.

## Codegen Probe

The only admissible next `strlen_4096` lever is a generated/disassembly-backed safe-Rust primitive that changes lowering more fundamentally than the families above.

Two RCH codegen attempts did not produce usable evidence:

1. `cargo rustc -p frankenlibc-bench --bench glibc_baseline_bench --profile bench -- --emit=asm` was refused by RCH remote-required mode as a non-compilation command.
2. `cargo build -j 1 -p frankenlibc-bench --benches --profile bench` with `RUSTFLAGS=--emit=asm` ran on `ovh-a` but was interrupted after extended silence during final assembly/codegen. No source was edited.

The baseline target directory exposed no local disassembly artifact for the inlined benchmark path after retrieval.

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

The focused gap is real, but guessing another manual scan-shape edit would repeat closed families. Return to this lane only with an RCH-compatible codegen extraction path or a generated backend primitive that can prove first-NUL order and show the emitted hot loop before source work.

Behavior proof is identity: no source changed, so first-NUL ordering, no-NUL return behavior, tie-breaking, floating-point state, RNG state, allocation behavior, errno, locale, and existing golden-output fixtures are unchanged by construction.
