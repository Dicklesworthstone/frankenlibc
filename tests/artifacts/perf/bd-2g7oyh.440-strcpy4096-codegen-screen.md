# bd-2g7oyh.440 strcpy_4096 codegen screen

Date: 2026-06-16
Agent: BoldFalcon
Status: no-code routed out

## Target

Pass 143 broad profile on `vmi1227854` reproduced `strcpy_4096` as the
largest string residual on current head:

| row | impl | Criterion interval | p50 ns | mean ns |
| --- | --- | --- | ---: | ---: |
| `strcpy_4096` | FrankenLibC | `[57.441 ns 59.418 ns 62.728 ns]` | 58.182 | 60.678 |
| `strcpy_4096` | host glibc | `[29.197 ns 29.797 ns 30.443 ns]` | 32.950 | 34.366 |

## Focused baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854
RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass144-strcpy4096-baseline-target-20260616T0412
CRITERION_HOME=/data/tmp/frankenlibc-pass144-strcpy4096-baseline-criterion-20260616T0412
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 3
```

Focused result:

| row | impl | Criterion interval | p50 ns | mean ns |
| --- | --- | --- | ---: | ---: |
| `strcpy_4096` | FrankenLibC | `[54.748 ns 56.203 ns 57.492 ns]` | 54.079 | 60.074 |
| `strcpy_4096` | host glibc | `[35.798 ns 36.197 ns 36.712 ns]` | 38.197 | 40.845 |

## Codegen screen

RCH command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854
RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUSTFLAGS
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass144-strcpy4096-codegen-target-20260616T0416
RUSTFLAGS=--emit=llvm-ir,asm
cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

The generated IR for `frankenlibc_core::string::str::strcpy` shows the
current exact-4097 path already scanning eight 512-byte blocks for a NUL
certificate and then issuing:

```text
llvm.memcpy(..., i64 4097, false)
```

for the no-early-NUL case. That is the kept terminal-bulk-copy family from the
current source.

## Candidate screen

No source lever was applied. The available edits repeat documented no-retry
families for this row:

- word/SWAR and global NUL certificates;
- prefix-helper attributes/cold splitting;
- terminal splitting and scalar terminal-NUL splitting;
- exact dispatch hoists;
- array-copy lowering;
- public-wrapper inlining;
- repeated SIMD copy-store variants.

## Isomorphism

No source changed. String copy order, first-NUL selection, panic behavior for
too-small destinations, byte values, output length, floating-point state, and
RNG state are unchanged by construction.

## Verdict

NO-CODE ROUTED OUT. Score `0.0`.

Return to `strcpy_4096` only with a genuinely different generated/backend-
dispatch terminal/no-overlap primitive or compiler-lowering proof after a fresh
focused same-worker gate.

