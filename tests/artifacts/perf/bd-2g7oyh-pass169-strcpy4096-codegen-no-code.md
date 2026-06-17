# bd-2g7oyh.452 strcpy_4096 generated/backend primitive gate

Pass: 169
Agent: BoldFalcon
Date: 2026-06-17
Mode: local cargo/Criterion because `ts1`/remote RCH is offline

## Focused Baseline

```bash
env AGENT_NAME=BoldFalcon \
  RCH_REQUIRE_REMOTE=0 \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass169-strcpy-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass169-strcpy-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 80 \
  --warm-up-time 1 --measurement-time 3
```

Log:

```text
/data/tmp/frankenlibc-pass169-strcpy-baseline.log
sha256 2f0bff366999bb67d3dc715e2bc5e9449e3201f416d69ff1a2f0dacce07db569
```

Focused row:

| impl | Criterion center | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[62.799 ns 63.889 ns 65.029 ns]` | `62.500` | `63.855` |
| host glibc | `[42.894 ns 43.949 ns 45.080 ns]` | `45.301` | `51.059` |

Ratio: `1.380x` p50, `1.251x` mean.

## Codegen Gate

```bash
env AGENT_NAME=BoldFalcon \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass169-strcpy-codegen-target \
  RUSTFLAGS="--emit=llvm-ir,asm" \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Hashes:

```text
/data/tmp/frankenlibc-pass169-strcpy-codegen.log
sha256 c9332626772324e3e84203794417b3f62a273ab920e04d7bf5b7e047b0df9da8

/data/tmp/frankenlibc-pass169-strcpy-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.ll
sha256 44ba4acb9faaf1ae5c07115c10ae4b0600e362b46499fb3ed189398992d81c04

/data/tmp/frankenlibc-pass169-strcpy-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.s
sha256 0462e506c4b3303488ece79eb605088c35bdcbf61e48267a8cd362ea218685ee

crates/frankenlibc-core/src/string/str.rs
sha256 807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd
```

The IR/assembly hashes match the prior pass166 codegen screen exactly. The
optimized `strcpy` path still has the exact `src.1 == 4097` branch, eight
512-byte NUL probes, `<64 x i8>` vector loads and stores for NUL-free blocks,
scalar first-NUL fallback on early blocks, and terminal inclusive-NUL
`llvm.memcpy`/copy behavior. This is not a new source-edit opportunity.

## Behavior Proof

No implementation source changed:

```bash
git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs
```

The optional focused golden test was not needed for a no-code route-out and was
stopped after Cargo build-lock contention:

```text
/data/tmp/frankenlibc-pass169-strcpy-golden-test.log
sha256 256920d31a6e3c8c7b7c6e25b6976dd361363b398cfdd33869c4affe88178eb2
```

First-NUL ordering, copied byte order, returned count, destination-tail
preservation, panic behavior, overlap policy, allocation/errno/locale state,
floating-point behavior, RNG state, and existing golden outputs are unchanged by
identity.

## Verdict

NO-CODE ROUTED OUT. Score `0.0`.

Do not return to `strcpy_4096` without a genuinely different generated/backend
terminal/no-overlap primitive. The next profile-backed route is `memcmp_256`
generated/backend evidence, not another manual string-copy source family.
