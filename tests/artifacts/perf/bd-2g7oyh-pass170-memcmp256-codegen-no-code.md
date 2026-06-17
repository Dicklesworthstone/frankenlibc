# bd-2g7oyh.454 memcmp_256 generated/backend primitive gate

Pass: 170
Agent: BoldFalcon
Date: 2026-06-17
Mode: local cargo/Criterion because `ts1`/remote RCH is offline

## Focused Baseline

```bash
env AGENT_NAME=BoldFalcon \
  RCH_REQUIRE_REMOTE=0 \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass170-memcmp-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass170-memcmp-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_256 --noplot --sample-size 100 \
  --warm-up-time 1 --measurement-time 3
```

Log:

```text
/data/tmp/frankenlibc-pass170-memcmp-baseline.log
sha256 708fe01bb6cfddcedaaad4ec5ce15948f59d59d28d85548ae31b84d7074a54ef
```

Focused row:

| impl | Criterion center | p50 ns | mean ns |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[5.6983 ns 5.8140 ns 5.9273 ns]` | `5.813` | `6.948` |
| host glibc | `[4.1513 ns 4.2761 ns 4.3916 ns]` | `4.270` | `4.692` |

Ratio: `1.361x` p50, `1.481x` mean.

## Codegen Gate

```bash
env AGENT_NAME=BoldFalcon \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass170-memcmp-codegen-target \
  RUSTFLAGS="--emit=llvm-ir,asm" \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Hashes:

```text
/data/tmp/frankenlibc-pass170-memcmp-codegen.log
sha256 3892dcdcdc8efa9d863dec09ec835bcf2011482f3aa7b83f64d19f0880088a76

/data/tmp/frankenlibc-pass170-memcmp-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.ll
sha256 44ba4acb9faaf1ae5c07115c10ae4b0600e362b46499fb3ed189398992d81c04

/data/tmp/frankenlibc-pass170-memcmp-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.s
sha256 0462e506c4b3303488ece79eb605088c35bdcbf61e48267a8cd362ea218685ee

crates/frankenlibc-core/src/string/mem.rs
sha256 78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d
```

Exact `memcmp` symbol in the emitted assembly:

```text
_RNvNtNtCsgnp6eBStzl3_16frankenlibc_core6string3mem6memcmp:
  cmpq $256, %r8
  je .LBB1222_7
...
.LBB1222_7:
  movdqu 0..240 byte panels from both inputs
  pcmpeqb / pand chain
  pmovmskb %xmm1, %eax
  cmpl $65535, %eax
  jne .LBB1222_58
  jmp equal-return
```

The IR/assembly hashes match the existing core codegen artifact. The exact-256
path is already self-contained and external-call-free. Prior no-repeat families
also cover the plausible source-level retunes here: exact-256 array equality,
u128 panels, foldback/two-128, folded-panel widening, chunk cursor, rank/select,
cross-crate inline exposure, scalar panel reshapes, and XOR/test-zero retunes.

## Behavior Proof

No implementation source changed:

```bash
git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs
```

First-difference ordering, unsigned byte comparison, zero-length behavior,
`n` clamping, non-256 paths, exact-16 and exact-4096 behavior,
allocation/errno/locale state, floating-point behavior, RNG state, and existing
golden memcmp outputs are unchanged by identity.

## Verdict

NO-CODE ROUTED OUT. Score `0.0`.

Do not return to `memcmp_256` without a genuinely new backend-dispatch or
compiler-lowering primitive. The next profile-backed route is `memmove_4096`
generated/backend evidence from the pass168 table.
