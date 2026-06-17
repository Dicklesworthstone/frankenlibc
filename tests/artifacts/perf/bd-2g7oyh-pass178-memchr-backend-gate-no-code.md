# bd-2g7oyh.462 pass178 memchr_absent backend-gate route-out

Date: 2026-06-17
Agent: BoldFalcon
Mode: local fallback (`ts1`/remote RCH offline, `RCH_REQUIRE_REMOTE=0`)

## Target

Pass177 current-head routing selected `glibc_baseline_memchr_absent` as the next
material string residual:

| row | FrankenLibC p50 / mean | host p50 / mean |
| --- | ---: | ---: |
| pass177 route | `30.737 / 32.337 ns` | `19.500 / 24.509 ns` |

Prior no-repeat families for this exact lane already include folded-panel
widening, exact-4096 dispatch, slice `contains` certificates, loop/tail
rearrangement, SWAR word-group scans, rank/select extraction, indexed folded
scans, wrapper inlining, and hot/cold outlining.

## Focused Baseline

Clean detached worktree:

`/data/tmp/frankenlibc-pass178-memchr-20260617T091036Z`

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass178-memchr-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass178-memchr-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memchr_absent --noplot --sample-size 100 \
  --warm-up-time 1 --measurement-time 3
```

Result:

| impl | Criterion interval | p50 | mean |
| --- | ---: | ---: | ---: |
| FrankenLibC | `[23.032 ns 23.299 ns 23.604 ns]` | `22.947 ns` | `27.800 ns` |
| host glibc | `[20.017 ns 20.424 ns 20.825 ns]` | `19.741 ns` | `20.778 ns` |

Baseline log SHA-256:

`da2dc8cd4566aef14c5f83baabdd8833347eaa7af59312cf16edee19f7416882`

The focused local gap remains material (`1.162x` p50, `1.338x` mean), so a
profile-backed gate exists.

## Backend Screen

Current source SHA-256:

`crates/frankenlibc-core/src/string/mem.rs`
`78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`

Codegen command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass178-memchr-codegen-target \
  RUSTFLAGS='--emit=llvm-ir,asm' \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Codegen hashes:

| artifact | SHA-256 |
| --- | --- |
| build log | `8fc74f50b9526418e0d4f3656b1829c414db51691af0fea330e11da0c35b442c` |
| LLVM IR | `72ff79c509345e8a0a558872d178ff497f8e30adef03b7eae9e108e6e5ee5581` |
| assembly | `83e5e60b6b36679b8f3354b9b6dfb80a12f6cbc30767afa549b6cc82a7529e61` |

Finding:

- Source already uses safe portable-SIMD folded 256-byte absent scans.
- LLVM IR represents the hot loop as `<64 x i8>` comparisons and bitmask
  reductions.
- The local backend lowers the memchr symbol to 16-byte SSE `pcmpeqb` panels,
  `pmovmskb` reductions, and stack-spilled aggregate masks rather than AVX2
  32-byte vector code.
- A per-function `#[target_feature(enable = "avx2")]` route is not admissible
  in `frankenlibc-core` without unsafe call sites. The crate has
  `#![deny(unsafe_code)]`, and a compiler probe with `#![deny(unsafe_code)]`
  confirms calling a target-feature function requires `unsafe`.

Target-feature diagnostic log SHA-256:

`27ca4ac2ae2b542479b90f0feba6e31dd88d5a381204f131b25fc67adaeb096e`

## Behavior Proof

No source was changed. The isomorphism is identity:

- first-match ordering is unchanged;
- absent scans still return `None`;
- `n` is still clamped to `haystack.len()`;
- the implementation does not read outside `haystack[..count]`;
- `memrchr`, wide-string siblings, allocation state, errno, locale, FP state,
  and RNG state are unchanged.

Focused golden checks:

| command | result | log SHA-256 |
| --- | --- | --- |
| `cargo test -j 1 -p frankenlibc-core string::mem::tests::memchr_golden_output_sha256 -- --nocapture --test-threads=1` | passed `1/1` | `9ebf335a0c859ca22dc37ab6ef6ff238048348d342eddaf24ef60a17a0c56a00` |
| `cargo test -j 1 -p frankenlibc-core --test property_tests golden_memchr_corpus_sha256 -- --nocapture --test-threads=1` | passed `1/1` | `0095bb8cb4529708a5595dbf2f0b4aba829c726367a0c30789d7211e459ce21b` |

Golden SHA-256 contracts:

- inline memchr corpus:
  `04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500`
- property-test memchr corpus:
  `aec12be451b7b8803c8c57199f64dd2f40fc7c8894f3830e203eacaf0039f952`

The clean worktree source diff check passed:

```bash
git -C /data/tmp/frankenlibc-pass178-memchr-20260617T091036Z \
  diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs
```

## Verdict

No source lever was retained. Score: `0.0`.

This pass routes the current `memchr_absent` source/backend family out rather
than repeating rejected source-shape micro-levers. The next admissible
`memchr_absent` attack needs a materially different backend-dispatch primitive,
such as a policy-approved safe-Rust generated target backend that changes vector
lowering without widening unsafe in `frankenlibc-core`.

Next campaign step: reprofile current head and choose the next material
profile-backed residual.
