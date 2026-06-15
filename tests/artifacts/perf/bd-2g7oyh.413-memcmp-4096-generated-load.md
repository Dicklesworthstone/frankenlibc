# bd-2g7oyh.413 - memcmp_4096 generated-load equality certificate

Date: 2026-06-15
Agent: BoldFalcon
Target: `glibc_baseline_memcmp_4096/memcmp/frankenlibc_core`
Worker: `vmi1227854`

Re-key note: this pass was opened locally as `bd-2g7oyh.412`, but
`origin/main` used `.412` for a `strcpy_4096` rejection while the pass was
running. The committed tracker entry is `bd-2g7oyh.413`.

## Route

The broad RCH profile on `ovh-a` left a material equal-buffer residual:

- FrankenLibC p50/mean: `74.847/79.123 ns`
- host glibc p50/mean: `50.229/53.872 ns`

Prior rejected families ruled out slice lexicographic compare, folded superblock
filters, load-port reshapes, exact-certificate foldback for smaller lanes,
broadword early-exit reshuffles, and resolver retuning. The accepted route is a
self-contained safe-Rust SIMD load certificate for equality only.

## Baseline

RCH selected `vmi1227854`.

- FrankenLibC Criterion: `[46.115 ns 46.806 ns 47.608 ns]`
- FrankenLibC p50/mean: `50.727/50.885 ns`
- host glibc Criterion: `[41.004 ns 41.231 ns 41.479 ns]`
- host glibc p50/mean: `41.123/42.504 ns`

## Lever

Add an exact 4096-byte equality certificate in safe Rust:

- Iterate 64-byte portable-SIMD lanes.
- Accumulate `av ^ bv` with bitwise OR.
- Return `Equal` only if the final accumulator is all zero.
- On any non-zero accumulator, fall through to the existing ordered resolver.

This preserves every first-difference, tie-break, and sign decision because the
new branch only short-circuits a proven full-window equality case.

## Codegen Screen

RCH assembly build:

```text
RUSTFLAGS='--emit=asm' cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

The compiled `string::mem::memcmp` symbol contains inlined unaligned SIMD loads,
`pxor`, `por`, `pcmpeqb`, and `pmovmskb` for the exact 4096 path. There is no
`memcmp` or `bcmp` call inside that symbol.

## Behavior Proof

RCH command:

```text
cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1
```

RCH selected `ovh-a`; result: `32` memcmp/timingsafe/wmemcmp tests passed,
including:

- `memcmp_golden_output_sha256`
- `prop_memcmp_is_antisymmetric`
- `prop_memcmp_matches_std_lexicographic`
- `test_memcmp_exact_4096_certificate_preserves_ordering`

Golden SHA remains:

```text
458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9
```

Isomorphism proof:

- Ordering/tie-breaking: preserved by construction because non-equal 4096-byte
  inputs fall through to the previous first-difference resolver.
- Equal case: the new path returns `Equal` only after an all-zero XOR
  accumulator proves every compared byte matches.
- Floating point: not touched.
- RNG: not touched.
- Allocation/lifetime behavior: no allocation introduced.

## Post Benchmark

RCH selected `vmi1227854`.

- FrankenLibC Criterion: `[45.124 ns 45.607 ns 46.092 ns]`
- FrankenLibC p50/mean: `44.892/47.186 ns`
- host glibc Criterion: `[41.771 ns 41.992 ns 42.244 ns]`
- host glibc p50/mean: `42.703/45.680 ns`

Same-worker self improvement:

- p50: `50.727 -> 44.892 ns`, `1.13x`, `11.5%`
- mean: `50.885 -> 47.186 ns`, `1.08x`, `7.3%`
- Criterion center: `46.806 -> 45.607 ns`, `2.6%`

Residual vs same-worker host after the lever:

- p50: `44.892/42.703 = 1.051x`
- mean: `47.186/45.680 = 1.033x`

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`
- RCH `cargo check -j 1 -p frankenlibc-core --lib`

The RCH proof/check still reports pre-existing unrelated duplicate-`#[inline]`
warnings in math modules and the known missing-SMT-solver note.

## Verdict

KEPT.

Score: `(Impact 3.0 x Confidence 5.0) / Effort 1.5 = 10.0`.

Next route: reprofile current head. Do not generalize this into another manual
exact-size certificate without a fresh focused same-worker gap and codegen proof
that the generated load shape differs from prior rejected fold/superblock
families.
