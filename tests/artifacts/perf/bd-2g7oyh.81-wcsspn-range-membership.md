# bd-2g7oyh.81 - wcsspn contiguous-range membership panels

## Target

Profile-backed target: `wcsspn_full` in `crates/frankenlibc-core/src/string/wide.rs`.

Focused baseline:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  wcsspn_full --sample-size 50 --measurement-time 3 --warm-up-time 1
worker: ts2
wcsspn_simd_16   p50=10.717 ns mean=12.474
wcsspn_simd_64   p50=20.157 ns mean=21.781
wcsspn_simd_256  p50=56.796 ns mean=59.297
wcsspn_simd_1024 p50=209.592 ns mean=217.667
wcsspn_simd_4096 p50=798.142 ns mean=799.168
```

## Lever

Detect accept/reject sets whose effective C wide string membership is exactly a
contiguous `u32` range. For long scans only, replace one SIMD equality per set
element with two SIMD range comparisons per panel. Short scans stay on the old
membership path to avoid paying the detector overhead.

## Isomorphism

`contiguous_wide_range(set)` returns `(min, max)` only if every code point in
`min..=max` is present in the effective set slice. Duplicates are ignored by
both the old `contains` semantics and the range detector. Sparse sets, empty
sets, and overflow spans fall back to the original SIMD equality path.

The fast panel condition still requires no NUL lane. The scalar tail is
unchanged, so first stop index, `wcspbrk` tie-breaking, NUL-before-member
ordering, and unterminated-slice behavior are preserved. FP and RNG are not
used.

Golden-output proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env RUST_TEST_THREADS=1 \
  cargo test -p frankenlibc-core --test property_tests span -- --nocapture
worker: ts2/ts1
result: 3 passed
golden_wide_span_corpus_sha256: 18274545e059d566e428a084131dd111835adb458d3030c46bff7b09501c6f96
```

## Post-Benchmark

Final gated run:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  wcsspn_full --sample-size 50 --measurement-time 3 --warm-up-time 1
worker: ts2
wcsspn_simd_16   p50=11.466 ns mean=13.218
wcsspn_simd_64   p50=21.860 ns mean=24.525
wcsspn_simd_256  p50=63.266 ns mean=65.039
wcsspn_simd_1024 p50=173.869 ns mean=176.050
wcsspn_simd_4096 p50=626.745 ns mean=634.704
```

Primary long-prefix row: `4096` p50 `798.142 -> 626.745 ns` (`1.27x`,
`21.5%` faster). `1024` p50 `209.592 -> 173.869 ns` (`1.21x`, `17.0%`
faster). The final run had slower scalar rows than baseline, so short-row noise
was not used as the keep criterion.

Score: Impact 3 x Confidence 4 / Effort 2 = 6.0.

## Validation

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs
result: pass

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env RUST_TEST_THREADS=1 \
  cargo test -p frankenlibc-core --test property_tests span -- --nocapture
result: pass, 3/3

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env RUST_TEST_THREADS=1 \
  cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture
result: pass, 74/74

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  cargo check -p frankenlibc-core --all-targets
result: pass

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  cargo clippy -p frankenlibc-core --all-targets -- -D warnings
result: blocked by unrelated existing failures:
  crates/frankenlibc-core/src/malloc/allocator.rs:72 clippy::cmp_owned
  crates/frankenlibc-core/src/malloc/allocator.rs:78 clippy::cmp_owned
  crates/frankenlibc-core/src/stdlib/sort.rs:1000 clippy::unnecessary_cast
```
