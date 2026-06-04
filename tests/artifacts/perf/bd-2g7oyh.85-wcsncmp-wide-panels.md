# bd-2g7oyh.85 - wcsncmp 32-lane equal-prefix panels

## Target

Profile-backed target: equal-prefix `wcsncmp` in
`crates/frankenlibc-core/src/string/wide.rs`.

Focused baseline:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  wcsncmp_equal --sample-size 50 --measurement-time 3 --warm-up-time 1
worker: ts2
wcsncmp_equal_16   p50=3.062 ns mean=6.029
wcsncmp_equal_64   p50=6.993 ns mean=9.010
wcsncmp_equal_256  p50=27.116 ns mean=29.866
wcsncmp_equal_1024 p50=107.791 ns mean=114.448
wcsncmp_equal_4096 p50=434.073 ns mean=455.666
```

## Lever

Add a 32-lane SIMD equal-and-no-NUL panel before the existing 16-lane
`wcsncmp` scanner. The wider panel only advances over confirmed identical,
non-terminating prefixes. Mismatch, NUL, and tail resolution still use the
existing smaller panel and scalar finish path.

## Isomorphism

The new fast path advances `i` only when all 32 lanes compare equal and every
lane is non-NUL. When any lane differs or contains NUL, it breaks immediately
and the old 16-lane/scalar logic computes the first observable divergence.

Ordering is preserved because the widened panel never consumes a mismatch or
terminator. Tie-breaking is unchanged because the scalar tail still determines
the first differing code unit and signed return value. Logical out-of-range NUL
behavior is unchanged because the widened scan is bounded by
`n.min(s1.len()).min(s2.len())`, exactly like the previous implementation. FP
and RNG are not used.

Golden-output proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env RUST_TEST_THREADS=1 \
  cargo test -p frankenlibc-core --test property_tests compare -- --nocapture
result: pass, golden_wide_compare_corpus_sha256
digest: c9f07f2b950cfc3a76e1b892b776b965698268ae0a8f8b63d66cf1acedf526ca

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env RUST_TEST_THREADS=1 \
  cargo test -p frankenlibc-core --test property_tests wcsncmp -- --nocapture
result: pass, prop_wcsncmp_matches_scalar_reference
```

## Post-Benchmark

Final gated run:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  wcsncmp_equal --sample-size 50 --measurement-time 3 --warm-up-time 1
worker: ts2
wcsncmp_equal_16   p50=3.113 ns mean=5.123
wcsncmp_equal_64   p50=7.041 ns mean=9.057
wcsncmp_equal_256  p50=25.783 ns mean=27.920
wcsncmp_equal_1024 p50=93.096 ns mean=97.330
wcsncmp_equal_4096 p50=399.940 ns mean=411.783
```

Primary long-prefix row: `4096` p50 `434.073 -> 399.940 ns` (`1.09x`,
`7.9%` faster). `1024` p50 `107.791 -> 93.096 ns` (`1.16x`, `13.6%`
faster). `256` p50 `27.116 -> 25.783 ns` (`1.05x`, `4.9%` faster).
Short 16/64 rows are effectively neutral and are not used as the keep
criterion.

Score: Impact 3 x Confidence 4 / Effort 2 = 6.0.

## Validation

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs
result: pass

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  cargo test -p frankenlibc-core --test property_tests compare -- --nocapture
result: pass, golden digest unchanged

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  cargo test -p frankenlibc-core --test property_tests wcsncmp -- --nocapture
result: pass, prop_wcsncmp_matches_scalar_reference

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
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
