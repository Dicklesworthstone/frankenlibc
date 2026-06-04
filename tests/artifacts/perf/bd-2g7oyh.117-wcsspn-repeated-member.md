# bd-2g7oyh.117 - wcsspn repeated-member run certificate

## Target

Profile-backed pass 4 target: `crates/frankenlibc-core/src/string/wide.rs::wcsspn`.

Fresh RCH baseline:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_wcsspn_pass4_baseline \
  FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  wcsspn_full --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
worker: ts2

wcsspn_simd_4096 p50=322.957 ns p95=403.250 p99=484.069 mean=338.482
wcsspn_simd_1024 p50=99.666 ns p95=105.250 p99=157.030 mean=103.068
wcsspn_simd_256  p50=55.672 ns p95=68.004  p99=81.355  mean=58.621
```

The benchmark corpus is a 4096-wide-character full-accept prefix over
`accept = [L'0', L'1', L'2', L'3']`, with the input filled with `L'1'`.

## Alien Primitive

Prior contiguous-range widening in `bd-2g7oyh.111` was rejected-restored, so
this pass uses a different primitive: a repeated-member run certificate. It is
grounded in the graveyard's succinct bitvector and SIMD metadata membership
sections (§7.1, §7.7): prove membership once for the first non-NUL code unit,
then scan SIMD-width control panels for exact repetition of that accepted value.

## Lever

`wcsspn` now checks long inputs for a repeated accepted first code unit before
the existing contiguous-range/general membership scan. Each skipped panel is
certified to contain only that same non-NUL accepted value. The first uncertain
panel is reprocessed by the existing range/general path and scalar stop-index
resolver.

No benchmark harness, ABI boundary, scalar reference, `wcscspn`, or `wcspbrk`
behavior changed.

## Isomorphism Proof

- Ordering preserved: the new loop only advances over panels whose lanes are
  all exactly equal to the first character of `s`.
- Tie-breaking unchanged: the first panel that is not entirely the repeated
  member falls through to the previous left-to-right membership/NUL resolver.
- NUL handling preserved: the repeated character must be non-NUL; a NUL in any
  later panel makes the exact-repetition certificate fail and is resolved by the
  existing code.
- Accept-set truncation preserved: membership is tested against
  `accept[..wcslen(accept)]`, exactly as before.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: `golden_wide_span_corpus_sha256` unchanged at
  `18274545e059d566e428a084131dd111835adb458d3030c46bff7b09501c6f96`.

## Verification

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs
result: pass

git diff --check -- crates/frankenlibc-core/src/string/wide.rs
result: pass

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_wcsspn_pass4_test \
  cargo test -p frankenlibc-core --lib \
  string::wide::tests::test_wcsspn_repeated_member_run_stops_at_first_nonmember -- --nocapture
worker: vmi1227854
result: pass, 1/1

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_wcsspn_pass4_prop \
  RUST_TEST_THREADS=1 cargo test -p frankenlibc-core --test property_tests span -- --nocapture
worker: ts2
result: pass, 3/3:
  golden_wide_span_corpus_sha256
  prop_wcs_span_family_matches_scalar_reference
  prop_wcs_span_family_matches_scalar_reference_full

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_wcsspn_pass4_check \
  cargo check -p frankenlibc-core --all-targets
worker: ts2
result: pass

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_wcsspn_pass4_clippy \
  cargo clippy -p frankenlibc-core --all-targets -- -D warnings \
  -A clippy::question_mark -A clippy::too_many_arguments \
  -A clippy::collapsible_if -A clippy::unnecessary_cast \
  -A clippy::type_complexity -A clippy::byte_char_slices \
  -A clippy::approx_constant -A clippy::unnecessary_min_or_max \
  -A clippy::manual_repeat_n -A clippy::manual_memcpy \
  -A clippy::needless_range_loop -A clippy::cmp_owned
worker: ts2
result: pass
```

The build script emitted the existing missing-SMT-solver warning on RCH workers.

## Post Benchmark

Same-worker RCH post-benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_wcsspn_pass4_post \
  FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  wcsspn_full --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
worker: ts2

wcsspn_simd_4096 p50=200.674 ns p95=223.576 p99=309.512 mean=207.397
wcsspn_simd_1024 p50=60.319 ns  p95=64.682  p99=80.000  mean=62.411
wcsspn_simd_256  p50=18.591 ns  p95=22.869  p99=45.000  mean=20.404
```

Primary row:

| row | baseline p50 | post p50 | baseline mean | post mean |
| --- | ---: | ---: | ---: | ---: |
| `wcsspn_simd_4096` | 322.957 ns | 200.674 ns | 338.482 ns | 207.397 ns |

Improvement: p50 `1.61x` faster (`37.9%` lower), mean `1.63x` faster
(`38.7%` lower). Secondary long rows improved materially as well:
`1024` p50 `99.666 -> 60.319 ns`, `256` p50 `55.672 -> 18.591 ns`.

Score: `(Impact 4 * Confidence 5) / Effort 2 = 10.0`; kept.
