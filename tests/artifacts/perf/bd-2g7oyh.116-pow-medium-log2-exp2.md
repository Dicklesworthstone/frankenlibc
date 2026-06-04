# bd-2g7oyh.116 bounded pow log2/exp2 fast path

## Target

`crates/frankenlibc-core/src/math/exp.rs::pow`.

The existing fast paths covered small integer exponents and half-integers, but
the profiled irrational exponent path still fell through to `libm::pow`.

## Baseline

Added a focused Criterion row for the actual general-path workload before
editing production `pow`:

```text
RCH_PREFERRED_WORKER=ts2 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_baseline FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'pow_irrational' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `ts2`.

| impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `frankenlibc_core` | 3994.268 | 4987.000 | 6155.375 | 4144.623 |
| `host_glibc` | 1144.800 | 1190.453 | 1343.000 | 1155.560 |

Same-worker old-code confirmation from the clean `f5af69ea` worktree with the
same benchmark row:

| impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `frankenlibc_core` | 4003.889 | 4152.208 | 4212.713 | 4017.113 |
| `host_glibc` | 1146.936 | 1191.168 | 1211.115 | 1157.622 |

## Alien Primitive

Primitive: bounded specialized kernel with exact fallback.

This is the first shippable slice of the requested table/log2/exp2 direction:
for positive finite medium bases and bounded finite exponents, skip the full
`pow` IEEE classifier and compute directly with the existing pure-Rust
`libm::log2` and `libm::exp2` kernels. Inputs outside the proven envelope keep
the old `libm::pow` path bit-for-bit.

Envelope:

- `base in [0.5, 2.5)`
- `exponent in [-3.0, 3.0]`
- `base` and `exponent` finite
- integer and half-integer fast paths still run first

The wider exponent envelope was explicitly rejected during exploration because
`exp2(y * log2(x))` crossed the existing 4-ULP math contract outside this
bounded range.

## Isomorphism Proof

- All non-finite inputs, negative bases, zero bases, subnormal/special bases,
  bases outside `[0.5, 2.5)`, and exponents outside `[-3, 3]` fall through to
  `libm::pow`, preserving previous bits and IEEE special-case behavior.
- Existing small integer and half-integer paths still run before this new
  branch, preserving their previous behavior and performance.
- Inside the new envelope, the mathematical identity
  `x^y = 2^(y * log2(x))` applies for `x > 0`; the runtime proof is a
  deterministic 1,000,000-point LCG sweep against host `f64::powf`, plus a
  golden corpus, all within the existing 4-ULP glibc parity contract.
- No ordering or tie-breaking behavior is involved.
- RNG behavior is not involved; the test sweep uses a deterministic LCG seed.

Golden output SHA-256:
`970a740ac2a4983abae2831799f179c711201e97de0e8b4373c12cab2e193ab7`.

## Post Benchmark

Same-worker postbench:

```text
RCH_PREFERRED_WORKER=ts2 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_post_ts2 FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'pow_irrational' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `ts2`.

| impl | pre p50 | post p50 | pre mean | post mean | p50 speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `frankenlibc_core` | 4003.889 | 2186.493 | 4017.113 | 2290.737 | 1.83x |
| `host_glibc` | 1146.936 | 1145.854 | 1157.622 | 1157.087 | 1.00x |

Cross-worker signal on `ts1` also improved `frankenlibc_core` to p50
`1343.700 ns/op`, mean `1444.955 ns/op`, but the keep decision uses the
same-worker `ts2` row above.

Score: `(Impact 4.0 * Confidence 4.0) / Effort 2.0 = 8.0`, keep.

Residual target after this lever: the same `pow_irrational` workload remains
about `1.91x` slower than host glibc on `ts2`, so the next primitive should be
the full table-driven double-double log2/exp2 kernel rather than another
classifier shortcut.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`:
  passed.
- `git diff --check -- crates/frankenlibc-core/src/math/exp.rs crates/frankenlibc-bench/benches/glibc_baseline_bench.rs .beads/issues.jsonl`:
  passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_tests cargo test -p frankenlibc-core --lib pow_medium_log2_exp2 -- --nocapture`:
  passed on `ts1`, 3 tests including the 1,000,000-point sweep.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_exp_tests FRANKENLIBC_PROPTEST_CASES=64 cargo test -p frankenlibc-core --lib math::exp::tests:: -- --nocapture`:
  passed on `ts1`, 17 tests.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_check_core cargo check -p frankenlibc-core --all-targets`:
  passed on `ts2`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_clippy_core cargo clippy -p frankenlibc-core --all-targets -- -D warnings -A clippy::question_mark -A clippy::too_many_arguments -A clippy::collapsible_if -A clippy::unnecessary_cast -A clippy::type_complexity -A clippy::byte_char_slices -A clippy::manual_repeat_n -A clippy::approx_constant -A clippy::unnecessary_min_or_max -A clippy::manual_memcpy -A clippy::needless_range_loop`:
  passed on `ts2`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pow116_clippy_bench2 cargo clippy -p frankenlibc-bench --benches -- -D warnings -A dead_code -A clippy::question_mark -A clippy::too_many_arguments -A clippy::collapsible_if -A clippy::unnecessary_cast -A clippy::type_complexity -A clippy::byte_char_slices -A clippy::manual_repeat_n -A clippy::approx_constant -A clippy::unnecessary_min_or_max -A clippy::manual_memcpy -A clippy::needless_range_loop`:
  passed on `ts2`.
