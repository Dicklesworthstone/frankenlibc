# bd-2g7oyh.130 - wcsncmp exact-prefix preflight

Timestamp: 2026-06-05T02:54:10Z
Agent: BoldFalcon

## Target

Profile-backed target from the bead handoff:

- `wcsncmp_equal_4096` on `ts2`: p50 400.358 ns/op, p95 418.250, p99 465.500, mean 405.623

The accepted lever adds a safe Rust SIMD exact-prefix preflight for long
`wcsncmp` calls. It returns zero only when the first `n` wide code units are
fully present in both slices and exactly equal. All mismatches, short-slice
logical-NUL cases, signed wide-character ordering, and tie-breaking stay on the
existing resolver path.

## Benchmark Evidence

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench string_bench -- wcsncmp_equal --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Baseline on `ts1` before edit:

- 16: p50 2.143 ns, p95 7.500, p99 30.000, mean 4.896
- 64: p50 4.269 ns, p95 6.250, p99 25.000, mean 5.551
- 256: p50 15.862 ns, p95 33.178, p99 70.500, mean 23.111
- 1024: p50 59.367 ns, p95 73.281, p99 87.995, mean 62.543
- 4096: p50 381.880 ns, p95 432.118, p99 546.106, mean 382.112

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench string_bench -- wcsncmp_equal --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Post on `ts2`:

- 16: p50 4.221 ns, p95 7.833, p99 25.000, mean 6.062
- 64: p50 7.683 ns, p95 12.500, p99 40.000, mean 10.190
- 256: p50 18.187 ns, p95 21.156, p99 45.000, mean 20.901
- 1024: p50 66.715 ns, p95 74.673, p99 371.000, mean 79.623
- 4096: p50 282.963 ns, p95 308.000, p99 335.500, mean 290.609

Confirmation post on `ts2`:

- 16: p50 4.225 ns, p95 6.875, p99 25.500, mean 6.225
- 64: p50 7.672 ns, p95 9.375, p99 30.000, mean 9.540
- 256: p50 15.500 ns, p95 19.826, p99 45.000, mean 18.636
- 1024: p50 66.611 ns, p95 76.733, p99 95.000, mean 70.139
- 4096: p50 281.183 ns, p95 290.500, p99 486.195, mean 290.449

Accepted ratio against handoff `ts2` target:

- p50: 400.358 ns -> 281.183 ns, 1.42x faster
- p95: 418.250 ns -> 290.500 ns, 1.44x faster
- mean: 405.623 ns -> 290.449 ns, 1.40x faster

Score: (Impact 4 * Confidence 4) / Effort 2 = 8.0.

## Isomorphism Proof

- Ordering: the preflight returns only for exact equality over all first `n`
  wide code units; any first-difference position falls through to the existing
  signed `u32` resolver.
- Tie-breaking: exact prefix equality returns the same zero result as scalar
  `wcsncmp`; divergence after `n` remains ignored.
- NUL stop behavior: a shared NUL before `n` is also exact equality, so zero is
  unchanged; non-shared NUL or short-slice cases cannot pass the full-prefix
  equality gate and use the existing path.
- Floating point and RNG: this path is integer-only and deterministic; no FP or
  RNG state is read or written.

Golden sha256 after the edit:

```text
d03c74d74670a84390584b6a6f7fe5e26f14026e33d62905f0fd007599164e77  tests/conformance/fixtures/wide_string.json
27f6c82defa323fab0eb349deff6cb3b31e0e47bc77793e458fdffe8d882e1e2  tests/conformance/fixtures/wide_string_ops.json
9e2bae0d8b66a538c01849bd5df6d27943a2ca75a8540d758bae0e2bf381f89f  crates/frankenlibc-core/tests/property_tests.rs
```

RCH behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core --test property_tests wcsncmp -- --nocapture --test-threads=1
```

Passed `wide_properties::prop_wcsncmp_matches_scalar_reference`.

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core --test property_tests compare -- --nocapture --test-threads=1
```

Passed `wide_properties::golden_wide_compare_corpus_sha256`.

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core --lib string::wide::tests::test_wcsncmp -- --nocapture --test-threads=1
```

Passed `test_wcsncmp_basic` and
`test_wcsncmp_equal_prefix_preflight_preserves_bounds_and_order`.

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
```

Passed on `ts2`.

```text
rustfmt --check --edition 2024 crates/frankenlibc-core/src/string/wide.rs
git diff --check -- crates/frankenlibc-core/src/string/wide.rs
```

Passed locally.

## Known Gate Blocker

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings
```

Failed on pre-existing crate-wide lints in `string/regex.rs`,
`string/fnmatch.rs`, `stdlib/sort.rs`, `string/str.rs`, plus older
question-mark lints in `string/wide.rs` outside this measured lever. Those were
not folded into this perf commit to preserve the one-lever scope.
