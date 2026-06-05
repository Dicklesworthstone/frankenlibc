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
RCH_PREFERRED_WORKER=ts2 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_130_baseline FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench string_bench -- wcsncmp_equal --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Baseline on `ts2` before edit, Criterion median estimates:

- 16: median 3.079 ns
- 64: median 6.890 ns
- 256: median 24.691 ns
- 1024: median 94.095 ns
- 4096: median 403.349 ns

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench string_bench -- wcsncmp_equal --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Post on `ts2`, Criterion median estimates:

- 16: median 4.225 ns
- 64: median 7.664 ns
- 256: median 14.972 ns
- 1024: median 66.568 ns
- 4096: median 281.179 ns

The 16/64 rows regress because the exact-prefix preflight is gated at
`n >= 256`; the accepted target is the long equal-prefix workload.

Same-worker `ts2` speedups:

- 256: 24.691 ns -> 14.972 ns, 1.65x faster
- 1024: 94.095 ns -> 66.568 ns, 1.41x faster
- 4096: 403.349 ns -> 281.179 ns, 1.43x faster

Accepted ratio against handoff `ts2` target:

- median: 400.358 ns -> 281.179 ns, 1.42x faster

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

An all-targets clippy pass with the observed pre-existing lint classes allowed
passed on `ts2`:

```text
cargo clippy -p frankenlibc-core --all-targets -- -D warnings \
  -A clippy::question_mark \
  -A clippy::too_many_arguments \
  -A clippy::collapsible_if \
  -A clippy::unnecessary_cast \
  -A clippy::byte_char_slices \
  -A clippy::type_complexity \
  -A clippy::unnecessary_min_or_max \
  -A clippy::manual_repeat_n \
  -A clippy::approx_constant \
  -A clippy::manual_memcpy \
  -A clippy::needless_range_loop
```

`cargo fmt -p frankenlibc-core --check` is also blocked by unrelated formatting
drift across `iconv`, `fnmatch`, `str`, `wchar`, and differential probe tests.
The touched file passed `rustfmt --edition 2024 --check`.
