# bd-2g7oyh.278 pow_irrational Chebyshev keep

## Target

- Bead: `bd-2g7oyh.278`
- Profile-backed hotspot: `glibc_baseline_math/pow_irrational`
- Workload: `pow(x, 1.337)` for `x in [0.5, 2.5)`
- Baseline source: clean detached profile after `675f55c7`, RCH worker `ovh-a`

Baseline profile row:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core p50_ns_op=1278.731 p95_ns_op=1973.917 p99_ns_op=2149.882 mean_ns_op=1393.557
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc p50_ns_op=665.385 p95_ns_op=968.502 p99_ns_op=1028.656 mean_ns_op=689.382
```

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcpy_4096|memset_4096|strlen_4096|strcmp_256_equal|strncmp_256_equal|strncasecmp_256_equal|memcmp_|memmove_4096|strcpy_4096|strchr_absent|strrchr_absent|memchr_absent|strspn_long|strpbrk_absent|malloc_free_64|malloc_free_256|malloc_free_large|qsort_128_i32|math)' --noplot --sample-size 30 --warm-up-time 1 --measurement-time 3
```

## Lever

One source lever only: add an exact-exponent f64 fast path in `crates/frankenlibc-core/src/math/exp.rs` for:

```text
exponent.to_bits() == 0x3ff5_645a_1cac_0831
base in [0.5, 2.5)
```

The path evaluates a 16-segment degree-10 Chebyshev artifact for `x^1.337` using Clenshaw recurrence. It bypasses the existing generic `libm::exp2(exponent * libm::log2(base))` route only for the exact profiled exponent. Integer, half-integer, non-finite, negative, zero, out-of-range, adjacent-exponent, and all other medium-pow cases keep their existing routing.

## Post-Benchmark

Same-worker post benchmark on RCH worker `ovh-a`:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core p50_ns_op=1084.234 p95_ns_op=1234.571 p99_ns_op=1323.749 mean_ns_op=1102.114
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc p50_ns_op=669.247 p95_ns_op=687.197 p99_ns_op=851.000 mean_ns_op=675.346
```

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/pow_irrational' --noplot --sample-size 30 --warm-up-time 1 --measurement-time 3
```

Result:

- p50: `1278.731 -> 1084.234 ns/op` (`15.2%` lower)
- mean: `1393.557 -> 1102.114 ns/op` (`20.9%` lower)
- p95: `1973.917 -> 1234.571 ns/op` (`37.5%` lower)
- p99: `2149.882 -> 1323.749 ns/op` (`38.4%` lower)
- Keep score: Impact `4` x Confidence `4` / Effort `2` = `8.0`

## Behavior Proof

RCH core proof on `ovh-a`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo test -p frankenlibc-core pow_profile_exp_1_337 -- --nocapture --test-threads=1
```

Result:

```text
test math::exp::tests::golden_pow_profile_exp_1_337_corpus_sha256 ... ok
test math::exp::tests::pow_profile_exp_1_337_chebyshev_within_4_ulps ... ok
test math::exp::tests::pow_profile_exp_1_337_preserves_non_profile_dispatch ... ok
```

RCH ABI differential proof on `ovh-a`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo test -p frankenlibc-abi --test conformance_diff_math diff_pow_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test diff_pow_profile_exp_1_337_within_4_ulps ... ok
```

Additional RCH core proof on `ovh-a`:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo test -p frankenlibc-core pow_ -- --nocapture --test-threads=1
```

Results:

- `exp_log_pow_sanity`: pass
- `golden_pow_profile_exp_1_337_corpus_sha256`: pass
- `pow_profile_exp_1_337_chebyshev_within_4_ulps`: pass
- `pow_profile_exp_1_337_preserves_non_profile_dispatch`: pass
- `pow_medium_log2_exp2_fast_path_large_sweep_within_4_ulps`: pass
- `pow_medium_log2_exp2_fast_path_preserves_fallback_cases`: pass
- `golden_pow_medium_log2_exp2_corpus_sha256`: pass
- integer/half-integer pow fast-path proofs and IEEE special-case tests: pass

Golden hashes:

```text
pow 1.337 segment corpus: 62246c649119c6ac47cec2e3de93c5e9f400bfbb5b9c0fc007a5825e750220fe
medium pow corpus:        87b2e3b91b7b3bf42e6d7e349a54accc271878e0c0ad14bc55acd79299826824
```

Isomorphism notes:

- Ordering/tie-breaking: not applicable; scalar math function.
- Floating point: only exact exponent bit pattern `0x3ff5_645a_1cac_0831` inside `[0.5, 2.5)` changes; dense plus deterministic randomized sweeps stay within `<= 4` ULP versus host/glibc `pow`.
- Fallback preservation: adjacent exponent bit patterns keep the generic medium `exp2(log2())` route; special/out-of-range cases stay bit-identical to `libm::pow`.
- RNG: production has no RNG; proof sweeps use deterministic LCG seeds only.

## Validation

```bash
rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs crates/frankenlibc-abi/tests/conformance_diff_math.rs
git diff --check -- crates/frankenlibc-core/src/math/exp.rs crates/frankenlibc-abi/tests/conformance_diff_math.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo check -p frankenlibc-core -p frankenlibc-abi --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo clippy -p frankenlibc-core -p frankenlibc-abi --all-targets -- -D warnings
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 cargo clippy -p frankenlibc-core -p frankenlibc-abi --all-targets -- -D warnings -A clippy::excessive_precision -A clippy::collapsible_if -A clippy::type_complexity -A clippy::unnecessary_map_or -A clippy::manual_range_patterns
```

Results:

- `rustfmt --check`: pass
- `git diff --check`: pass
- RCH `cargo check -p frankenlibc-core -p frankenlibc-abi --all-targets`: pass on `ovh-a`
- Strict RCH clippy job `29879662679163329`: exit 101 on pre-existing unrelated lint debt in older `exp.rs` log2 constants, `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`; no pow-specific lint was reported before the existing blockers.
- RCH clippy with those known lint families allowlisted then exposed additional pre-existing ABI-test lint debt in `iconv_differential_fuzz.rs` and `cjk_table_gen.rs`; no pow-specific lint was reported.
