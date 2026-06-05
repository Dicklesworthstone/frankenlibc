# bd-2g7oyh.135 - strnlen SIMD bounded prefix for strnstr

## Target

Profile-backed child of `bd-2g7oyh`.

Baseline filed in the bead from RCH `vmi1156319` on 2026-06-05:

- `strnstr_bounded_absent_4096`: p50 4713.913 ns, p95 5501.000 ns, p99 5694.062 ns, mean 4710.506 ns
- `strnstr_bounded_absent_1024`: p50 1203.140 ns
- `strnstr_bounded_absent_256`: p50 340.168 ns

Code inspection: `strnstr` already delegates the bounded NUL-free prefix to `memmem`, but first obtains that prefix length through scalar `strnlen`.

## Lever

One lever in `crates/frankenlibc-core/src/string/str.rs`:

- Replace scalar `s.iter().take(limit).position(...)` in `strnlen` with `strlen(&s[..limit])`.
- Keep the same `limit = min(maxlen, s.len())` clamp.

This reuses the existing SIMD `strlen` NUL scan for bounded prefixes and removes the scalar prefix scan from `strnstr_bounded_absent`.

## Behavior proof

For any `s` and `maxlen`, the old `strnlen` returned:

- the smallest index `i < min(maxlen, s.len())` where `s[i] == 0`, or
- `min(maxlen, s.len())` if no such NUL exists.

The new implementation slices exactly `s[..limit]` where `limit = min(maxlen, s.len())`, then calls `strlen` on that prefix. `strlen` returns the first NUL index within the slice, or the slice length when none exists. Therefore the result set and ordering are identical to the old bounded scalar scan.

Tie-breaking: first NUL wins in both implementations.

Ordering: prefix search order is unchanged semantically because `strlen` returns the earliest NUL in the exact same bounded prefix.

Floating point: not applicable.

RNG: not applicable.

`strnstr` behavior remains unchanged because it still uses the same bounded haystack prefix length and delegates the same prefix plus needle to `memmem`.

## Golden sha256

- `tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json`: `a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1`
- `tests/conformance/fixtures/string_memory_hotpaths_wave10.json`: `65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845`
- In-test `strnstr_golden_corpus_sha256`: `84555952f755c0ff071a2b064db484fb74e838c180632c105f9b034f0e9bafa7`

## Re-benchmark

Post-bench on RCH `ts2`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_strnstr_post cargo bench -p frankenlibc-bench --bench string_bench -- strnstr_bounded_absent --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot`
- `strnstr_bounded_absent/raw/16`: Criterion 21.765 ns; `STRING_BENCH` p50 21.701 ns
- `strnstr_bounded_absent/raw/64`: Criterion 24.159 ns; `STRING_BENCH` p50 24.156 ns
- `strnstr_bounded_absent/raw/256`: Criterion 27.207 ns; `STRING_BENCH` p50 27.189 ns
- `strnstr_bounded_absent/raw/1024`: Criterion 36.111 ns; `STRING_BENCH` p50 36.034 ns
- `strnstr_bounded_absent/raw/4096`: Criterion 83.539 ns; `STRING_BENCH` p50 83.408 ns

Before/after on the filed target:

- 4096 p50: 4713.913 ns -> 83.408 ns, 56.5x faster
- 1024 p50: 1203.140 ns -> 36.034 ns, 33.4x faster
- 256 p50: 340.168 ns -> 27.189 ns, 12.5x faster

The baseline and post workers differ, but the ratios are large enough that worker variance cannot explain the result. The post-bench still ran through RCH and the exact benchmark target.

## Validation

- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: pass
- `sha256sum tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json tests/conformance/fixtures/string_memory_hotpaths_wave10.json`: hashes unchanged
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_strnstr_test cargo test -p frankenlibc-core strnstr --lib -- --nocapture`: pass, 20 tests
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_strnlen_test cargo test -p frankenlibc-core strnlen --lib -- --nocapture`: pass, 2 tests
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_strnstr_check cargo check -p frankenlibc-core --all-targets`: pass
- `rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: blocked by pre-existing formatting drift elsewhere in `str.rs`; the staged diff itself passes `git diff --check`
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_strnstr_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by existing lint debt in `regex.rs`, `wide.rs`, `sort.rs`, `fnmatch.rs`, and existing `str.rs` byte-char-slice tests; no new diagnostic targets the `strnlen` lever or golden corpus.

## Score

Impact 5 * Confidence 4 / Effort 1 = 20.0.

Kept because the RCH post-bench removes the profiled scalar prefix scan, behavior is isomorphic by construction, and focused tests plus golden hashes passed.
