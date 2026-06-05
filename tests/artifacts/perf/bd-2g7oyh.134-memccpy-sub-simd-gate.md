# bd-2g7oyh.134 - memccpy sub-SIMD scalar copy-until gate

## Target

Profile-backed child of `bd-2g7oyh`.

Hot row from RCH `ts1` baseline on 2026-06-05:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memccpy_baseline cargo bench -p frankenlibc-bench --bench string_bench -- memccpy_absent --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot`
- `memccpy_absent/raw/simd/16`: Criterion estimate 13.111 ns; `STRING_BENCH` p50 13.109 ns
- `memccpy_absent/raw/scalar/16`: Criterion estimate 11.669 ns; `STRING_BENCH` p50 11.476 ns
- Larger rows were already current-path favorable, so the lever is gated to `count < 32`.

## Lever

One lever in `crates/frankenlibc-core/src/string/mem.rs`:

- For `memccpy`, when `count < SIMD_LANES`, copy byte-by-byte until the first stop byte or the clamped count.
- Preserve the existing `memchr` plus bulk-copy path for `count >= SIMD_LANES`.

This removes the small-size `memchr` call and slice-copy setup from the 16-byte absent profile while leaving the large-buffer SIMD path unchanged.

## Behavior proof

`count = min(n, dest.len(), src.len())` is computed before the new branch and remains the sole bound for reads and writes.

For `count < SIMD_LANES`, the previous body:

1. Searched `src[..count]` for the first `c`.
2. If found at `p`, copied `dest[..=p] = src[..=p]` and returned `Some(p + 1)`.
3. If absent, copied `dest[..count] = src[..count]` and returned `None`.

The new branch performs exactly the same ordered scan. It writes `dest[i] = src[i]` before checking whether `src[i] == c`, so the stop byte is copied before returning `Some(i + 1)`. It does not write after the first stop byte. If no stop byte exists before `count`, it copies all `count` bytes and returns `None`.

Ordering and tie-breaking: first occurrence of `c` is preserved because the scan is ascending from zero and returns immediately on the first match.

Floating point: not applicable.

RNG: not applicable.

Aliasing: safe Rust slice borrowing still enforces the same non-overlap contract at the API surface.

Large-buffer path: unchanged for `count >= SIMD_LANES`.

## Golden sha256

- `tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json`: `a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1`
- `tests/conformance/fixtures/string_memory_hotpaths_wave10.json`: `65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845`

## Re-benchmark

Final-source post-bench on RCH `ts1`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memccpy_finalpost cargo bench -p frankenlibc-bench --bench string_bench -- 'memccpy_absent/raw/simd/16' --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot`
- `memccpy_absent/raw/simd/16`: Criterion estimate 9.6341 ns; `STRING_BENCH` p50 9.588 ns

Before/after:

- Criterion estimate: 13.111 ns -> 9.6341 ns, 1.36x faster
- `STRING_BENCH` p50: 13.109 ns -> 9.588 ns, 1.37x faster

Additional cross-worker post-bench on RCH `ts2`:

- `memccpy_absent/raw/simd/16`: Criterion estimate 10.578 ns; `STRING_BENCH` p50 10.651 ns
- 64B+ rows remained on the unchanged path and kept their existing SIMD-favorable profile.

Temporary same-process reference check on RCH `ts1`:

- Current `memccpy_absent/raw/simd/16`: Criterion estimate 6.8585 ns; p50 6.913 ns
- Temporary old-body `memchr` plus bulk-copy reference: Criterion estimate 7.0381 ns; p50 6.957 ns
- The temporary benchmark row was removed before commit.

## Validation

- `rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: pass
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: pass
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memccpy_test cargo test -p frankenlibc-core memccpy --lib -- --nocapture`: pass, 3 tests
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memccpy_check cargo check -p frankenlibc-core --all-targets`: pass
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memccpy_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by existing lint debt outside `mem.rs` in `regex.rs`, `wide.rs`, `sort.rs`, `fnmatch.rs`, and `str.rs`.

## Score

Impact 3 * Confidence 4 / Effort 2 = 6.0.

Kept because the same-worker final-source re-benchmark shows a real 16-byte hot-row win, behavior is isomorphic, and the scope is one lever.
