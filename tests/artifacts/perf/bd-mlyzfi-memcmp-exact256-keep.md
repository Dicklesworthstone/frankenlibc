# bd-mlyzfi memcmp exact-256 equality dispatch keep

Date: 2026-06-05
Agent: BlackThrush
Target: `[perf] memcmp 256 SWAR first-difference dispatch`
Files: `crates/frankenlibc-core/src/string/mem.rs`

## Profile target

Profile-backed bead: `bd-mlyzfi`.

RCH baseline command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Worker: `ts2`.

Baseline row:

```text
glibc_baseline_memcmp_256/memcmp/frankenlibc_core
time [7.6726 ns 7.8647 ns 8.1544 ns]
GLIBC_BASELINE_BENCH p50_ns_op=7.656 p95_ns_op=15.125 p99_ns_op=30.500 mean_ns_op=10.348

glibc_baseline_memcmp_256/memcmp/host_glibc
time [4.9823 ns 5.0059 ns 5.0357 ns]
GLIBC_BASELINE_BENCH p50_ns_op=5.018 p95_ns_op=11.250 p99_ns_op=25.000 mean_ns_op=6.742
```

## Lever

One lever only: exact-256 equality preflight in `memcmp`.

For `count == 256`, the function probes the two existing 128-byte folded SIMD panels and returns `Ordering::Equal` only when both panels prove byte-for-byte equality. If either panel has any mismatch, control falls through to the existing ordered resolver.

This is intentionally not the previously rejected wider portable-SIMD fold. It uses the existing 128-byte folded primitive and only removes loop/tail overhead for the profiled exact-size equal-buffer row.

## Isomorphism proof

- Ordering preserved: yes. The new branch returns `Equal` only after both 128-byte probes prove no byte differs. Any mismatch, including a mismatch at the first byte, last byte, or panel boundary, falls through to the existing first-difference resolver.
- Tie-breaking unchanged: yes. `memcmp` has no secondary tie-break. Equal remains equal only for all compared bytes equal under `count = min(n, a.len(), b.len())`.
- Floating point: N/A.
- RNG seeds: N/A. The golden corpus generator seed stays `0xD1B5_4A32_D192_ED03`.
- Golden output: `golden_memcmp_corpus_sha256 = 23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`.

Baseline proof command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-proof-baseline cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

Baseline proof result on `ts2`: 28 focused memcmp/timingsafe/wmemcmp unit/property tests passed; `string_properties::golden_memcmp_corpus_sha256` and `string_properties::prop_memcpy_then_memcmp_is_zero` passed.

Post proof command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-proof-post cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

Post proof result on `ts2`: same 28 focused tests passed; `golden_memcmp_corpus_sha256` and `prop_memcpy_then_memcmp_is_zero` passed.

Formatting and check:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-check cargo check -p frankenlibc-core --all-targets
```

All passed.

Clippy:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings
```

Failed on pre-existing non-`mem.rs` lints: excessive precision and digit grouping in `math/special.rs`, unrelated `stdlib/conversion.rs` and `stdlib/sort.rs` lints, and unrelated `fnmatch.rs`/`regex.rs`/`wide.rs` clippy style lints. No `mem.rs` lint was reported.

## Post benchmark

Post command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Post row on `ts2`:

```text
glibc_baseline_memcmp_256/memcmp/frankenlibc_core
time [7.5727 ns 7.5910 ns 7.6115 ns]
GLIBC_BASELINE_BENCH p50_ns_op=7.576 p95_ns_op=12.500 p99_ns_op=25.000 mean_ns_op=9.481
```

Confirmation command:

```bash
RCH_REQUIRE_REMOTE=1 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-mlyzfi-confirm cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Confirmation row on `ts2`:

```text
glibc_baseline_memcmp_256/memcmp/frankenlibc_core
time [7.5383 ns 7.5518 ns 7.5630 ns]
GLIBC_BASELINE_BENCH p50_ns_op=7.552 p95_ns_op=11.250 p99_ns_op=25.000 mean_ns_op=9.228
```

Confirmed absolute improvement versus baseline:

- p50: `7.656 ns -> 7.552 ns` (`1.4%` faster).
- mean: `10.348 ns -> 9.228 ns` (`10.8%` faster).
- Criterion estimate center: `7.8647 ns -> 7.5518 ns` (`4.0%` faster), non-overlapping intervals.

Score: `(Impact 2 * Confidence 4) / Effort 1 = 8.0`.

## Next profile target

After this exact-size dispatch, the next deeper primitive for `memcmp` should be a first-difference SWAR word-mask resolver for mismatching panels, or a different memory-layout primitive for the equal path if future profile rows show the same exact-size equality gap remains dominant.
