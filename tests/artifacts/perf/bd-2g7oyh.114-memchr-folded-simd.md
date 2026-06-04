# bd-2g7oyh.114 - memchr absent-byte folded SIMD panels

Status: kept.

## Target

- Bead: `bd-2g7oyh.114`
- Hotspot: `glibc_baseline_memchr_absent`
- Source: `crates/frankenlibc-core/src/string/mem.rs`
- Lever: scan forward `memchr` absent-heavy prefixes as 256-byte blocks made of eight
  32-byte portable-SIMD equality panels, reducing the block loop and mask-reduction frequency.

## Baseline And Perf Evidence

RCH baseline on `ts2`:

- FrankenLibC: p50 `41.390 ns/op`, p95 `58.110`, p99 `85.000`, mean `45.962`.
- Host glibc: p50 `30.300 ns/op`, p95 `31.642`, p99 `55.000`, mean `32.040`.

RCH post on `vmi1149989`:

- FrankenLibC: p50 `22.157 ns/op`, p95 `26.572`, p99 `40.000`, mean `23.671`.
- Host glibc: p50 `21.474 ns/op`, p95 `27.966`, p99 `80.000`, mean `24.001`.

RCH same-worker confirmation on `ts2`:

- FrankenLibC: p50 `34.935 ns/op`, p95 `41.381`, p99 `60.500`, mean `37.761`.
- Host glibc: p50 `31.690 ns/op`, p95 `39.506`, p99 `67.744`, mean `34.444`.

Same-worker p50 improved `41.390 -> 34.935 ns/op` (`1.18x`); mean improved
`45.962 -> 37.761 ns/op` (`1.22x`). The p50 host gap shrank from `11.090 ns`
to `3.245 ns`.

Score: Impact `3` x Confidence `4` / Effort `2` = `6.0`; keep.

## Isomorphism Proof

- Ordering preserved: yes. A 256-byte block is skipped only when the OR of all eight exact
  byte-equality masks is false. A positive block is resolved by scanning 32-byte panels
  left-to-right, then bytes left-to-right inside the first matching panel.
- Tie-breaking preserved: yes. Multiple matches still return the lowest index because the
  resolver order is unchanged within the first positive folded block.
- Bounds and empty handling preserved: yes. `n.min(haystack.len())` clamping is unchanged,
  and the tail paths for sub-256-byte remainders are unchanged.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: direct `memchr` corpus SHA-256 remains
  `aec12be451b7b8803c8c57199f64dd2f40fc7c8894f3830e203eacaf0039f952`.

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_114_memchr_lib_tests RUST_TEST_THREADS=1 cargo test -p frankenlibc-core memchr --lib -- --nocapture --test-threads=1`
  - worker: `ts1`
  - result: pass, 9/9.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_114_memchr_property RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=256 cargo test -p frankenlibc-core --test property_tests memchr -- --nocapture --test-threads=1`
  - worker: `ts1`
  - result: pass, 2/2.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_114_check cargo check -p frankenlibc-core --all-targets`
  - worker: `ts2`
  - result: pass.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_114_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings -A clippy::question_mark -A clippy::too_many_arguments -A clippy::collapsible_if -A clippy::unnecessary_cast -A clippy::type_complexity -A clippy::byte_char_slices -A clippy::approx_constant -A clippy::unnecessary_min_or_max -A clippy::manual_repeat_n -A clippy::manual_memcpy -A clippy::needless_range_loop`
  - worker: `ts2`
  - result: pass.
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs crates/frankenlibc-core/tests/property_tests.rs`
  - result: pass.

Known unrelated blockers:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs` reports pre-existing
  formatting drift in the peer-touched memmem tests and test-vector cleanup.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/tests/property_tests.rs` reports
  pre-existing formatting drift outside the memchr golden block.
