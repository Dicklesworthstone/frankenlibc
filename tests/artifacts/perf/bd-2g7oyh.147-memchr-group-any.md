# bd-2g7oyh.147 - memchr folded group any predicate

Status: kept.

## Target

- Bead: `bd-2g7oyh.147`
- Hotspot: `memchr_absent_4096`
- Source: `crates/frankenlibc-core/src/string/mem.rs`
- Lever: keep the folded 256-byte `memchr` absent check in SIMD mask space and call
  `.any()` once, instead of extracting eight per-panel bitmasks for the group test.

The exact candidate-mask extraction remains in the positive-block resolver, so first-match
ordering is unchanged.

## Profile Evidence

Broad RCH profile on `ts2` before selecting the target:

- FrankenLibC `memchr_absent`: p50 `47.134 ns`, p95 `60.000 ns`, p99 `93.930 ns`, mean `50.178 ns`
- Host glibc `memchr_absent`: p50 `31.882 ns`, mean `33.987 ns`

Focused RCH baseline on `ts1`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memchr147_baseline cargo bench -p frankenlibc-bench --bench string_bench -- memchr_absent --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot`
- `memchr_absent_4096`: Criterion around `31.129 ns`; raw p50 `30.803 ns`, p95 `45.000 ns`, p99 `71.777 ns`, mean `34.551 ns`

Focused RCH post-bench on `ts1`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memchr147_post cargo bench -p frankenlibc-bench --bench string_bench -- memchr_absent --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot`
- `memchr_absent_4096`: Criterion around `29.352 ns`; raw p50 `29.063 ns`, p95 `37.764 ns`, p99 `45.500 ns`, mean `31.335 ns`

Same-worker exact-row confirmation on `ts1`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memchr147_confirm cargo bench -p frankenlibc-bench --bench string_bench -- 'memchr_absent/raw/4096' --warm-up-time 1 --measurement-time 3 --sample-size 40 --noplot`
- `memchr_absent_4096`: Criterion around `20.238 ns`; raw p50 `20.480 ns`, p95 `27.904 ns`, p99 `50.000 ns`, mean `23.217 ns`

Primary same-command comparison:

- p50: `30.803 ns -> 29.063 ns`, `1.06x` faster
- mean: `34.551 ns -> 31.335 ns`, `1.10x` faster
- p95: `45.000 ns -> 37.764 ns`
- p99: `71.777 ns -> 45.500 ns`

Score: Impact `2` x Confidence `4` / Effort `1` = `8.0`; keep.

## Isomorphism Proof

- Ordering preserved: yes. A 256-byte folded block is skipped only when no lane in any
  of the eight 32-byte panels equals the needle.
- Tie-breaking preserved: yes. Positive blocks still resolve panels left-to-right via
  `first_byte_simd_32`, and that resolver still returns the lowest set bit.
- Bounds preserved: yes. `n.min(haystack.len())`, folded-block length, SIMD panel
  length, and tail paths are unchanged.
- Floating point: not applicable.
- RNG: not applicable.

## Golden SHA-256

- `tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json`:
  `a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1`
- `tests/conformance/fixtures/string_memory_hotpaths_wave10.json`:
  `65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845`

## Validation

- `rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: pass
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: pass
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memchr147_test cargo test -p frankenlibc-core memchr --lib -- --nocapture`
  - worker: `ts2`
  - result: pass, 10/10.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memchr147_check cargo check -p frankenlibc-core --all-targets`
  - worker: `ts2`
  - result: pass.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_memchr147_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings`
  - result: blocked by pre-existing unrelated lint debt in `regex.rs` and `wide.rs`; no
    diagnostics came from `mem.rs`.
