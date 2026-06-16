# bd-2g7oyh.434 - memcmp_16 u128 equality certificate keep

Date: 2026-06-16
Agent: BoldFalcon
Target: `glibc_baseline_memcmp_16`
Worker: `vmi1227854`

## Profile-backed target

Pass 135 broad routing after `bd-2g7oyh.433` showed `memcmp_16` as a
material small-string residual on the current pushed head:

- FrankenLibC p50/mean: `2.470/4.763 ns`
- Host p50/mean: `1.968/3.364 ns`

Focused same-worker baseline reproduced the gap and measured the adjacent
`memcmp_256` row as a guard:

- `memcmp_16` FrankenLibC Criterion: `[2.2531 ns 2.3004 ns 2.3486 ns]`
- `memcmp_16` FrankenLibC p50/mean: `2.378/3.925 ns`
- `memcmp_16` host Criterion: `[1.9442 ns 1.9936 ns 2.0489 ns]`
- `memcmp_16` host p50/mean: `1.981/3.021 ns`
- `memcmp_256` guard FrankenLibC Criterion: `[4.1994 ns 4.3170 ns 4.4536 ns]`
- `memcmp_256` guard FrankenLibC p50/mean: `4.528/6.118 ns`

## One lever

Replace the exact-16 equality certificate's portable-SIMD `simd_ne` mask with
one safe Rust native-endian `u128` equality load:

```rust
if u128_from_exact_16(a) == u128_from_exact_16(b) {
    return core::cmp::Ordering::Equal;
}

compare_bytes(a, b)
```

This is an equality-only certificate. It never decides ordering. If the 16-byte
words differ, the implementation falls through to the existing bytewise
first-difference resolver.

## Behavior proof

RCH focused unit tests:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-core --lib memcmp \
  -- --nocapture --test-threads=1
```

Result: passed 32/32 filtered tests, including:

- `memcmp_exact_16_mask_resolves_first_difference`
- `memcmp_golden_output_sha256`
- exact-256 and exact-4096 guards
- antisymmetry and std-lexicographic properties
- timingsafe memcmp and wide memcmp guards

RCH property golden:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-core --test property_tests \
  golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
```

Result: passed 1/1 filtered test.

Golden hashes:

- `string::mem::tests::memcmp_golden_output_sha256`: `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`
- `string_properties::golden_memcmp_corpus_sha256`: `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`
- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/string_memory_hotpaths.json`: `3dfa8b35df1dcc43244a1c1a9105d6ca44ea418c7b8c4c8db40919867cade170`
- `tests/conformance/fixtures/string_memory_hotpaths_wave10.json`: `65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845`

Isomorphism:

- Equal exact-16 buffers still return `Ordering::Equal` only after all 16 bytes
  are proven equal.
- Non-equal exact-16 buffers still use the existing `compare_bytes` resolver,
  preserving first-difference tie-breaking and unsigned-byte ordering.
- Native-endian conversion is unobservable for equality because it only answers
  whether the full 16-byte value is identical.
- `n` clamping, zero-length behavior, non-16 sizes, exact-256 behavior,
  exact-4096 behavior, floating-point behavior, RNG behavior, allocation
  behavior, errno behavior, and locale behavior are unchanged.

Source SHA after the lever:

- `crates/frankenlibc-core/src/string/mem.rs`: `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`

## Post benchmark

RCH command:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_memcmp_(16|256)' --noplot --sample-size 80 \
  --warm-up-time 1 --measurement-time 3
```

Post result:

- `memcmp_16` FrankenLibC Criterion: `[1.5902 ns 1.6561 ns 1.7213 ns]`
- `memcmp_16` FrankenLibC p50/mean: `1.533/2.346 ns`
- `memcmp_16` host Criterion: `[1.9407 ns 2.0077 ns 2.0756 ns]`
- `memcmp_16` host p50/mean: `1.922/2.663 ns`
- `memcmp_256` guard FrankenLibC Criterion: `[4.2317 ns 4.3172 ns 4.4134 ns]`
- `memcmp_256` guard FrankenLibC p50/mean: `4.642/5.658 ns`

Same-worker self delta for `memcmp_16`:

- p50: `2.378 -> 1.533 ns`, `35.5%` lower
- mean: `3.925 -> 2.346 ns`, `40.2%` lower
- Criterion center: `2.3004 -> 1.6561 ns`, `28.0%` lower

The `memcmp_16` row now beats the host row by p50 and mean on the focused
same-worker gate. The `memcmp_256` guard did not regress by Criterion center
(`4.3170 -> 4.3172 ns`) and improved by mean (`6.118 -> 5.658 ns`), with only a
small p50 wobble (`4.528 -> 4.642 ns`).

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: passed
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: passed
- RCH `cargo check -j 1 -p frankenlibc-core --all-targets`: passed
- RCH strict `cargo clippy -j 1 -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated pre-existing lints:
  - `crates/frankenlibc-core/src/resolv/dns_name.rs:411` `clippy::single_match`
  - `crates/frankenlibc-core/src/resolv/mod.rs:316` `clippy::explicit_counter_loop`
- RCH allowlisted `cargo clippy -j 1 -p frankenlibc-core --all-targets -- -D warnings -A clippy::single_match -A clippy::explicit_counter_loop`: passed

## Verdict

KEPT.

Score: `(Impact 3.0 x Confidence 4.5) / Effort 1.0 = 13.5`.

Next route: reprofile current head. Do not return to `memcmp_16` without a
fresh material same-worker residual and a materially different primitive.
