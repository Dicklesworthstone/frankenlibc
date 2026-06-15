# bd-2g7oyh.430 - memcmp_256 public inline rejection

Date: 2026-06-15
Agent: BoldFalcon
Target: `glibc_baseline_memcmp_256`
Worker: `vmi1227854`

## Profile-backed target

Pass 131 broad routing on pushed head `857380693` still showed `memcmp_256` as a material string residual after the XOR-accumulator keep:

- FrankenLibC Criterion: `[4.6460 ns 4.7088 ns 4.7791 ns]`
- FrankenLibC p50/mean: `4.728/5.979 ns`
- Host Criterion: `[2.9979 ns 3.0564 ns 3.1146 ns]`
- Host p50/mean: `3.191/4.957 ns`

Focused same-worker baseline reproduced the gap:

- FrankenLibC Criterion: `[4.3559 ns 4.4407 ns 4.5350 ns]`
- FrankenLibC p50/mean: `4.505/5.925 ns`
- Host Criterion: `[3.1187 ns 3.3168 ns 3.5228 ns]`
- Host p50/mean: `3.032/3.749 ns`

## One tested lever

Tested adding `#[inline(always)]` to the public `frankenlibc_core::string::memcmp` wrapper. The exact-size helpers and comparison body were unchanged.

This was a different codegen-boundary lever from the prior XOR/OR accumulator keep, intended to expose the existing exact-256 equality certificate to the benchmark call site.

## Behavior proof

RCH `cargo test -j 1 -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1` passed 32/32 filtered tests, including:

- `test_memcmp_exact_256_equal_certificate_guard`
- `test_memcmp_exact_4096_certificate_preserves_ordering`
- `test_memcmp_preserves_first_difference_inside_bulk_chunk`
- `memcmp_golden_output_sha256`

RCH `cargo test -j 1 -p frankenlibc-core --test property_tests golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1` passed.

Golden SHAs covered by the passing tests:

- Unit `memcmp_golden_output_sha256`: `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`
- Property `golden_memcmp_corpus_sha256`: `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`

Preserved by proof: first-difference ordering, unsigned byte ordering, equality handling, zero-length behavior, clamped `n`, 16/256/4096 exact-size certificates, floating-point behavior, RNG behavior, allocation behavior, errno behavior, and locale behavior.

## Post-benchmark

RCH post benchmark with the same focused filter and sample size:

- Candidate FrankenLibC Criterion: `[5.4796 ns 5.6633 ns 5.8573 ns]`
- Candidate FrankenLibC p50/mean: `5.576/6.817 ns`
- Host Criterion: `[3.4109 ns 3.4859 ns 3.5635 ns]`
- Host p50/mean: `3.495/4.513 ns`

Same-worker self delta vs focused baseline:

- p50: `4.505 -> 5.576 ns`, `23.8%` slower
- mean: `5.925 -> 6.817 ns`, `15.1%` slower
- Criterion center: `4.4407 -> 5.6633 ns`, `27.5%` slower

## Validation and restore

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: passed before benchmark
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: passed before benchmark
- Source restored after rejection; no production source change is retained.

Restored SHAs:

- `crates/frankenlibc-core/src/string/mem.rs`: `088d2f0f8560cb76be215f584ef2adbffe9fae5135b28045655e2bf23cbbb14c`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`

## Verdict

REJECTED-RESTORED.

Score: `0.0`.

Do not retry public-wrapper inlining for `memcmp_256`. The next `memcmp_256` route must be a materially different generated/backend-dispatch primitive or a new exact-size lowering, not wrapper-boundary exposure.
