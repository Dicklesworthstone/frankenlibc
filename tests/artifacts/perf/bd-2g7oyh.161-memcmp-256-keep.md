# bd-2g7oyh.161 memcmp_256 keep

Date: 2026-06-05
Worker: ts2
Scope: `crates/frankenlibc-core/src/string/mem.rs`

## Target

`glibc_baseline_memcmp_256` showed a same-suite gap on the equal-buffer workload:

- Broad profile: FrankenLibC p50 9.287 ns, mean 10.862 ns; host glibc p50 6.228 ns, mean 7.978 ns.
- Focused baseline command:
  `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 --noplot --sample-size 50`

Focused baseline:

- FrankenLibC: p50 7.571 ns, p95 11.045 ns, p99 25.000 ns, mean 9.155 ns.
- host glibc: p50 4.990 ns, p95 7.500 ns, p99 25.000 ns, mean 6.330 ns.

## Lever

Replace the exact `n == 256` equal-buffer certificate from two folded 128-byte reductions to one folded 256-byte safe-SIMD reduction using four 64-lane panels.

This is an equality-only shortcut. If any byte differs, execution falls through to the existing ordered resolver, so first-difference ordering and unsigned byte comparison are unchanged.

## Post Benchmark

Same command, same worker (`ts2`):

- FrankenLibC: p50 7.350 ns, p95 10.062 ns, p99 30.000 ns, mean 8.648 ns.
- host glibc: p50 4.959 ns, p95 6.875 ns, p99 25.000 ns, mean 6.558 ns.

Delta:

- p50: 7.571 ns -> 7.350 ns, 2.9% faster.
- mean: 9.155 ns -> 8.648 ns, 5.5% faster.

Score: `(Impact 2 * Confidence 4) / Effort 1 = 8.0`; keep.

## Behavior Proof

Command:

`RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1`

Result: passed on `ts2`.

Coverage:

- 29 focused `memcmp`-related unit tests passed, including ordering, antisymmetry, scalar equivalence, timing-safe memcmp, wide memcmp, and the new exact-256 guard.
- `string_properties::golden_memcmp_corpus_sha256` passed.
- `string_properties::prop_memcpy_then_memcmp_is_zero` passed.

Isomorphism:

- Equal exact-256 buffers return `Ordering::Equal` after one 256-byte equality certificate.
- Any non-equal exact-256 buffer falls through to the existing first-difference resolver.
- Tie-breaking, unsigned byte ordering, and `n` clamping are unchanged.
- No floating-point or RNG behavior is involved.

Golden fixture hashes:

- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/string_memory_hotpaths.json`: `3dfa8b35df1dcc43244a1c1a9105d6ca44ea418c7b8c4c8db40919867cade170`
- `tests/conformance/fixtures/string_memory_hotpaths_wave10.json`: `65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845`

## Build Gates

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: passed.
- `cargo fmt -p frankenlibc-core --check`: blocked by committed concurrent log2-lane `crates/frankenlibc-core/src/math/exp.rs` table formatting; `mem.rs` is clean.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`: passed on `ts2`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by committed concurrent log2-lane `exp.rs` `clippy::excessive_precision` diagnostics.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings -A clippy::excessive_precision`: passed on `ts2`.
