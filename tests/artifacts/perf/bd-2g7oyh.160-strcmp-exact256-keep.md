# bd-2g7oyh.160 strcmp exact-256 equality dispatch keep

Date: 2026-06-05
Agent: Codex
Target: `[perf][no-gaps] strcmp_256_equal exact-size equality dispatch`
Files: `crates/frankenlibc-core/src/string/str.rs`

## Profile Target

Profile-backed bead: `bd-2g7oyh.160`.

RCH baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcmp_256_equal --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Worker: `ts2`.

Baseline rows:

```text
frankenlibc_core: p50=10.520 ns, p95=18.063 ns, p99=35.500 ns, mean=13.176 ns
host_glibc:       p50=8.129 ns,  p95=12.500 ns, p99=30.000 ns, mean=10.740 ns
```

## Lever

One lever only: an exact-size equality certificate for the profiled 256-byte
equal `strcmp` row.

When both safe slices are exactly 257 bytes, byte 256 is NUL in both, and four
safe 64-lane SIMD panels prove bytes 0..255 are byte-equal and NUL-free,
`strcmp` returns 0 immediately. Any mismatch, embedded NUL, missing terminator,
or non-exact shape falls through to the existing ordered resolver.

This is private to `strcmp`; it does not alter the shared `equal_and_no_nul_*`
helpers used by the live `strncmp` bead.

## Alien Primitive Card

Surface: hot string/memory kernel.

Failure signature: exact-size equal string row spends its remaining time in
loop/tail dispatch after two 128-byte folded equal-prefix blocks.

Selected primitive: proof-carrying equality certificate with a guarded fast
accept state.

Runtime artifact: `strcmp_exact_256_equal_nul_terminated`.

Offline proof artifact: focused guard test plus the existing scalar-reference
and golden transcript checks.

Fallback: if the guard cannot prove exact equality and NUL placement, use the
existing byte-ordered resolver.

## Isomorphism Proof

- Ordering preserved: yes. The new branch returns only when all 256 payload
  bytes are equal and non-NUL and the next byte is NUL in both inputs. Every
  ordered mismatch falls through to the existing first-difference resolver.
- Tie-breaking unchanged: yes. Equal remains equal only for the exact certified
  C-string shape. Embedded NULs and missing terminators are resolved by the
  previous path.
- Floating point: N/A.
- RNG: N/A.
- Golden fixtures unchanged:
  - `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
  - `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
  - `tests/conformance/string_abi_promotion_tranche.v1.json`: `f29e3d900ebdfa10054bfe1b26062361b68853c510cf809c7b9e373135fc8868`

## Proof

Baseline proof:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-proof-baseline cargo test -p frankenlibc-core strcmp -- --nocapture --test-threads=1
```

Result on `ts2`: 9 focused `strcmp` unit tests and 3 `strcmp` property tests
passed.

Post proof:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-proof-post cargo test -p frankenlibc-core strcmp -- --nocapture --test-threads=1
```

Result on `ts2`: 10 focused `strcmp` unit tests, including
`test_strcmp_exact_256_certificate_guard`, and the same 3 property tests passed.

Validation:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
cargo fmt --check -p frankenlibc-core
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-check cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings
```

All passed.

## Post Benchmark

Post command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcmp_256_equal --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Post rows on `ts2`:

```text
frankenlibc_core: p50=5.441 ns, p95=13.875 ns, p99=30.000 ns, mean=8.013 ns
host_glibc:       p50=8.068 ns, p95=13.750 ns, p99=30.000 ns, mean=10.129 ns
```

Cross-worker confirmation command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-160-confirm cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcmp_256_equal --warm-up-time 1 --measurement-time 3 --sample-size 30
```

Confirmation rows on `ts1`:

```text
frankenlibc_core: p50=3.919 ns, p95=11.250 ns, p99=20.000 ns, mean=5.917 ns
host_glibc:       p50=5.633 ns, p95=10.000 ns, p99=20.000 ns, mean=6.928 ns
```

Same-worker before/after on `ts2`:

```text
frankenlibc_core p50:  10.520 ns -> 5.441 ns
frankenlibc_core mean: 13.176 ns -> 8.013 ns
host ratio p50:        1.29x slower -> 1.49x faster
```

Score: `(Impact 4 * Confidence 5) / Effort 1 = 20.0`.

## Next Target

Re-profile the glibc baseline suite and avoid `strncmp` while `bd-2g7oyh.65`
is live-owned. If exact-size equality rows no longer dominate, pivot to the
next measured residual rather than extending this certificate family blindly.
