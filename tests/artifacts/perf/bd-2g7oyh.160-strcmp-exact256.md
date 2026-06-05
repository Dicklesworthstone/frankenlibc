# bd-2g7oyh.160 - strcmp exact-256 equality certificate

Timestamp: 2026-06-05T23:27:00Z
Agent: Codex

## Target

Profile-backed target from the bead handoff:

- `glibc_baseline_strcmp_256_equal` on `ts2`: FrankenLibC p50 10.739 ns/op, mean 13.163; host glibc p50 8.362, mean 11.096.

The accepted lever adds a private safe-SIMD exact-shape certificate for
`strcmp`: when both inputs are exactly 257 bytes, byte 256 is NUL in both, and
the first 256 bytes are equal and NUL-free, `strcmp` returns zero immediately.
Every mismatch, early NUL, one-sided terminator, missing terminator, or
non-exact shape falls through to the existing ordered resolver.

## Benchmark Evidence

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcmp_256_equal --noplot --sample-size 50
```

Baseline on `ts1` before edit:

- FrankenLibC: p50 7.121 ns/op, p95 10.625, p99 25.000, mean 9.793
- host glibc: p50 6.001 ns/op, p95 11.002, p99 30.000, mean 7.865

Post on `ts1` after edit, same command:

- FrankenLibC: p50 3.815 ns/op, p95 9.375, p99 25.000, mean 6.522
- host glibc: p50 5.535 ns/op, p95 8.188, p99 25.000, mean 6.743

Same-worker `ts1` speedup:

- p50: 7.121 ns -> 3.815 ns, 1.87x faster
- mean: 9.793 ns -> 6.522 ns, 1.50x faster

Confirmation on `ts2` after edit:

- FrankenLibC: p50 5.485 ns/op, p95 7.500, p99 30.000, mean 6.855
- host glibc: p50 8.094 ns/op, p95 13.750, p99 35.000, mean 11.162

Score: (Impact 3 * Confidence 5) / Effort 2 = 7.5.

## Isomorphism Proof

- Ordering: the certificate returns only for exact equality over bytes 0..256
  plus equal NUL terminators; every first-difference position uses the existing
  signed byte-difference resolver.
- Tie-breaking: the only certified result is zero, exactly matching scalar
  `strcmp` for equal 256-byte C strings.
- NUL behavior: any NUL before byte 256 rejects the certificate and preserves
  the existing early-terminator semantics.
- Terminator behavior: a one-sided non-NUL byte 256 rejects the certificate and
  preserves signed terminator ordering; two-sided non-NUL byte 256 rejects and
  preserves the safe-slice fallback semantics.
- Floating point and RNG: not applicable; this path is integer-only and
  deterministic.

Golden sha256 after the edit:

```text
27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89  tests/conformance/fixtures/string_ops.json
94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4  tests/conformance/fixtures/string_memory_full.json
3dfa8b35df1dcc43244a1c1a9105d6ca44ea418c7b8c4c8db40919867cade170  tests/conformance/fixtures/string_memory_hotpaths.json
65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845  tests/conformance/fixtures/string_memory_hotpaths_wave10.json
fc3812158b5f287c2084d8c03f920b93ee1a1163da4d027f0587d4d961f240d5  crates/frankenlibc-core/src/string/str.rs
```

RCH behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core strcmp -- --nocapture --test-threads=1
```

Passed on `ts1`: 10 filtered `strcmp` unit tests, including
`test_strcmp_exact_256_certificate_guard` and
`test_strcmp_golden_transcript_sha256`, plus 3 external `property_tests`
`strcmp` properties.

Validation:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
cargo fmt -p frankenlibc-core --check
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings
```

All passed. The remote `check` ran on `vmi1227854`; the remote `clippy` ran on
`ts1`.
