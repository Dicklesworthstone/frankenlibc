# bd-2g7oyh.142 - strspn_long contiguous range classifier

## Target

Profile-backed hotspot: `glibc_baseline_strspn_long/strspn_long/frankenlibc_core`.

Workload: 4096-byte `strspn` over accept set `abcdefgh`.

Fresh RCH baseline on `ts1` before edit:

- FrankenLibC p50 245.391 ns, p95 547.375 ns, p99 580.781 ns, mean 288.658 ns.
- Host glibc p50 166.729 ns, p95 228.279 ns, p99 237.195 ns, mean 166.964 ns.

## Lever

One safe-Rust classifier lever in `crates/frankenlibc-core/src/string/str.rs`:

- Certify when the real membership table is one contiguous byte interval.
- Dispatch only those sets to a 32-byte SIMD range classifier.
- Keep the existing table as the scalar resolver for the first uncertain chunk.
- Preserve the existing padded 8/16-way equality classifier for non-contiguous sets.

An initial 64-byte panel plus full 256-entry table certification regressed and was not kept:

- FrankenLibC p50 2047.550 ns, p95 3315.070 ns, p99 3526.000 ns, mean 2297.481 ns on `ts1`.

The kept shape uses O(set width) certification and the existing 32-byte panel width.

## Post-Benchmark

RCH post-benchmark on the same worker, `ts1`:

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ts1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd142_post2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'strspn_long' --warm-up-time 1 --measurement-time 3 --sample-size 50 --noplot`
- FrankenLibC p50 123.449 ns, p95 261.750 ns, p99 295.500 ns, mean 138.353 ns.
- Host glibc p50 144.654 ns, p95 185.312 ns, p99 274.113 ns, mean 152.698 ns.

Same-worker p50 improvement: 245.391 ns -> 123.449 ns, 1.99x faster.

Score: `(Impact 4 * Confidence 4) / Effort 2 = 8.0`.

## Isomorphism Proof

`accept` and `reject` strings are bounded by `strlen`, so NUL is not a member of the set.

The new dispatch is taken only when `table[lo..=hi]` is fully true for the min/max byte range computed from the real set. Therefore, for every non-NUL byte `b`, `lo <= b <= hi` is equivalent to `table[b] == true`.

For `strspn`, the SIMD path fast-forwards only when every lane is a member. A NUL lane is below `lo` and therefore non-member, so NUL still forces scalar resolution at the earliest byte.

For `strcspn` and `strpbrk`, the SIMD path stops when any lane is a member or NUL. The scalar resolver still checks `byte == 0 || table[byte] == stop_in_set`, preserving the exact first-stop index and `strpbrk`'s `Some(index)` vs `None` mapping.

Ordering and tie-breaking: first stop byte is unchanged because every uncertain chunk is resolved from low to high index with the original table.

Floating point and RNG: not applicable.

## Golden Hashes

Unchanged after the source-only optimization:

- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/memory_ops.json`: `c2e63ee0140a27b9ad8286edc115eebade440e1c06040ebdc21dea8ee285a1dc`
- `crates/frankenlibc-core/tests/property_tests.rs`: `20c73d64d39caa6e175c63e362673354bb9d93e16625658b31225ae4a5da2d98`

## Validation

- `RCH_WORKER=ts1 cargo test -p frankenlibc-core span_general -- --nocapture --test-threads=1`: passed, 2 tests.
- `RCH_WORKER=ts1 cargo check -p frankenlibc-core --all-targets`: passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed.

Known pre-existing validation blockers:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs` reports unrelated existing formatting drift outside this lever.
- `RCH_WORKER=ts1 cargo clippy -p frankenlibc-core --all-targets -- -D warnings` is blocked by unrelated existing lints in `regex.rs`, `fnmatch.rs`, `sort.rs`, `wide.rs`, and pre-existing byte-slice style warnings in the older `span_general_matches_scalar_oracle` test.
