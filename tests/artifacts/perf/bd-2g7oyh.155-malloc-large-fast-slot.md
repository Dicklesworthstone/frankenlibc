# bd-2g7oyh.155 - malloc large active fast slot

## Target

Profile-backed target: `malloc_free_large` (65536-byte allocate/free cycle).

Pre-edit broad RCH profile on `ts2`:

- FrankenLibC: p50 `40.849 ns/op`, p95 `60.500 ns/op`, p99 `141.000 ns/op`, mean `44.323 ns/op`
- host glibc: p50 `30.296 ns/op`, mean `45.782 ns/op`

Focused pre-edit RCH baseline on `ts1`:

- FrankenLibC: p50 `25.206 ns/op`, p95 `32.168 ns/op`, p99 `40.000 ns/op`, mean `26.375 ns/op`
- host glibc: p50 `18.781 ns/op`, p95 `23.275 ns/op`, p99 `55.000 ns/op`, mean `25.012 ns/op`

## Lever

One lever: keep a single active `LargeAllocation` inline in `MallocState` and use the existing `LargeAllocator` map only for the uncommon multi-live-large-allocation case.

This removes the hash-table register/free/lookup path from the benchmarked common cycle while preserving backend callback invocation and public accounting.

## Behavior Proof

RCH behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd155_tests2 \
      RUST_TEST_THREADS=1 \
      cargo test -p frankenlibc-core malloc -- --nocapture --test-threads=1
```

Result on `ts1`: passed.

- `63` malloc/unit tests passed.
- `allocator_properties::prop_malloc_state_tracks_large_allocation_metadata` passed.
- Added `test_large_malloc_fast_slot_preserves_free_callback_and_metadata`.

Isomorphism obligations:

- Ordering/tie-breaking: N/A; allocator state transitions remain deterministic and single-threaded inside `MallocState`.
- Floating point: N/A.
- RNG: N/A.
- Backend callback observability: preserved. Large `free` still calls `free_fn(ptr)` for the fast slot.
- Metadata lookup: preserved. `large_allocation(ptr)` checks the fast slot before the map.
- Accounting: preserved. `active_large_count`, `total_large_mapped`, `total_allocated`, and `active_count` include the fast slot.
- Error paths: preserved for zero size, mapped-size overflow, null/zero backend pointer, and duplicate large pointer registration fallback.

Golden SHA evidence:

- `hot_cycle_lifecycle_record_sha256`: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`
- `malloc_bounds_audit`: `d9fc3e111580ec85638701db06c7be9ba8413cfb28d7fe5cf3d9331f0d28f0af`
- `tests/conformance/golden/fixture_verify_strict_hardened.v1.suite.json`: `a70dc7fad4679910cf938a65e8a18b3fec0823d9c739f931345624e0b406bdc1`

## Rebench

Post-edit focused RCH criterion rebench:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env FRANKENLIBC_BENCH_PIN=1 \
      CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd155_post \
      cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
      malloc_free_large --noplot --sample-size 40 --measurement-time 3 --warm-up-time 1
```

Post-edit result on `ts2`:

- FrankenLibC: p50 `13.166 ns/op`, p95 `17.500 ns/op`, p99 `30.000 ns/op`, mean `14.252 ns/op`
- host glibc: p50 `30.387 ns/op`, p95 `38.445 ns/op`, p99 `75.500 ns/op`, mean `38.848 ns/op`

Same-worker comparison against pre-edit `ts2` profile row:

- p50: `40.849 -> 13.166 ns/op` (`3.10x`)
- mean: `44.323 -> 14.252 ns/op` (`3.11x`)

Score: `Impact 3 x Confidence 3 / Effort 1 = 9.0`; keep.

## Validation

- `cargo +nightly fmt -p frankenlibc-core --check`: blocked by unrelated pre-existing formatting drift in `iconv`, `fnmatch`, differential probe tests, and other non-allocator files.
- `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd155_check cargo check -p frankenlibc-core --all-targets`: passed on `ts2`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd155_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by pre-existing lints in `regex.rs`, `wide.rs`, `fnmatch.rs`, `sort.rs`, and peer-owned `str.rs`; no `allocator.rs` diagnostics.
