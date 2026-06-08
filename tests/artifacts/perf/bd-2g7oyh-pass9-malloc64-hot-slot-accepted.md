# bd-2g7oyh.244: malloc_free_64 front hot-slot accepted

## Target

Fresh pass-9 RCH broad profile on worker `vmi1293453` showed `malloc_free_64`
remained a profile-backed allocator residual after the `bd-2g7oyh.189` front
hot-slot keep for non-64 small allocations.

Baseline command:

```bash
RCH_WORKER=vmi1293453 RCH_PREFERRED_WORKER=vmi1293453 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass9-broad-profile-20260608 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(memcmp_16|memcmp_256|memcmp_4096|memchr_absent|strchr_absent|memmove_4096|memcpy_4096|memset_4096|malloc_free_64|malloc_free_256|malloc_free_large|qsort_128_i32)' \
  --noplot --sample-size 35 --warm-up-time 1 --measurement-time 3
```

Key baseline rows on `vmi1293453`:

| row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean | note |
|---|---:|---:|---:|---:|---|
| `malloc_free_64` | 6.447 ns | 10.839 ns | 4.259 ns | 6.327 ns | target |
| `malloc_free_256` | 6.081 ns | 8.412 ns | 4.615 ns | 6.411 ns | guard |
| `malloc_free_large` | 8.405 ns | 10.173 ns | 38.902 ns | 48.507 ns | FL ahead |
| `memcmp_4096` | 55.194 ns | 58.813 ns | 40.066 ns | 42.662 ns | repeated family, not selected |

`memcmp_4096` remained a larger raw p50 gap, but pass 8 had just rejected the
folded-superblock/equality-control-plane family. The allocator sidecar triage
recommended a structural allocator route and excluded repeated memcmp families.

## Lever

Remove the exact-64 carve-out from the existing front hot-slot path. Exact
64-byte malloc/free cycles now use the same one-object per-size-class front slot
that was already accepted for 256-byte cycles, while the general magazine remains
the overflow stack behind that front slot.

This is one structural cache-layout lever. It does not change central bins,
elimination, large allocations, backend allocation, lifecycle record shape, or
logging thresholds.

## Behavior Proof

Isomorphism:

- Allocation accounting unchanged: `track_allocation`, `total_allocated`, and
  `active_count` updates remain in the same malloc/free positions.
- LIFO pointer reuse unchanged: the front hot slot is the logical stack top; a
  displaced object is pushed into the existing magazine only when capacity
  allows, preserving the same top-to-bottom order.
- Capacity unchanged: `thread_cache_hot_slot_preserves_lifo_order_and_capacity`
  proves the hot slot plus magazine still holds `MAGAZINE_CAPACITY` objects.
- Trace lifecycle ordering and fields unchanged for the 64-byte hot cycle:
  `hot_cycle_lifecycle_record_sha256_is_stable` stayed at
  `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.
- The 256-byte hot-slot lifecycle SHA also stayed at
  `eca20f7a00fb7f2dc41fcafde6f1d9f7184f585b492b87616dd9ef07e16e2729`.
- Floating-point and RNG are not involved.

Proof commands:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs
git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs

RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-244-proof-20260608 \
  cargo test -p frankenlibc-core malloc -- --nocapture --test-threads=1
```

Proof result:

- `rustfmt` and `git diff --check` passed for the touched allocator file.
- RCH `cargo test -p frankenlibc-core malloc` passed on `vmi1167313`: 65 unit
  tests plus `allocator_properties::prop_malloc_state_tracks_large_allocation_metadata`.

## Benchmark

Post command:

```bash
RCH_WORKER=vmi1293453 RCH_PREFERRED_WORKER=vmi1293453 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-244-post-20260608 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(malloc_free_64|malloc_free_256|malloc_free_large)' \
  --noplot --sample-size 45 --warm-up-time 1 --measurement-time 3
```

Same-worker before/after on `vmi1293453`:

| row | baseline FL p50 | baseline FL mean | post FL p50 | post FL mean | result |
|---|---:|---:|---:|---:|---|
| `malloc_free_64` | 6.447 ns | 10.839 ns | 5.893 ns | 8.172 ns | p50 +8.6%, mean +24.6% |
| `malloc_free_256` | 6.081 ns | 8.412 ns | 6.075 ns | 7.908 ns | guard neutral/improved |
| `malloc_free_large` | 8.405 ns | 10.173 ns | 8.253 ns | 9.844 ns | guard improved |

Keep score: `(Impact 4 * Confidence 4) / Effort 1 = 16.0`.

## Validation Notes

Final crate-scoped gates:

- RCH `vmi1167313` `cargo test -p frankenlibc-core malloc -- --nocapture --test-threads=1`
  passed: 65 malloc tests plus the allocator property, including
  `hot_cycle_lifecycle_record_sha256_is_stable`,
  `hot_cycle_static_lifecycle_details_are_borrowed`, and
  `hot_slot_lifecycle_record_sha256_is_stable`.
- RCH `vmi1149989` `cargo check -p frankenlibc-core --all-targets` passed.
- RCH `vmi1167313` `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`
  failed on pre-existing unrelated lints outside this allocator lever:
  `math/exp.rs` excessive precision constants, `stdio/file.rs`
  `unnecessary_unwrap`, and `string/regex.rs` collapsible-if /
  unnecessary-map-or diagnostics.
