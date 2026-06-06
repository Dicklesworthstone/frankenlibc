# bd-2g7oyh.189: allocator front hot-slot accepted

## Target

Fresh RCH baseline on worker `ts1` shifted the strongest allocator gap from the filed `malloc_free_64` row to `malloc_free_256`, while keeping the work inside the same allocator bead and file reservation.

Baseline command:

```bash
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-189-baseline-20260606 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  -- 'glibc_baseline_(malloc_free_64|malloc_free_256|malloc_free_large)' \
  --noplot --sample-size 45 --warm-up-time 1 --measurement-time 3
```

## Lever

Add a one-object front hot slot per size class in `MallocState`, before the existing magazine cache, but keep exact 64-byte requests on the previous hot-cert magazine path. On free, a new object displaces the prior hot slot into the magazine only while total hot-slot-plus-magazine occupancy remains within `MAGAZINE_CAPACITY`; otherwise the current object spills exactly as before.

This is one structural cache-layout lever: avoid `Vec` push/pop traffic for the profiled one-live non-64 small allocation cycles without changing central-bin, elimination, backend, or lifecycle semantics.

## Behavior Proof

Isomorphism:
- Allocation accounting is unchanged: `track_allocation` and free-side saturating subtraction remain in the same places.
- Pointer reuse order is unchanged for cacheable small allocations: the hot slot is the logical magazine top, and displacement preserves LIFO. Capacity remains 64 total cached objects, proven by `thread_cache_hot_slot_preserves_lifo_order_and_capacity`.
- Trace lifecycle ordering/tie-breaking is unchanged for the existing 64-byte path; the optimized 256-byte path still emits `path=thread_cache` with the same event shape.
- Floating-point and RNG are not involved.

Golden SHA:
- Existing 64-byte lifecycle SHA unchanged: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.
- New optimized 256-byte hot-slot lifecycle SHA: `eca20f7a00fb7f2dc41fcafde6f1d9f7184f585b492b87616dd9ef07e16e2729`.

Proof commands:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs crates/frankenlibc-core/src/malloc/thread_cache.rs
git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs crates/frankenlibc-core/src/malloc/thread_cache.rs

RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-189-proof4-20260606 \
  cargo test -p frankenlibc-core malloc -- --nocapture --test-threads=1
```

Proof result: `65 passed; 0 failed; 2995 filtered out` plus `allocator_properties::prop_malloc_state_tracks_large_allocation_metadata` passed.

## Benchmark

Final candidate command:

```bash
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-189-candidate2-20260606 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench \
  -- 'glibc_baseline_(malloc_free_64|malloc_free_256|malloc_free_large)' \
  --noplot --sample-size 45 --warm-up-time 1 --measurement-time 3
```

| row | baseline FL p50 | baseline FL mean | candidate FL p50 | candidate FL mean | result |
|---|---:|---:|---:|---:|---|
| `malloc_free_64` | 6.452 ns | 7.265 ns | 6.183 ns | 7.446 ns | p50 +4.2%, mean noisy/slightly worse |
| `malloc_free_256` | 12.860 ns | 13.101 ns | 5.982 ns | 6.907 ns | p50 +53.5%, mean +47.3% |
| `malloc_free_large` | 9.626 ns | 10.583 ns | 8.860 ns | 9.714 ns | p50 +8.0%, mean +8.2% |

Host rows moved materially during the same bench family, so the keep decision is based on direct FrankenLibC same-worker before/after rows.

Score: `(Impact 5 * Confidence 4) / Effort 2 = 10.0`, keep.

## Verification Notes

`cargo check -p frankenlibc-core --all-targets` passed on `ts1`.

`cargo clippy -p frankenlibc-core --all-targets -- -D warnings` was rerun after fixing the allocator `collapsible_if`; it now fails only on pre-existing unrelated diagnostics in `math/exp.rs`, `stdio/file.rs`, and `string/regex.rs`.

Workspace `cargo fmt --check` is blocked by existing unrelated formatting drift in peer-owned ABI/math/string/test files. Touched allocator files pass `rustfmt --edition 2024 --check`.
