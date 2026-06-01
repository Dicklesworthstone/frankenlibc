# malloc_bench — summary (frankenlibc-core allocator pass)

Worker: rch (AMD EPYC), bench profile, criterion --sample-size 50 --measurement-time 3.

| bench | median | note |
|-------|--------|------|
| bounded_index/raw_usize | 1.157 ns | raw `buckets[idx]` |
| bounded_index/bounded_try_from | 1.158 ns | `SizeClassIndex::try_from(idx)` + index |
| alloc_free_cycle/system/16..256 | ~98 ns | **system allocator** (`vec![0u8; sz]`), baseline ref |
| alloc_free_cycle/system/32768 | ~461 ns | system allocator, large |
| alloc_burst/1000x64B | 42.2 µs | system allocator burst, baseline ref |

**Findings:**
- `SizeClassIndex::try_from` bounded-index abstraction is **zero-overhead** (1.158 vs 1.157 ns) — REJECTS any "bounded-index costs us" hypothesis. No bead.
- The alloc_free_cycle / alloc_burst groups exercise the **Rust global/system allocator** (`vec![]`), NOT `frankenlibc-core::malloc`. They are a baseline reference only.
- COVERAGE GAP (not a hotspot): there is no bench that drives `frankenlibc-core::malloc` directly (it is not wired as `#[global_allocator]` in the bench crate), so the native size-class allocator's own latency is currently unmeasured here. Recommend a future bench that calls the core allocator API directly if allocator perf becomes a target.
