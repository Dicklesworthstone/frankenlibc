# bd-4scbmf — malloc small/med is structurally slower than glibc (not log overhead)

## Measured gap (glibc_baseline_bench, worker-independent g/fl ratio)

| profile            | fl ns | glibc ns | g/fl  | verdict                    |
|--------------------|-------|----------|-------|----------------------------|
| malloc_free_64     | 6.61  | 4.87     | 0.74  | fl **1.36x slower**        |
| malloc_free_256    | 5.81  | 4.85     | 0.83  | fl **1.20x slower**        |
| malloc_free_large  | 8.14  | 18.16    | 2.23  | fl **2.23x faster** (mmap) |

The large path already beats glibc. The small/medium fast path is the gap.

## Rejected micro-lever (do NOT re-attempt)

The malloc thread-cache-**hit** path (`allocator.rs` ~457) and free thread-cache
path (~637) call the non-`#[inline]` `record_lifecycle` **unguarded**, unlike the
large/elimination paths which wrap it in
`if (Trace as u8) >= (self.min_log_level as u8)`. Hypothesis: the unguarded call
is per-op overhead. **Result: REJECTED** — same-session A/B was perf-neutral
(g/fl 0.873 → 0.876, noise). The release build (`lto = true`) already inlines
`record_lifecycle`, so its `min_log_level` early-return short-circuits at the
call site regardless of an explicit guard. Prior wins already gated the
`format!`/log-push costs. There is no removable log/format overhead left.

## Root cause: structural per-op bookkeeping

The gap is the cost of FrankenLibC's safety + observability design, which glibc's
raw tcache lacks. Per small malloc/free the hot path pays, on top of the actual
free-list pop/push:
- `can_track_allocation(size)` + `track_allocation(size)` — overflow-checked
  global allocation counters.
- `thread_cache_hits` / `thread_cache_misses` counters.
- `size_class_certificate` precheck (cheap when waste==0, i.e. exact class).
- a **bounds-checked `Vec<Magazine{objects: Vec<usize>}>` pop** (nested Vec
  index + len check) vs glibc's raw singly-linked LIFO:
  `e = entries[i]; entries[i] = e->next; counts[i]--; return e;` (3-4 insns,
  no bounds checks, no nested indirection).

## Next big swing (the directive's arena/slab target)

Redesign the small-alloc fast path to a glibc-tcache-class **flat
index-linked LIFO**:
- replace the per-bin `objects: Vec<usize>` with a flat array + intrusive
  free-index links (still 100% safe Rust; indices, not pointers), so a pop is a
  single array read + head update with the bounds check provably elided;
- move the observability counters OFF the hot path (batch/defer, or only update
  under the Trace gate), keeping byte-identical logs when Trace is enabled;
- keep `#![forbid(unsafe_code)]` and the full lifecycle trace available behind
  `min_log_level`.

Target: malloc_free_64 g/fl 0.74 → ~1.0. Multi-hour, soundness-critical
(allocator core). Coordinate before editing — recently peer-touched
(b5f99f36 / 8cdfb50c). Files: `crates/frankenlibc-core/src/malloc/{allocator.rs,
thread_cache.rs}`.
