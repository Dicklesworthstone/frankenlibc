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

## 2026-06-05 follow-up loop

Baseline (RCH `ts1`, `glibc_baseline_bench malloc_free`, warm-up 1s,
measurement 2s, sample-size 20):

| profile         | frankenlibc p50 | glibc p50 | fl/glibc |
|-----------------|-----------------|-----------|----------|
| malloc_free_64  | 5.956 ns        | 4.993 ns  | 1.19x    |
| malloc_free_256 | 5.759 ns        | 4.748 ns  | 1.21x    |

Behavior proof used for all attempted allocator/thread-cache levers:
`RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p
frankenlibc-core malloc:: --lib -- --nocapture --test-threads=1`:
63/63 passed, including `hot_cycle_lifecycle_record_sha256_is_stable`.

Rejected levers:

- Fixed-capacity per-bin magazine array (`[[usize; 64]; NUM_SIZE_CLASSES]`
  equivalent): behavior proof passed, but same-worker follow-up did not show a
  stable keep. `ts2` post rows oscillated from modest normalized improvement
  (`64` 8.703 vs glibc 7.634; `256` 8.816 vs glibc 7.551) to regression/noise
  (`64` 9.967 vs glibc 7.973; `256` 9.975 vs glibc 7.651). This repeats the
  earlier `bd-2g7oyh.48-thread-cache-array` rejection and should not be
  re-attempted as a plain storage-layout swap.
- One-entry hot LIFO slot in `MallocState`: behavior proof passed and lifecycle
  sha256 stayed stable, but the post-change row did not clear the keep gate
  (`ts2`: `64` 9.117 vs glibc 7.564, `256` 9.285 vs glibc 7.993).
- Production-only elimination compile-out was investigated because the
  elimination handle is private in non-test builds. It remained noisy rather
  than a defensible Score>=2.0 keep under RCH worker churn (`ts2` best p50 ratio
  around 1.14x for `64`, but `ts1` emitted p50 worsened under outlier shape).
  Do not count this as a shipped win without a cleaner same-worker A/B harness.

Conclusion: this bead's simple allocator/bookkeeping levers are rejected. The
next valid no-gaps primitive must replace the data structure, not tune the same
Vec/magazine path: an intrusive safe-Rust index-linked LIFO/slab for cached
objects plus deferred/batched hot-path observability counters, with a dedicated
same-worker A/B harness that prevents RCH source-artifact churn from polluting
the working tree.
