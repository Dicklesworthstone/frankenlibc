# bd-2g7oyh.404 malloc current-head focused gate

Date: 2026-06-14
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

`bd-2g7oyh.404` was opened from pass-105 current-head routing on
`vmi1227854`, which reported small-allocation residuals:

- `malloc_free_64`: FrankenLibC p50/mean `6.190/9.266 ns` vs host
  `3.879/5.389 ns`
- `malloc_free_256`: FrankenLibC p50/mean `6.721/9.234 ns` vs host
  `4.259/6.367 ns`

The focused gate had to reproduce the gap on clean current source before any
source edit.

Clean source worktree:

```text
/data/projects/.scratch/frankenlibc-bd-2g7oyh-404-baseline-20260614T224510Z
commit 51b972cf8d1b07e99afd1dfca4b4bf1db83cd3fc
```

Clean source fingerprints:

```text
4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
98340922b3b3f2daa38dc274a73b5197de91f5d439aac5092366ec988c126882  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

## Focused Baseline

First pinned run selected `vmi1227854` but failed during dependency rsync:
`kex_exchange_identification: read: Connection reset by peer`. Because
`RCH_REQUIRE_REMOTE=1` was set, local fallback was refused. This is transport
context only, not performance evidence.

Successful focused run:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd404-clean-baseline-target-20260614T224510Z-retry
CRITERION_HOME=/data/tmp/frankenlibc-bd404-clean-baseline-criterion-20260614T224510Z-retry
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
'glibc_baseline_(malloc_free_64|malloc_free_256|malloc_free_large)'
--noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`.

| row | impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `malloc_free_64` | FrankenLibC | `[5.9383 ns 6.1578 ns 6.3793 ns]` | 6.055 | 7.120 | 7.860 | 30.000 |
| `malloc_free_64` | host glibc | `[3.7340 ns 3.8863 ns 4.0586 ns]` | 3.933 | 7.207 | 10.000 | 40.000 |
| `malloc_free_256` | FrankenLibC | `[5.4025 ns 5.6927 ns 6.0209 ns]` | 5.504 | 6.710 | 8.750 | 35.000 |
| `malloc_free_256` | host glibc | `[3.8191 ns 3.9416 ns 4.0648 ns]` | 4.021 | 5.782 | 8.812 | 45.000 |
| `malloc_free_large` | FrankenLibC | `[6.0162 ns 6.0731 ns 6.1347 ns]` | 6.134 | 7.696 | 8.750 | 40.000 |
| `malloc_free_large` | host glibc | `[26.860 ns 27.567 ns 28.319 ns]` | 27.680 | 34.383 | 31.577 | 90.000 |

## Candidate Screen

No source lever was attempted for this bead.

The focused one-live small-object benchmark reaches this steady state after the
first iteration:

1. `free` parks the object in `thread_cache_hot_slots[bin]`.
2. the next `malloc` takes that exact hot slot before the general magazine,
   central bin, backend refill, elimination array, TLSF/slab-like storage, or
   any deeper intrusive list can run.
3. `pending_hot_accounting` is cleared by the exact matching `free`, preserving
   public counters without eager counter mutation in the exact one-live cycle.

The remaining small-row gap is real enough to route follow-up work, but this
bead's one-live benchmark does not exercise the allocator primitive families
that have not already been measured on this exact path. The no-retry families
for the one-live path include exact-size/cache shortcuts, Trace lifecycle gates,
fixed magazine/plain storage swaps, certificate/log specialization, hot-slot
metadata tweaks, lazy-accounting retunes, bitmap-only hot-slot representation,
and exact-class pre-certificate reordering.

## Graveyard Route

Canonical graveyard section 7.9 maps this symptom to modern allocator design:
mimalloc-style local pages and delayed remote frees, TLSF two-level bitmap
segregated fit, and slab allocation. Its perf contract requires profiling
fast-path hit rate, remote-free drain frequency, and fragmentation under a
representative workload before switching allocator internals.

For FrankenLibC, the next allocator attack is not another one-live hot-slot
micro-lever. It is a focused multi-object refill/cache-pressure target that
actually reaches the general magazine, central bins, slab/TLSF heads, and
spill paths. Expected target ratio for that route is `>=1.3x` on the deeper
allocator path with no change to single-object LIFO semantics.

## Isomorphism

No source code changed.

- Allocation/free ordering: unchanged by construction.
- Hot-slot LIFO behavior: unchanged by construction.
- Magazine displacement, central-bin spill, and elimination tie-breaking:
  unchanged by construction.
- `active_count`, `total_allocated`, lifecycle rows, and golden lifecycle
  hashes: unchanged by construction.
- Floating point and RNG: not involved.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The clean focused baseline reproduced p50 residuals for the small one-live
rows, but did not identify a source lever for this bead that is both
profile-honest and outside the already-rejected one-live hot-slot families.
The allocator route remains active through a new section-7.9-style multi-object
refill/cache-pressure bead, not by reusing this one-live gate.
