# bd-2g7oyh.404 malloc hot-cycle focused gate

Date: 2026-06-14
Agent: BoldFalcon
Worker: `vmi1153651`
Status: NO-CODE REJECTED

## Routing Evidence

Pass 105 current-head routing selected allocator hot-cycle rows from a broad
`glibc_baseline_bench` sweep:

| row | impl | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| broad `malloc_free_64` | FrankenLibC | 6.190 | 9.266 |
| broad `malloc_free_64` | host glibc | 3.879 | 5.389 |
| broad `malloc_free_256` | FrankenLibC | 6.721 | 9.234 |
| broad `malloc_free_256` | host glibc | 4.259 | 6.367 |

The broad table is routing evidence only. This pass used a clean detached
worktree at commit `51b972cf8d1b07e99afd1dfca4b4bf1db83cd3fc`.

## Focused Gate

Requested `vmi1227854`; RCH selected `vmi1153651`, so the focused evidence for
this closeout is same-worker on `vmi1153651`.

```text
RCH_BUILD_SLOTS=1 RCH_WORKERS=vmi1227854 RCH_WORKER=vmi1227854
RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd404-malloc-focused-target-20260614T2250
CRITERION_HOME=/data/tmp/frankenlibc-bd404-malloc-focused-criterion-20260614T2250
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
'glibc_baseline_malloc_free_(64|256)' --noplot --sample-size 80
--warm-up-time 1 --measurement-time 4
```

Focused result:

| row | impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `malloc_free_64` | FrankenLibC | `[11.804 ns 12.138 ns 12.530 ns]` | 12.678 | 16.176 | 16.916 | 55.000 |
| `malloc_free_64` | host glibc | `[8.3902 ns 8.5557 ns 8.7478 ns]` | 8.533 | 11.997 | 13.479 | 40.500 |
| `malloc_free_256` | FrankenLibC | `[12.228 ns 12.600 ns 12.984 ns]` | 12.866 | 13.918 | 16.737 | 45.000 |
| `malloc_free_256` | host glibc | `[8.2349 ns 8.3826 ns 8.5273 ns]` | 8.547 | 10.014 | 11.562 | 40.000 |

The focused gap reproduced, but this exact benchmark is a one-live hot-slot
loop. The benchmark reuses one `MallocState`, immediately frees each allocation,
and after warm-up the small allocation returns from `thread_cache_hot_slots[bin]`
before magazine, elimination, central-bin, or backend paths. The corresponding
free puts the same pointer back into that hot slot.

## Candidate Screen

No source lever was applied. The only paths that affect this exact benchmark are
fixed hot-slot overhead: size-class lookup, certificate skip check, hot-slot
take/store, pending hot accounting, hit counter, Trace early-return logging, and
single-owner elimination check.

Those families are already measured no-ships or the prior kept lever:

- exact-size/cache shortcuts and exact-class pre-certificate reordering,
- Trace lifecycle gates and log/certificate micro-specialization,
- fixed magazine/plain storage swaps,
- hot-slot metadata/lease/bitmap representation variants,
- lazy-accounting retunes after the kept `.380` lazy hot-slot accounting lever.

Repeating any of those would violate the one-lever, profile-backed keep gate.
The remaining credible allocator primitive is deeper: a multi-object/cache-
pressure profile that exercises magazine, central-bin spill/refill, or an
intrusive index-linked slab/LIFO state machine. This one-live benchmark does not
exercise that path, so it cannot honestly prove or reject that primitive.

## Isomorphism

No source code changed.

- Allocation/free ordering: unchanged by construction.
- Hot-slot LIFO behavior: unchanged by construction.
- Central-bin, elimination, backend release order: unchanged by construction.
- `active_count` and `total_allocated`: unchanged by construction.
- Lifecycle log records and drain order: unchanged by construction.
- Floating point and RNG: not involved.
- Golden outputs: unchanged by construction.

Current-head reference SHAs from the clean focused worktree:

```text
4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
98340922b3b3f2daa38dc274a73b5197de91f5d439aac5092366ec988c126882  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

## Verdict

NO-CODE REJECTED. Score `0.0`.

The allocator hot-cycle residual is real on `vmi1153651`, but this is the wrong
gate for the remaining non-exhausted allocator work. Close this bead without a
source edit, then route allocator optimization to a new focused multi-object
cache-pressure benchmark that allocates and frees more than `MAGAZINE_CAPACITY +
1` objects per size class and then reallocates to drain hot slot, magazine, and
central-bin paths.
