# bd-2g7oyh.397 malloc slab/hot-list focused gate

Date: 2026-06-14
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

This pass followed the `bd-2g7oyh.396` memcmp no-code closeout. The allocator
lane was only admissible if a fresh focused RCH run reproduced a material
`malloc_free_64` or `malloc_free_256` gap on current source.

Current source fingerprints before and after this pass:

```text
4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

## Focused Baseline

The first pinned-worker attempt returned `RCH-E324 dependency preflight` and
refused local fallback under `RCH_REQUIRE_REMOTE=1`; that run is tooling
context only, not performance evidence.

The successful focused run:

```text
RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd397-malloc-focus-target-20260614-retry
CRITERION_HOME=/data/tmp/frankenlibc-bd397-malloc-focus-criterion-20260614-retry
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
'glibc_baseline_(malloc_free_64|malloc_free_256|malloc_free_large)'
--noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`.

| row | impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| `malloc_free_64` | FrankenLibC | `[4.2845 ns 4.4624 ns 4.6500 ns]` | 4.279 | 5.977 | 8.188 | 30.000 |
| `malloc_free_64` | host glibc | `[3.8395 ns 4.0434 ns 4.2455 ns]` | 3.422 | 5.253 | 5.198 | 35.000 |
| `malloc_free_256` | FrankenLibC | `[4.5173 ns 4.7730 ns 5.0505 ns]` | 5.041 | 6.476 | 10.000 | 30.000 |
| `malloc_free_256` | host glibc | `[3.8318 ns 3.9508 ns 4.0685 ns]` | 3.689 | 4.614 | 4.561 | 30.000 |
| `malloc_free_large` | FrankenLibC | `[5.8769 ns 5.9280 ns 5.9765 ns]` | 5.979 | 7.402 | 10.204 | 35.500 |
| `malloc_free_large` | host glibc | `[27.209 ns 27.608 ns 28.029 ns]` | 27.240 | 33.844 | 31.434 | 75.000 |

The strongest reproduced small-object lane was `malloc_free_256`, with
FrankenLibC `1.37x` slower by p50 and `1.40x` slower by mean. The large guard
remains much faster than host.

## Candidate Screen

No source lever was attempted.

The current one-live small-object benchmark reaches this steady-state path after
warm-up:

1. `free` parks the object in `thread_cache_hot_slots[bin]`.
2. the next `malloc` takes that exact hot slot before the general magazine,
   central bin, backend refill, or any deeper slab/list storage can run.
3. `pending_hot_accounting` is cleared by the exact matching `free`, preserving
   public `active_count()` and `total_allocated()` while avoiding eager counter
   mutation in the exact cycle.

Prior measured no-ship families already cover the source paths that affect this
exact cycle:

- exact-size/cache hot-slot shortcuts;
- Trace lifecycle gates and record-emission hoists;
- exact-class pre-certificate hot-slot reordering;
- fixed magazine/plain storage-layout swaps;
- affine lease and hot-slot metadata changes;
- bitmap/packed hot-slot representation;
- lazy-accounting retunes after the kept `bd-2g7oyh.380` lever;
- production elimination-handle / `Arc::strong_count` compile-out.

The only remaining allocator primitive named by prior route notes is a true
safe-Rust segregated slab or intrusive index-linked hot-list. That primitive is
still the correct next allocator attack for multi-object/magazine/refill
traffic, but it would not be exercised by this focused one-live benchmark after
the first cached object enters the per-class hot slot. Testing it against this
gate would not be profile-honest.

## Isomorphism

No source code changed.

- Allocation/free ordering, hot-slot LIFO behavior, magazine displacement,
  central-bin spill order, backend release, and shared-elimination tie-breaking
  are unchanged by construction.
- `active_count`, `total_allocated`, lifecycle logs, certificate rows, and
  lifecycle golden SHA outputs are unchanged by construction.
- Floating point and RNG behavior are not involved.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused allocator gap reproduced on `vmi1227854`, especially for 256B, but
the only source edits that affect this exact one-live hot-slot cycle are already
documented rejected families. The next allocator return must use a benchmark
that exercises the deeper slab/intrusive-list path, such as multi-object
refill/drain or mixed-size cache pressure, so the source lever and profile target
match. Otherwise reprofile and move to the next reproduced non-allocator
residual.
