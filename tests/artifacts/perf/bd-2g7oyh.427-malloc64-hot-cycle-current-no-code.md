# bd-2g7oyh.427 malloc_free_64 hot-cycle current-head screen

Date: 2026-06-16
Agent: BoldFalcon
Status: no-code routed out

## Target

The current-head broad profile on `vmi1227854` reproduced a material
`malloc_free_64` residual:

| row | impl | Criterion interval | p50 ns | mean ns |
| --- | --- | --- | ---: | ---: |
| `malloc_free_64` | FrankenLibC | `[6.9307 ns 7.3447 ns 7.8457 ns]` | 7.413 | 10.338 |
| `malloc_free_64` | host glibc | `[4.1545 ns 4.4710 ns 4.8702 ns]` | 4.727 | 7.210 |

The focused bead is `bd-2g7oyh.427`, created as a child of the parent no-gaps
perf directive.

## Focused baseline attempt

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854
RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass145-malloc64-baseline-target-20260616T0422
CRITERION_HOME=/data/tmp/frankenlibc-pass145-malloc64-baseline-criterion-20260616T0422
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_malloc_free_64 --noplot --sample-size 100 --warm-up-time 1
--measurement-time 3
```

RCH refused local fallback under `RCH_REQUIRE_REMOTE=1`:

```text
[RCH] local (no admissible workers: critical_pressure=1,insufficient_slots=1,hard_preflight=8)
[RCH] remote required; refusing local fallback (no worker assigned)
```

No local timing was used as evidence.

## Candidate screen

No source lever was applied. Prior focused artifacts already cover the source
paths that affect the one-live hot-slot benchmark:

- exact-size/cache hot-slot shortcuts;
- Trace lifecycle gates and record-emission hoists;
- exact-class pre-certificate hot-slot reordering;
- fixed magazine and plain storage-layout swaps;
- affine lease and hot-slot metadata changes;
- bitmap/packed hot-slot representation;
- lazy-accounting retunes after the kept `bd-2g7oyh.380` lever;
- production elimination-handle / `Arc::strong_count` compile-out.

The remaining allocator primitive named by prior route notes is a true
safe-Rust segregated slab or intrusive index-linked hot-list. That primitive is
still allocator-relevant for multi-object refill/drain or mixed-size cache
pressure, but it is not profile-honest for this one-live benchmark: after
warmup, the benchmark frees into `thread_cache_hot_slots[bin]`, and the next
malloc takes that exact slot before the deeper slab/magazine/refill path can
run.

## Isomorphism

No source changed. Allocation/free ordering, hot-slot LIFO behavior, magazine
displacement, central-bin spill order, backend callback behavior, shared
elimination tie-breaking, public `active_count` / `total_allocated`, lifecycle
log rows, golden lifecycle SHA outputs, floating-point state, and RNG state are
unchanged by construction.

## Verdict

NO-CODE ROUTED OUT. Score `0.0`.

The next allocator return should use a benchmark that exercises the deeper
slab/intrusive-list path, such as multi-object refill/drain or mixed-size cache
pressure. Current loop moves to `strncasecmp_256_equal`, which remains a
profile-backed current-head residual.

