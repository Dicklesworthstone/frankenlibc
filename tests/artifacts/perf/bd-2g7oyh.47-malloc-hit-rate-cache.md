# bd-2g7oyh.47 - malloc Hot Log Hit-Rate Snapshot Cache

## Target

- Bead: `bd-2g7oyh.47` (`[perf] malloc hot log hit-rate snapshot cache`)
- Target function: `crates/frankenlibc-core/src/malloc/allocator.rs::record_lifecycle`
- Benchmark: `malloc_free_64`
- Profile basis:
  - Broad RCH profile after `da1bedd6` on `vmi1149989`: FrankenLibC p50 `160.666 ns/op`, p95 `198.966`, p99 `282.336`, mean `168.685`; host p50 `3.884`, p95 `10.625`, p99 `40.000`, mean `6.132`.
  - Focused RCH baseline on `vmi1149989`: FrankenLibC p50 `173.142 ns/op`, p95 `232.157`, p99 `350.215`, mean `178.515`; host p50 `4.302`, p95 `8.188`, p99 `40.500`, mean `7.245`.

## Candidate Lever

One tested source lever:

- Add a cached `cache_hit_rate_permille` snapshot field to `MallocState`.
- Refresh that snapshot only after `thread_cache_hits` or `thread_cache_misses` changed.
- Make `record_lifecycle` copy the cached snapshot instead of recomputing the hit-rate division for every lifecycle row.

The candidate did not touch `malloc/elimination.rs`, allocation order, free order, thread-cache LIFO behavior, central-bin behavior, pointer generation, record schema, decision ids, trace ids, floating-point code, or RNG state.

## Baseline And Proof Commands

Focused pre-change benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Pre-change behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 15/15 allocator tests passed on `vmi1153651`.

Post-change behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 15/15 allocator tests passed on `vmi1227854`.

Golden lifecycle SHA256:

```text
01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

Source SHA256 after restore:

```text
crates/frankenlibc-core/src/malloc/allocator.rs
6bb73dd97daef30f2c596931f0dec11e1014837733fee23a44586df56445716d
```

## Isomorphism Proof

- The cached hit-rate snapshot was refreshed immediately after each hit/miss counter increment, so any following lifecycle record would observe the same value as the original `thread_cache_hits / (hits + misses)` computation.
- Lifecycle records before the first hit/miss mutation still observed the initialized `0` snapshot, matching the original zero-total computation.
- Records on free and other paths that do not mutate hit/miss counters would observe the latest snapshot, matching the original recomputation over unchanged counters.
- Allocation/free ordering, cache LIFO behavior, central-bin ordering, elimination behavior, pointer values, active allocation counters, total byte counters, record schema, decision ids, and trace ids were unchanged.
- No floating-point operations or RNG state participate in this allocator path.

## Benchmark Results

Post-change RCH benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Post run on `vmi1153651`:

```text
FrankenLibC p50 334.072 ns/op, p95 399.520, p99 521.000, mean 345.745
host glibc  p50 8.219 ns/op, p95 15.125, p99 47.500, mean 11.050
```

Regression vs focused baseline:

- p50: `173.142 -> 334.072 ns/op`, `0.52x`.
- mean: `178.515 -> 345.745 ns/op`, `0.52x`.

## Decision

Rejected and source restored.

Score: 0.0.
