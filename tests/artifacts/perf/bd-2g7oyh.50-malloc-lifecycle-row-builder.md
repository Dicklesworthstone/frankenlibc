# bd-2g7oyh.50 - malloc Inline Lifecycle Trace Id

## Target

- Bead: `bd-2g7oyh.50` (`[perf] malloc slab hot-cycle lifecycle row builder`)
- Profile-backed hotspot: `glibc_baseline_malloc_free_64`
- Source target tested: `crates/frankenlibc-core/src/malloc/allocator.rs`
- Alien-graveyard primitive: allocator/slab hot-cold split and region-style hot
  record construction. This pass tested one representation lever: make each
  allocator lifecycle record carry an inline fixed-capacity trace id instead of
  allocating a `String` per row.

## Baseline

Focused clean-source RCH baseline:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_perf_malloc_clean_baseline_20260603_1537 FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker `vmi1149989`:

```text
FrankenLibC p50 174.049 ns/op, p95 391.683, p99 576.809, mean 192.893
host glibc  p50   3.032 ns/op, p95   6.250, p99  35.000, mean   5.067
```

## Candidate Lever

One source lever was tested and then rejected:

- Add public `AllocatorTraceId` as an inline `[u8; 64]` + length value.
- Change `AllocatorLogRecord.trace_id` from `String` to `AllocatorTraceId`.
- Preserve the legacy trace-id text through `Display`, `Debug`, `Deref<Target =
  str>`, and `as_str()`.

No allocation/free routing, size-class selection, thread-cache LIFO behavior,
central-bin ordering, elimination ordering, pointer generation, counter update,
floating-point operation, or RNG state was changed.

## Behavior Proof

Pre-change RCH golden:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_50_preproof RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1
```

Result: passed on `vmi1156319`.

Post-change RCH allocator proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_50_postproof RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 15/15 allocator tests passed on `vmi1227854`, including the lifecycle
golden.

Lifecycle golden SHA256 stayed:

```text
01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

## Isomorphism Proof

- Trace-id text stayed byte-identical: `core::malloc::{symbol}::{decision_id:016x}`.
- Decision-id sequencing stayed monotonic and unchanged because
  `next_log_decision_id` was untouched.
- Lifecycle row order stayed unchanged because all `record_lifecycle` call sites
  and control-flow branches were untouched.
- Pointer values, allocation/free ordering, thread-cache LIFO behavior,
  central-bin order, elimination order, active counters, byte counters, hit/miss
  counters, and cache-hit-rate snapshots were unchanged.
- Error/tie classes were unchanged because the candidate only changed trace-id
  storage, not allocator decisions.
- Floating-point and RNG behavior were not present in this path.

## Benchmark Result

Post-change RCH benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_50_postbench FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker `vmi1264463`:

```text
FrankenLibC p50 178.920 ns/op, p95 661.000, p99 856.090, mean 263.992
host glibc  p50   9.092 ns/op, p95  21.032, p99  45.500, mean  11.805
```

Result versus baseline:

- p50: `174.049 -> 178.920 ns/op` (`0.97x`, regression).
- mean: `192.893 -> 263.992 ns/op` (`0.73x`, regression).

Score: `0.0`. The change failed the Score>=2.0 keep gate.

## Decision

Rejected and source restored.

Restored source SHA256:

```text
crates/frankenlibc-core/src/malloc/allocator.rs
6bb73dd97daef30f2c596931f0dec11e1014837733fee23a44586df56445716d
```

Next attack: do not continue per-field lifecycle row tweaks. The next allocator
primitive should be a true hot/cold event split: append compact lifecycle events
in a contiguous hot buffer and materialize full `AllocatorLogRecord` rows only at
drain/observation boundaries, preserving golden output through batched
materialization.
