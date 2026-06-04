# bd-2g7oyh.49 - malloc exact-64 size-class fast path

## Target

- Bead: `bd-2g7oyh.49` (`[perf] malloc exact-64 size-class fast path`)
- Target function: `crates/frankenlibc-core/src/malloc/size_class.rs::small_bin_index`
- Benchmark: `malloc_free_64`
- Profile basis:
  - Focused RCH baseline from the bead on `vmi1149989`: FrankenLibC p50 `173.142 ns/op`, p95 `232.157`, p99 `350.215`, mean `178.515`; host p50 `4.302`, mean `7.245`.
  - Fresh pre-change RCH baseline on `vmi1264463`: FrankenLibC p50 `414.354 ns/op`, p95 `1690.237`, p99 `2214.309`, mean `611.798`; host p50 `8.978`, mean `20.990`.
  - The workload calls `small_bin_index(64)` on both allocation and free.

## Lever

One retained source lever:

- Add an exact hot path in `small_bin_index` for normalized `size == 64`.
- Return the already-proven bounded size-class index `3`.
- Keep all other sizes on the existing ordered `SIZE_TABLE` scan.

## Baseline And Proof Commands

Focused fresh pre-change benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Pre-change size-class proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_tests_pre cargo test -p frankenlibc-core malloc::size_class::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 13/13 tests passed remotely on `vmi1264463`.

Pre-change lifecycle golden proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_lifecycle_pre cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --test-threads=1 --nocapture
```

Result: 1/1 passed remotely on `vmi1149989`.

Post-change size-class proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_tests_post cargo test -p frankenlibc-core malloc::size_class::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 13/13 tests passed remotely on `vmi1149989`.

Post-change lifecycle golden proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_lifecycle_post cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --test-threads=1 --nocapture
```

Result: 1/1 passed remotely on `vmi1153651`.

Golden lifecycle SHA256:

```text
01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

## Isomorphism Proof

- Ordering preserved: yes. The size-class table order is unchanged, and `64` previously resolved to the same first table entry at index `3`.
- Tie-breaking unchanged: yes. Boundary sizes below, above, and equal to adjacent classes still resolve by the same first-fit table rule; only the exact `64` case bypasses the scan and returns the same bounded index.
- Allocation/free ordering unchanged: yes. Thread-cache LIFO order, central-bin order, elimination behavior, pointer values, decision ids, trace ids, and lifecycle event order are unchanged.
- Boundary behavior unchanged: yes. Sizes below `MIN_SIZE` still normalize to `16`, sizes above `MAX_SMALL_SIZE` still return `None`, and all non-64 sizes still use the existing scan.
- Floating-point: N/A.
- RNG seeds/state: N/A.
- Golden outputs: unchanged via the pinned lifecycle SHA test above.

## Benchmark Results

Post-change RCH benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Post run on `vmi1153651`:

```text
FrankenLibC p50 379.031 ns/op, p95 510.119, p99 626.108, mean 393.381
host glibc  p50 9.359 ns/op, p95 19.586, p99 50.500, mean 12.354
```

Same-worker confirmation on `vmi1149989`:

```text
FrankenLibC p50 109.713 ns/op, p95 241.422, p99 363.164, mean 115.095
host glibc  p50 5.275 ns/op, p95 12.942, p99 32.296, mean 7.442
```

Confirmation vs bead baseline on `vmi1149989`:

- p50: `173.142 -> 109.713 ns/op`, `1.58x`.
- mean: `178.515 -> 115.095 ns/op`, `1.55x`.

Score: Impact `2` x Confidence `4` / Effort `1` = `8.0`.

## Decision

Retained.
