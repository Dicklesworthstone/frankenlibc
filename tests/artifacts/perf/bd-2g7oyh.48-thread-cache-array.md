# bd-2g7oyh.48 - malloc Thread-Cache Fixed Magazine Array

## Target

- Bead: `bd-2g7oyh.48` (`[perf] malloc thread-cache fixed magazine array`)
- Target function: `crates/frankenlibc-core/src/malloc/thread_cache.rs::ThreadCache`
- Benchmark: `malloc_free_64`
- Profile basis:
  - Focused RCH baseline on `vmi1149989`: FrankenLibC p50 `173.142 ns/op`, p95 `232.157`, p99 `350.215`, mean `178.515`; host p50 `4.302`, p95 `8.188`, p99 `40.500`, mean `7.245`.
  - Source state was unchanged after bd47 because that lever was rejected and restored.

## Candidate Lever

One tested source lever:

- Replace `ThreadCache.magazines: Vec<Magazine>` with `ThreadCache.magazines: [Magazine; NUM_SIZE_CLASSES]`.
- Initialize the fixed array with `std::array::from_fn`.
- Keep each per-class `Magazine` unchanged, including the internal `Vec<usize>` stack and capacity.

## Baseline And Proof Commands

Pre-change thread-cache proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::thread_cache::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 9/9 tests passed on `vmi1153651`.

Pre-change allocator proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 15/15 tests passed on `vmi1227854`.

Post-change thread-cache proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::thread_cache::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 9/9 tests passed on `vmi1227854`.

Post-change allocator proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
```

Result: 15/15 tests passed on `vmi1156319`.

Golden lifecycle SHA256:

```text
01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

Source SHA256 after restore:

```text
crates/frankenlibc-core/src/malloc/thread_cache.rs
bafae8d9dea4651dd5c69ca66c4592ad10fa59ed181fc2662c630b6ce176fbdd
```

## Isomorphism Proof

- The magazine table still contained exactly `NUM_SIZE_CLASSES` entries and was indexed by the same already-validated `SizeClassIndex`.
- Each `Magazine` retained its original `Vec<usize>` object stack and capacity, so LIFO ordering and full/empty behavior were unchanged.
- `drain_magazine` still drained one class and subtracted the drained length from `total_cached`; invalid raw indexes still returned empty/false through the existing `size_class_index` boundary.
- Allocator pointer values, allocation/free order, central-bin order, elimination behavior, lifecycle record schema, decision ids, trace ids, and lifecycle golden output were unchanged.
- No floating-point operations or RNG state participate in this path.

## Benchmark Results

Post-change RCH benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

First post run on `vmi1227854`:

```text
FrankenLibC p50 141.945 ns/op, p95 181.226, p99 260.000, mean 151.051
host glibc  p50 4.262 ns/op, p95 6.250, p99 35.000, mean 5.773
```

Same-worker confirmation on `vmi1149989`:

```text
FrankenLibC p50 182.005 ns/op, p95 201.126, p99 400.000, mean 177.248
host glibc  p50 3.468 ns/op, p95 6.562, p99 40.000, mean 5.338
```

Confirmation vs focused baseline:

- p50: `173.142 -> 182.005 ns/op`, regression.
- mean: `178.515 -> 177.248 ns/op`, not material.

## Decision

Rejected and source restored.

Score: 0.0.
