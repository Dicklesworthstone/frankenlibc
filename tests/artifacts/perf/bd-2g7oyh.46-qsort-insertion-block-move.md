# bd-2g7oyh.46 - qsort Small-Partition Insertion Block Move

## Target

- Bead: `bd-2g7oyh.46` (`[perf] qsort small-partition insertion block move`)
- Target function: `crates/frankenlibc-core/src/stdlib/sort.rs::insertion_sort`
- Benchmark: `qsort_128_i32`
- Profile basis:
  - Broad RCH profile after `87695585` on `vmi1167313`: FrankenLibC p50 `7182.823 ns/op`, p95 `7910.732`, p99 `8754.439`, mean `7070.474`; host p50 `4556.657`, p95 `5316.742`, p99 `5709.379`, mean `4499.363`.
  - Focused RCH baseline on `vmi1264463`: FrankenLibC p50 `7341.765 ns/op`, p95 `15465.841`, p99 `18053.184`, mean `8257.883`; host p50 `4724.885`, p95 `8558.040`, p99 `10761.861`, mean `5297.461`.

## Lever

One retained source lever:

- For element widths up to 64 bytes, small-partition insertion sort saves the moving item into a fixed stack scratch buffer, shifts the intervening byte block once with `copy_within`, and restores the item at the insertion point.
- For element widths above 64 bytes, the previous adjacent `swap_chunks` insertion-sort algorithm remains the fallback.
- No changes to pivot selection, partitioning, recursion, comparator implementation, benchmark harness, random state, or floating-point behavior.

## Baseline And Proof Commands

Pre-change behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core stdlib::sort::sort_variant_tests:: --lib -- --test-threads=1 --nocapture
```

Result: 25/25 tests passed on `vmi1153651`.

Post-change behavior proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core stdlib::sort::sort_variant_tests:: --lib -- --test-threads=1 --nocapture
```

Result: 26/26 tests passed on `vmi1153651`, including `qsort_small_partition_block_move_preserves_equal_order`.

Golden SHA256:

```text
tests/conformance/fixtures/stdlib_sort.json
ff7eb36ea363367e78b7287e53ecbd28ef43f0fed8337c864d446ae166be71b6
```

Source SHA256:

```text
pre:  f54102e160c31e4c53f9cf18baeb08284f2a0dc26eebe6cb7d42e399c85537af
post: e37b948c321a70d7258f96039b5f5f604e993fd1f71e7423d68098796bc87b2a
```

## Isomorphism Proof

- The insertion point is still found by scanning left until `compare(prev, item) <= 0`, so equal prior elements remain before the moving item just as in the old adjacent-swap insertion sort.
- The retained lever copies the moving item bytes to stack scratch, shifts exactly `dest_start..item_start` right by one element width, and copies the saved bytes into `dest_start`. This is the same final byte sequence produced by repeated adjacent element swaps.
- Widths above 64 bytes execute the previous adjacent-swap implementation exactly.
- Sorted multiset output is unchanged. Qsort global equal-element ordering is unspecified, and the local insertion fallback's equal-key tie behavior is preserved.
- No floating-point operations or RNG state participate in qsort, and neither was changed.

## Benchmark Results

Post-change RCH benchmark:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench qsort_128_i32 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

First post run on `vmi1153651`:

```text
FrankenLibC p50 4179.607 ns/op, p95 4839.000, p99 4897.097, mean 4237.437
host glibc  p50 4032.619 ns/op, p95 5336.482, p99 5794.817, mean 4206.889
```

Confirmation post run on `vmi1153651`:

```text
FrankenLibC p50 4434.335 ns/op, p95 5233.542, p99 5861.000, mean 4476.938
host glibc  p50 4085.234 ns/op, p95 4743.583, p99 4863.201, mean 4185.171
```

Improvement vs focused baseline:

- p50: `7341.765 -> 4434.335 ns/op` confirmed, `1.66x` faster.
- mean: `8257.883 -> 4476.938 ns/op` confirmed, `1.84x` faster.

## Validation

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings
rustfmt --edition 2024 --check crates/frankenlibc-core/src/stdlib/sort.rs
```

Results:

- RCH `cargo check -p frankenlibc-core --all-targets` passed on `vmi1153651` with the existing SMT-solver warning.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings` passed on `vmi1153651` with the existing SMT-solver warning.
- Local rustfmt check passed.

## Decision

Retained.

Score: Impact 4 x Confidence 5 / Effort 2 = 10.0.
