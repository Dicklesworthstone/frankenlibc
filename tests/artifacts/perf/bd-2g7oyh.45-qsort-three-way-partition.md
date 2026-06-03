# bd-2g7oyh.45 - qsort duplicate-heavy three-way partition

Verdict: rejected. The source candidate was restored because the post-change
RCH benchmark did not produce a real win and regressed p50.

## Profile-Backed Target

Fresh broad RCH profile after `87695585` on `vmi1167313` showed a clean
non-string qsort residual:

```text
FrankenLibC qsort_128_i32:
  p50 7182.823 ns/op
  p95 7910.732 ns/op
  p99 8754.439 ns/op
  mean 7070.474 ns/op

Host glibc qsort_128_i32:
  p50 4556.657 ns/op
  p95 5316.742 ns/op
  p99 5709.379 ns/op
  mean 4499.363 ns/op
```

`malloc_free_64` remained the larger global gap, but allocator surfaces were
peer-dirty/contended and several allocator sub-levers had just failed.
BlackThrush owns the active `str.rs` strlen lane. `memcpy`, `memset`, and
`strcmp` were noise-level on the same broad worker.

Focused pre-change baseline:

```text
RCH worker: vmi1264463
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench qsort_128_i32 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC qsort_128_i32:
  p50 7341.765 ns/op
  p95 15465.841 ns/op
  p99 18053.184 ns/op
  mean 8257.883 ns/op

Host glibc qsort_128_i32:
  p50 4724.885 ns/op
  p95 8558.040 ns/op
  p99 10761.861 ns/op
  mean 5297.461 ns/op
```

## Candidate Lever

One safe-Rust production lever in `crates/frankenlibc-core/src/stdlib/sort.rs`:
replace the two-way Lomuto qsort partition recursion with a duplicate-aware
three-way partition that groups `< pivot`, `== pivot`, and `> pivot` elements
in one pass, then recurses only on the less/greater bands.

The target was profile-evident because the benchmark input is duplicate-heavy:
`(0..128).rev().map(|value| value * 17 % 97)`.

## Behavior Proof

Pre-change sort proof:

```text
RCH worker: vmi1153651
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core stdlib::sort::sort_variant_tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 25/25 sort variant tests
```

Post-change sort proof:

```text
RCH worker: vmi1153651
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core stdlib::sort::sort_variant_tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 26/26 sort variant tests including all-equal qsort regression
```

Golden fixture hash stayed unchanged:

```text
tests/conformance/fixtures/stdlib_sort.json = ff7eb36ea363367e78b7287e53ecbd28ef43f0fed8337c864d446ae166be71b6
```

Isomorphism:

- Sorted multiset output would be preserved because every element is still
  compared by the caller comparator and partitioned into less/equal/greater
  bands before recursive sorting.
- Duplicate tie behavior is not a qsort stability guarantee; equal-element
  ordering remains unspecified.
- Error classes and zero-width/short-buffer early exits were unchanged because
  only the recursive partition path was edited.
- Floating-point and RNG behavior were unaffected.

After restoring the source, the `sort.rs` hash returned to the pre-change value:

```text
crates/frankenlibc-core/src/stdlib/sort.rs = f54102e160c31e4c53f9cf18baeb08284f2a0dc26eebe6cb7d42e399c85537af
```

## Re-Benchmark

Post-change focused RCH benchmark:

```text
RCH worker: vmi1153651
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench qsort_128_i32 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC qsort_128_i32:
  p50 8410.067 ns/op
  p95 9507.546 ns/op
  p99 10046.258 ns/op
  mean 8186.175 ns/op

Host glibc qsort_128_i32:
  p50 4572.499 ns/op
  p95 5806.553 ns/op
  p99 6002.000 ns/op
  mean 4659.686 ns/op
```

## Decision

Rejected. The candidate regressed FrankenLibC p50 and did not produce a
material mean win:

```text
FrankenLibC p50: 7341.765 -> 8410.067 ns/op
FrankenLibC mean: 8257.883 -> 8186.175 ns/op
```

Score after measurement: `0.0`. The candidate failed the `Score >= 2.0` keep
gate, and `sort.rs` was restored with no source change retained.
