# bd-2g7oyh.42 - malloc lifecycle drain swap

Verdict: rejected. The source candidate was restored because the post-change
RCH benchmark regressed `malloc_free_64`.

## Profile-Backed Target

Fresh post-`b50a99ee` broad RCH profile on `vmi1293453` kept `malloc_free_64`
as the dominant non-colliding residual gap:

- FrankenLibC: p50 `164.641 ns/op`, p95 `183.011`, p99 `270.324`, mean `173.146`
- Host glibc: p50 `3.719 ns/op`, p95 `5.000`, p99 `30.000`, mean `5.223`

`strlen_4096` and `strcmp_256_equal` also showed residual gaps, but those live
in BlackThrush's active `str.rs` lane. `malloc/elimination.rs` was peer-dirty
and intentionally untouched.

Focused pre-change baseline for this candidate:

```text
RCH worker: vmi1149989
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC malloc_free_64:
  p50 128.725 ns/op
  p95 226.868 ns/op
  p99 253.176 ns/op
  mean 147.439 ns/op

Host glibc malloc_free_64:
  p50 3.117 ns/op
  p95 4.771 ns/op
  p99 30.000 ns/op
  mean 4.548 ns/op
```

## Candidate Lever

One safe-Rust lifecycle-log lever in
`crates/frankenlibc-core/src/malloc/allocator.rs`: replace
`self.lifecycle_logs.drain(..).collect()` with a backing `Vec` swap that returns
the same records in the same order while leaving the allocator with an empty log
buffer of the previous capacity.

The target was profile-evident because `glibc_baseline_malloc_free_64` drains
lifecycle logs whenever the buffer grows beyond 2048 records.

## Behavior Proof

Pre-change allocator proof:

```text
RCH worker: vmi1293453
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 15/15 allocator tests
```

Post-change allocator proof:

```text
RCH worker: vmi1264463
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 15/15 allocator tests
```

Golden output was unchanged:

```text
hot_cycle_lifecycle_record_sha256 = 01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

Isomorphism:

- Returned drain record ordering was unchanged because the candidate moved the whole backing vector without reordering elements.
- Post-drain empty-buffer capacity was unchanged by the existing retained-capacity test.
- Allocation ordering was unchanged because size-class selection, thread-cache LIFO, central-bin order, and elimination behavior were not modified.
- Tie-breaking was unchanged because no comparator, bin selection, slot selection, or fallback branch changed.
- Floating-point and RNG behavior were unaffected.

## Re-Benchmark

Post-change focused RCH benchmark:

```text
RCH worker: vmi1264463
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC malloc_free_64:
  p50 402.791 ns/op
  p95 783.520 ns/op
  p99 1001.594 ns/op
  mean 468.792 ns/op

Host glibc malloc_free_64:
  p50 9.541 ns/op
  p95 25.000 ns/op
  p99 31.667 ns/op
  mean 12.336 ns/op
```

## Decision

Rejected. The candidate materially regressed both p50 and mean:

```text
FrankenLibC p50: 128.725 -> 402.791 ns/op
FrankenLibC mean: 147.439 -> 468.792 ns/op
```

Score after measurement: `0.0`. The candidate failed the `Score >= 2.0` keep
gate, and `allocator.rs` was restored with no source change retained.
