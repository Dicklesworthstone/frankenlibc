# bd-2g7oyh.37 - malloc trace prefix fast path

Verdict: rejected. The source candidate was restored because the confirmation
benchmark failed the real-win gate.

## Profile-Backed Target

Fresh post-`b67706fc` broad RCH profile on `vmi1227854` kept `malloc_free_64`
as the largest clean residual broad-bench gap:

- FrankenLibC: p50 `177.986 ns/op`, p95 `221.535`, p99 `306.625`, mean `185.595`
- Host glibc: p50 `3.571 ns/op`, p95 `4.897`, p99 `25.000`, mean `5.139`

Focused same-worker pre-change baseline for this candidate:

```text
RCH worker: vmi1153651
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC malloc_free_64:
  p50 368.140 ns/op
  p95 416.938 ns/op
  p99 528.365 ns/op
  mean 373.502 ns/op

Host glibc malloc_free_64:
  p50 9.019 ns/op
  p95 16.250 ns/op
  p99 90.000 ns/op
  mean 14.559 ns/op
```

## Candidate Lever

One safe-Rust formatting lever in `crates/frankenlibc-core/src/malloc/allocator.rs`:
use static trace-id prefixes for the three hot allocator lifecycle symbols
`malloc`, `free`, and `size_class_certificate`, while preserving the generic
fallback for every other symbol and preserving the 16-digit lowercase hex suffix.

## Behavior Proof

Pre/post allocator tests were run remotely:

```text
RCH worker: vmi1149989
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 15/15 tests
```

Golden output was unchanged:

```text
hot_cycle_lifecycle_record_sha256 = 01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

Isomorphism:

- Record ordering was unchanged because lifecycle records were still emitted at the same allocation/free/certificate points.
- Trace decision IDs were unchanged; the candidate changed only the construction of equal prefix bytes.
- Tie-breaking was unchanged because size-class selection, thread-cache LIFO, central-bin order, elimination behavior, and pointer reuse were not touched.
- Floating-point and RNG behavior were unaffected.
- All non-hot symbols delegated to the original generic construction.

## Re-Benchmark

First post-change RCH benchmark:

```text
RCH worker: vmi1153651
FrankenLibC malloc_free_64:
  p50 364.070 ns/op
  p95 537.303 ns/op
  p99 681.000 ns/op
  mean 369.638 ns/op

Host glibc malloc_free_64:
  p50 8.965 ns/op
  p95 13.549 ns/op
  p99 40.000 ns/op
  mean 11.967 ns/op
```

Confirmation post-change RCH benchmark:

```text
RCH worker: vmi1153651
FrankenLibC malloc_free_64:
  p50 398.683 ns/op
  p95 2635.527 ns/op
  p99 7603.309 ns/op
  mean 725.463 ns/op

Host glibc malloc_free_64:
  p50 8.805 ns/op
  p95 18.123 ns/op
  p99 40.000 ns/op
  mean 11.082 ns/op
```

## Decision

Rejected. The first post-change run had only a small p50/mean improvement and
worse tails. Same-worker confirmation regressed p50 and mean versus baseline and
made tail latency materially worse:

```text
FrankenLibC p50: 368.140 -> 398.683 ns/op
FrankenLibC mean: 373.502 -> 725.463 ns/op
FrankenLibC p99: 528.365 -> 7603.309 ns/op
```

Score after measurement: `0.0`. The candidate failed the `Score >= 2.0` keep
gate, and `allocator.rs` was restored with no source change retained.
