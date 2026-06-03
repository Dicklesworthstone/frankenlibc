# bd-2g7oyh.38 - qsort width-4 swap specialization

Verdict: rejected. The source candidate was restored because the RCH results did
not show a sustained real win.

## Profile-Backed Target

Fresh broad RCH profile after `f73cafd7` on `vmi1149989` showed a clean
non-string qsort residual:

```text
FrankenLibC qsort_128_i32:
  p50 2410.516 ns/op
  p95 3458.206 ns/op
  p99 3540.895 ns/op
  mean 2559.625 ns/op

Host glibc qsort_128_i32:
  p50 1988.379 ns/op
  p95 2569.028 ns/op
  p99 2592.369 ns/op
  mean 2026.170 ns/op
```

Focused pre-change baseline:

```text
RCH worker: vmi1153651
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- qsort_128_i32 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC qsort_128_i32:
  p50 7751.337 ns/op
  p95 13340.911 ns/op
  p99 16677.281 ns/op
  mean 8563.939 ns/op

Host glibc qsort_128_i32:
  p50 4541.030 ns/op
  p95 5926.439 ns/op
  p99 6534.256 ns/op
  mean 4615.666 ns/op
```

## Candidate Lever

One safe-Rust production lever in `crates/frankenlibc-core/src/stdlib/sort.rs`:
specialize `swap_chunks` for `width == 4` by swapping the four bytes directly
and keeping the existing generic `split_at_mut` + `swap_with_slice` path for
all other widths.

Alien primitive: fixed-width/register micro-kernel specialization for a hot
inner loop.

## Behavior Proof

Pre-change golden SHA test:

```text
RCH worker: vmi1227854
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core qsort_reverse_ish_bench_golden_sha256_is_stable --lib -- --test-threads=1 --nocapture
Result: passed
QSORT_REVERSE_ISH_GOLDEN_SHA256=6f1d71d33c28656abb499ebd7177b9eda2ee8d3d369d1fb3f4e131944932851a
```

Post-change golden SHA test:

```text
RCH worker: vmi1149989
Result: passed
QSORT_REVERSE_ISH_GOLDEN_SHA256=6f1d71d33c28656abb499ebd7177b9eda2ee8d3d369d1fb3f4e131944932851a
```

Isomorphism:

- Compare ordering would be preserved because partitioning, recursion, pivot selection, and comparator calls were untouched.
- Equality tie behavior would be preserved because the same element swap sites would occur; only byte movement inside each width-4 swap changed.
- Non-4-byte element sorting would be unchanged by direct delegation to the original generic path.
- Floating-point and RNG behavior were unaffected.

## Re-Benchmark

First post-change RCH benchmark:

```text
RCH worker: vmi1227854
FrankenLibC qsort_128_i32:
  p50 2735.616 ns/op
  p95 3105.548 ns/op
  p99 3150.235 ns/op
  mean 2743.964 ns/op

Host glibc qsort_128_i32:
  p50 2272.653 ns/op
  p95 3026.391 ns/op
  p99 3140.969 ns/op
  mean 2396.023 ns/op
```

Confirmation post-change RCH benchmark:

```text
RCH worker: vmi1227854
FrankenLibC qsort_128_i32:
  p50 2958.296 ns/op
  p95 3367.273 ns/op
  p99 3671.713 ns/op
  mean 2957.595 ns/op

Host glibc qsort_128_i32:
  p50 2615.785 ns/op
  p95 2979.884 ns/op
  p99 3111.844 ns/op
  mean 2577.611 ns/op
```

## Decision

Rejected. The post-change worker differed from the focused baseline worker, and
same-worker post confirmation did not show a stable win. The confirmation p50
and mean were worse than the first post run, and neither post result cleared the
`Score >= 2.0` keep gate.

Score after measurement: `0.0`. The candidate failed the keep gate, and
`sort.rs` was restored with no source change retained.
