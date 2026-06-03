# bd-2g7oyh.44 - memcpy exact full-slice fast path

Verdict: rejected. The source candidate was restored because the post-change
RCH benchmark regressed `memcpy_4096`.

## Profile-Backed Target

Fresh post-`bf9330ff` broad RCH profile on `vmi1293453` showed a non-colliding
`memcpy_4096` residual gap:

- FrankenLibC: p50 `41.868 ns/op`, p95 `46.645`, p99 `65.000`, mean `43.545`
- Host glibc: p50 `27.074 ns/op`, p95 `32.500`, p99 `90.000`, mean `29.827`

`malloc_free_64` remained the dominant global gap, but allocator sub-levers had
failed and `malloc/elimination.rs` was peer-dirty. `strlen_4096` and
`strcmp_256_equal` live in BlackThrush's active `str.rs` lane.

Focused pre-change baseline:

```text
RCH worker: vmi1293453
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench memcpy_4096 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC memcpy_4096:
  p50 41.456 ns/op
  p95 45.160 ns/op
  p99 80.000 ns/op
  mean 43.312 ns/op

Host glibc memcpy_4096:
  p50 31.300 ns/op
  p95 33.707 ns/op
  p99 40.000 ns/op
  mean 31.379 ns/op
```

## Candidate Lever

One safe-Rust `memcpy` lever in
`crates/frankenlibc-core/src/string/mem.rs`: add an exact full-slice fast path
for `n == dest.len() == src.len()` before the existing clamped prefix-copy path.

## Behavior Proof

Pre-change string memory proof:

```text
RCH worker: vmi1156319
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=256 cargo test -p frankenlibc-core string::mem::tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 41/41 string::mem tests
```

Post-change string memory proof:

```text
RCH worker: vmi1149989
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=256 cargo test -p frankenlibc-core string::mem::tests:: --lib -- --test-threads=1 --nocapture
Result: passed, 41/41 string::mem tests
```

Golden fixture hashes stayed unchanged:

```text
tests/conformance/fixtures/string_memory_full.json = 94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4
tests/conformance/fixtures/memcpy_strict.json = 6bdd6fb00bff508d07eb985bdc7c258a1a10f8ea96de72cf7e392483e886c233
```

Isomorphism:

- Exact full-slice cases would return the same `n` and copy the same complete
  slice because the original `count` also equals `n`.
- Partial cases would fall through to the original `min(n, dest.len(), src.len())`
  prefix-copy path, preserving copied prefix and untouched tail behavior.
- Ordering and tie-breaking were unchanged because `memcpy` performs no
  comparisons and preserves the same non-overlap copy contract.
- Floating-point and RNG behavior were unaffected.

After restoring the source, the `mem.rs` hash returned to the pre-change value:

```text
crates/frankenlibc-core/src/string/mem.rs = 8e7674c7176db872361de4f1038003eacd87fc9c510047f6f7aa42d4d218fd08
```

## Re-Benchmark

Post-change focused RCH benchmark:

```text
RCH worker: vmi1227854
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench memcpy_4096 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC memcpy_4096:
  p50 42.652 ns/op
  p95 46.620 ns/op
  p99 75.000 ns/op
  mean 45.301 ns/op

Host glibc memcpy_4096:
  p50 28.231 ns/op
  p95 31.184 ns/op
  p99 50.000 ns/op
  mean 29.598 ns/op
```

## Decision

Rejected. The candidate regressed both FrankenLibC p50 and mean:

```text
FrankenLibC p50: 41.456 -> 42.652 ns/op
FrankenLibC mean: 43.312 -> 45.301 ns/op
```

Score after measurement: `0.0`. The candidate failed the `Score >= 2.0` keep
gate, and `mem.rs` was restored with no source change retained.
