# log2 DD-table rejection

Date: 2026-06-05
Agent: BlackThrush
Bead: bd-e4jb7k

## Target

Same fresh `ts2` baseline as the atanh-series rejection:

```text
log2 frankenlibc_core p50_ns_op=650.285 p95_ns_op=678.055 p99_ns_op=721.500 mean_ns_op=665.325
log2 host_glibc       p50_ns_op=510.213 p95_ns_op=528.070 p99_ns_op=563.986 mean_ns_op=514.191
```

## Lever Tried

N=32 centered table over `[1/sqrt(2), sqrt(2))`:

```text
normal positive x in [0.5, 2.5)
fallback for |x - 1| <= 0.3
m centered to [1/sqrt(2), sqrt(2))
index from mantissa
r = m * inv_c - 1
degree-8 log1p polynomial in base-2 coefficients
two_sum(exponent, log2_c_hi) + log2_c_lo + poly
```

This directly attacked the prior cancellation failure by storing `log2(c)` as
hi/lo and using compensated exponent finalization. Normal positives outside the
profiled interval retained the existing `libm::log(x) * LOG2_E` route; exact
powers of two still fell through to `libm::log2`.

## Behavior Proof

Commands:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs
git diff --check -- crates/frankenlibc-core/src/math/exp.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-log2-table-tests cargo test -p frankenlibc-core --lib log2_fast_path_within_4_ulps_of_glibc -- --nocapture --test-threads=1
```

Result:

```text
log2_fast_path_within_4_ulps_of_glibc passed
```

Isomorphism notes:

- Ordering/tie-breaking: none introduced.
- Floating point: table path stayed within the existing 4-ULP glibc contract;
  near-one, out-of-range, subnormal, non-positive, non-finite, and exact powers
  preserved existing fallback behavior.
- RNG: none.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-log2-table-post-ts2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/log2/' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Post rows:

```text
log2 frankenlibc_core p50_ns_op=837.053 p95_ns_op=932.000 p99_ns_op=1071.441 mean_ns_op=850.324
log2 host_glibc       p50_ns_op=513.458 p95_ns_op=540.672 p99_ns_op=741.000  mean_ns_op=523.696
```

Decision:

```text
p50 650.285 -> 837.053 ns, 0.78x of baseline throughput
mean 665.325 -> 850.324 ns, 0.78x of baseline throughput
Score = 0.0; source not kept
```

## Next Primitive

Do not retry this exact N=32/fallback-heavy table shape. The next log2 attack
must reduce control-flow and table overhead while keeping compensated accuracy:

```text
candidate A: generated minimax polynomial for the profiled [0.5,2.5) subranges
candidate B: smaller branchless table with c=1 exact center and no wide fallback
candidate C: split kernels for [0.5,0.7), [1.3,2.0), [2.0,2.5) with tuned coefficients
```

Target remains same-worker `ts2` p50 below 650 ns, ideally below host 510 ns.
