# log2 centered atanh-series rejection

Date: 2026-06-05
Agent: BlackThrush
Bead: bd-e4jb7k

## Target

Fresh `rch` Criterion baseline confirmed a profile-backed f64 `log2` residual
on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-log2-baseline-ts2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/log2' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Baseline rows:

```text
log2 frankenlibc_core p50_ns_op=650.285 p95_ns_op=678.055 p99_ns_op=721.500 mean_ns_op=665.325
log2 host_glibc       p50_ns_op=510.213 p95_ns_op=528.070 p99_ns_op=563.986 mean_ns_op=514.191
```

## Lever Tried

Replace the current `libm::log(x) * LOG2_E` route with a safe-Rust centered
exponent/mantissa reduction and an atanh odd series:

```text
x = 2^e * m, m centered to [1/sqrt(2), sqrt(2))
z = (m - 1) / (m + 1)
ln(m) = 2 * (z + z^3/3 + ... + z^31/31)
log2(x) = e + ln(m) * LOG2_E
```

This avoids the near-1 cancellation that broke the earlier plain f64-table
attempt, and it keeps powers of two bit-exact because the centered mantissa is
exactly 1.

## Behavior Proof

Commands:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs
git diff --check -- crates/frankenlibc-core/src/math/exp.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-log2-atanh-tests cargo test -p frankenlibc-core --lib log2_fast_path_within_4_ulps_of_glibc -- --nocapture --test-threads=1
```

Result:

```text
log2_fast_path_within_4_ulps_of_glibc passed
```

Isomorphism notes:

- Ordering/tie-breaking: no ordering-dependent behavior introduced.
- Floating point: normal positive inputs used the centered series; subnormal,
  non-positive, and non-finite inputs still fell back to `libm::log2`; exact
  powers of two stayed bit-exact.
- RNG: none.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-log2-atanh-post-ts2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/log2/' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Post rows:

```text
log2 frankenlibc_core p50_ns_op=1102.155 p95_ns_op=1201.021 p99_ns_op=1277.316 mean_ns_op=1123.914
log2 host_glibc       p50_ns_op=510.731  p95_ns_op=584.886  p99_ns_op=718.234  mean_ns_op=520.188
```

Decision:

```text
p50 650.285 -> 1102.155 ns, 0.59x of baseline throughput
mean 665.325 -> 1123.914 ns, 0.59x of baseline throughput
Score = 0.0; source not kept
```

## Next Primitive

Do not retry a long scalar atanh series. The next `bd-e4jb7k` primitive is a
small table with double-double log constants and double-double finalization:

```text
N=16 or N=32 centered table
fast index from mantissa high bits
z = m * inv_c - 1 with |z| tightly bounded
degree 5-7 polynomial for log1p(z)
two_sum / compensated finalization for e + logc_hi + poly + logc_lo
```

Target: stay within 4 ULP while reducing runtime below the current `650 ns`
Criterion row and toward the `510 ns` host row on `ts2`.
