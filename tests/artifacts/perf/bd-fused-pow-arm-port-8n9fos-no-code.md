# bd-fused-pow-arm-port-8n9fos fused pow no-code closeout

Status: REJECTED no-code, current-head profile gate collapsed.

## Target

The bead proposed a full safe-Rust fused `pow(x, 1.337)` implementation based
on the ARM optimized-routines `pow.c` structure. It claimed the remaining
current residual was:

- `pow_irrational`: about `1.90x` slower than host glibc
- `powf_irrational`: about `1.74x` slower than host glibc

The proposed lever is large and valid only if a fresh current-head same-worker
profile still reproduces a material gap.

## Current-head Routing Profile

Commit: `5896df99`

RCH worker: `vmi1153651`

Command:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass88-pow-route-target CRITERION_HOME=/data/tmp/frankenlibc-pass88-pow-route-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/(pow_irrational|powf_irrational|pow$|pow_half|log2|exp2)' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Rows:

- `log2/frankenlibc_core`: Criterion `[807.84 ns 861.78 ns 927.07 ns]`,
  p50 `765.600 ns`, p95 `1092.368 ns`, p99 `1491.804 ns`, mean `818.248 ns`
- `log2/host_glibc`: Criterion `[696.52 ns 746.19 ns 811.27 ns]`,
  p50 `682.420 ns`, p95 `1040.415 ns`, p99 `1630.548 ns`, mean `749.034 ns`
- `exp2/frankenlibc_core`: Criterion `[470.68 ns 482.25 ns 493.56 ns]`,
  p50 `477.942 ns`, p95 `569.292 ns`, p99 `741.000 ns`, mean `489.140 ns`
- `exp2/host_glibc`: Criterion `[494.40 ns 506.75 ns 523.75 ns]`,
  p50 `492.935 ns`, p95 `627.631 ns`, p99 `993.588 ns`, mean `517.006 ns`
- `pow_half/frankenlibc_core`: Criterion `[837.27 ns 864.41 ns 892.27 ns]`,
  p50 `893.470 ns`, mean `877.433 ns`
- `pow_half/host_glibc`: Criterion `[1.6936 us 1.7227 us 1.7530 us]`,
  p50 `1677.326 ns`, mean `1754.585 ns`
- `pow_irrational/frankenlibc_core`: Criterion
  `[1.8156 us 1.8718 us 1.9458 us]`, p50 `1776.294 ns`,
  p95 `2269.324 ns`, p99 `3136.961 ns`, mean `1837.275 ns`
- `pow_irrational/host_glibc`: Criterion `[1.6462 us 1.6790 us 1.7135 us]`,
  p50 `1686.754 ns`, p95 `2322.408 ns`, p99 `5513.969 ns`,
  mean `1960.379 ns`
- `powf_irrational/frankenlibc_core`: Criterion
  `[1.0128 us 1.0498 us 1.0937 us]`, p50 `1006.993 ns`,
  p95 `1187.302 ns`, p99 `1485.546 ns`, mean `1017.730 ns`
- `powf_irrational/frankenlibc_old_libm`: Criterion
  `[4.4505 us 4.6267 us 4.8339 us]`, p50 `4426.008 ns`,
  mean `4659.461 ns`
- `powf_irrational/host_glibc`: Criterion
  `[975.99 ns 1.0736 us 1.2143 us]`, p50 `941.706 ns`,
  p95 `1524.391 ns`, p99 `2207.066 ns`, mean `1050.214 ns`
- `log2f/frankenlibc_core`: Criterion `[389.06 ns 402.21 ns 417.30 ns]`,
  p50 `405.044 ns`, mean `473.610 ns`
- `log2f/host_glibc`: Criterion `[490.76 ns 508.50 ns 536.90 ns]`,
  p50 `485.360 ns`, mean `493.012 ns`

Build notes: the run emitted the known missing-SMT-solver build warning and the
pre-existing `string/regex.rs::prefilter_skips` dead-code warning. Neither is a
pow behavior or benchmark artifact.

## Verdict

REJECTED no-code. Score `0.0`.

The claimed fused-pow target did not reproduce on current `5896df99`:

- `pow_irrational` is only `1.053x` slower by p50 (`1776.294 ns` vs
  `1686.754 ns`) and is faster by mean (`1837.275 ns` vs `1960.379 ns`).
- `powf_irrational` is only `1.069x` slower by p50 (`1006.993 ns` vs
  `941.706 ns`) and is faster by mean (`1017.730 ns` vs `1050.214 ns`).
- `pow_half` and `exp2` are already faster than host.

No source was changed, so behavior is unchanged by construction. Ordering,
tie-breaking, floating-point results, errno/fenv-facing behavior, and RNG were
not touched.

Next route: do not start the multi-hour ARM fused-pow port from this stale
target. The current profile points instead at the smaller f64 `log2` residual:
FrankenLibC `log2` p50/mean `765.600/818.248 ns` vs host
`682.420/749.034 ns`. Any follow-up must first file or claim a dedicated
profile-backed `log2` bead and use a fundamentally different generated
minimax/table or range-reduction primitive with a 4-ULP/golden proof.
