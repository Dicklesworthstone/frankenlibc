# bd-e4jb7k log2 table kernels rejected

Date: 2026-06-05
Agent: BlackThrush
Worker: RCH ts1

## Baseline

Command:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-baseline \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_math/log2/' --sample-size 30 --warm-up-time 1 \
  --measurement-time 3 --noplot
```

Baseline row:

```text
frankenlibc_core p50=437.592 ns p95=528.088 p99=581.981 mean=452.565
host_glibc       p50=334.461 ns p95=375.500 p99=467.476 mean=345.313
```

## Rejected lever 1: DD table + atanh finalization

Shape: 16-entry mantissa table, double-double `log2(c)` constants,
`log(m/c)=2*atanh((m-c)/(m+c))`, compensated final sum, exact-power and
near-1 fallbacks.

Behavior proof passed:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-test \
  cargo test -p frankenlibc-core log2_ -- --nocapture --test-threads=1
```

Result: 6 focused log2/pow tests passed, including the full dynamic-range
`log2_fast_path_within_4_ulps_of_glibc` sweep and a profile-domain table sweep.
Golden table/atanh corpus sha256 during the candidate was
`3f80e49b3b0715344e8a9e978dc18da02f8bd25e2073c88d0809243a637eefed`.

Post-benchmark:

```text
frankenlibc_core p50=582.441 ns p95=913.316 p99=1051.562 mean=628.316
host_glibc       p50=335.459 ns p95=504.794 p99=517.724 mean=374.186
```

Decision: reject. The division in the atanh reduction dominated the saved libm
call. Score 0.0.

## Rejected lever 2: reciprocal table + degree-9 Taylor

Shape: 16-entry reciprocal/log table, degree-9 `log2(1+r)` Taylor kernel,
double-double `log2(c)` constants, compensated final sum, exact-power fallback,
and a wider `[0.7, 1.35]` fallback band to preserve the 4-ULP contract.

Behavior proof passed:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- \
  env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-e4jb7k-test2 \
  cargo test -p frankenlibc-core log2_ -- --nocapture --test-threads=1
```

Result: 6 focused log2/pow tests passed, including the full dynamic-range
`log2_fast_path_within_4_ulps_of_glibc` sweep and a profile-domain table sweep.
Golden table/poly corpus sha256 during the candidate was
`7db6f5dd02f63f92ae65b6992ef8bc2131c49560790320ebc8ab73da5c626e7a`.

Post-benchmark:

```text
frankenlibc_core p50=654.875 ns p95=711.076 p99=843.368 mean=666.786
host_glibc       p50=335.549 ns p95=370.906 p99=446.560 mean=340.390
```

Decision: reject. Extra branches/table arithmetic outweighed the current
`libm::log(x) * LOG2_E` route even when 41 of 64 profiled points used the fast
path. Score 0.0.

## Isomorphism status

- Ordering/tie-breaking: N/A for scalar `log2`; no ordering surface.
- Floating-point: both candidates proved <=4 ULP vs host glibc on focused
  profile-domain and existing full-range sweeps; exact powers of two, subnormals,
  non-positive, and non-finite inputs stayed on fallback paths.
- RNG: N/A.
- Golden output: candidate-specific golden hashes are recorded above; no source
  change was kept, so committed behavior returns to the pre-candidate golden state.

## Next primitive

Do not retry small scalar table/log2 microkernels for this bead. The next deeper
log-family attack should be an offline-generated piecewise minimax/Estrin kernel
with an explicit operation-count budget, or a different profiler-evident hotspot
after reprofile if log2 is no longer the best unowned target.
