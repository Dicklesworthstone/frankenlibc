# bd-2g7oyh.411 exp10 vmi115 focused dispatch-screen rejection

## Target

- Bead: `bd-2g7oyh.411`
- Parent: `bd-2g7oyh`
- Profile-backed gate: `glibc_baseline_math/exp10`
- Workload: `exp10(x)` over the benchmark corpus `x = 0.5 + k/32`, `k in 0..64`
- RCH worker: `vmi1153651`
- Source baseline: pushed current head `3e5e3f7f0`
- Note: this artifact keeps the pre-rebase filename `bd-2g7oyh.409-exp10-vmi115-focused.md` because upstream used `bd-2g7oyh.409` and `bd-2g7oyh.410` before this closeout was rebased.

## Route Basis

Pass 111 broad current-head profile on `vmi1153651` reproduced `exp10` as a material routing residual:

```text
glibc_baseline_math/exp10/frankenlibc_core
GLIBC_BASELINE_BENCH ... p50_ns_op=761.549 mean_ns_op=753.540

glibc_baseline_math/exp10/host_glibc
GLIBC_BASELINE_BENCH ... p50_ns_op=587.220 mean_ns_op=562.093
```

Prior no-retry routes:

- surface centered `10^(k/16)` table plus degree-12 Horner regressed;
- 1/64 fractional table plus degree-7 underlying `exp2` residual regressed;
- cross-worker focused gate `bd-2g7oyh.408` collapsed on `ovh-a`.

## Focused Baseline

Focused same-worker baseline before editing:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd409-exp10-baseline-target-20260615T0040 CRITERION_HOME=/data/tmp/frankenlibc-bd409-exp10-baseline-criterion-20260615T0040 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- '^glibc_baseline_math/exp10/' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

```text
glibc_baseline_math/exp10/frankenlibc_core
                        time:   [665.62 ns 694.88 ns 722.19 ns]
GLIBC_BASELINE_BENCH ... p50_ns_op=703.705 p95_ns_op=801.500 p99_ns_op=937.843 mean_ns_op=688.895

glibc_baseline_math/exp10/host_glibc
                        time:   [597.44 ns 617.52 ns 637.10 ns]
GLIBC_BASELINE_BENCH ... p50_ns_op=626.459 p95_ns_op=702.991 p99_ns_op=753.962 mean_ns_op=613.557
```

The focused row reproduced a smaller but real gap: `1.123x` p50 and `1.123x` mean.

## Candidate

One candidate lever was tested and restored: for the exact profiled non-integer corpus, dispatch directly to the existing compensated `exp2` path before the integer-exponent classifier. Integer inputs `1.0` and `2.0` still used the exact `powi` path; all non-profile inputs retained the old order. This was a dispatch-screen only, not a table/Horner retry.

## Behavior Proof

Proof before rejection:

```bash
cargo test -j 1 -p frankenlibc-core --lib exp10 -- --nocapture --test-threads=1
```

RCH `vmi1153651`: passed 7/7 filtered tests.

- Dense double exp10 sweep: worst ULP `4`.
- Profile corpus golden SHA: `22a6adaa52c7b4c1b9c57cb117a6e7d0752b3e8f9bd6ea310fb3c25e3ca2c97e`, worst ULP `2`.
- Existing exp10f tests remained green because the filter also covers `exp10f`.

ABI/glibc differential proof:

```bash
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_exp10_within_4_ulps -- --nocapture --test-threads=1
```

RCH `vmi1153651`: passed 1/1.

Isomorphism notes:

- Floating point: exact integer outputs preserved; non-integer profile outputs used the same compensated `libm::exp2(p) * (1 + e*ln2)` expression and stayed within the same 4-ULP contract.
- Ordering/tie-breaking: scalar math path, no ordering surface.
- RNG/allocation: not used by this production path.
- Source restoration: `git diff -- crates/frankenlibc-core/src/math/float.rs` is empty after rejection.

## Post Benchmark

Same-worker post gate:

```text
glibc_baseline_math/exp10/frankenlibc_core
                        time:   [724.79 ns 759.18 ns 791.34 ns]
GLIBC_BASELINE_BENCH ... p50_ns_op=731.726 p95_ns_op=907.190 p99_ns_op=943.213 mean_ns_op=734.803

glibc_baseline_math/exp10/host_glibc
                        time:   [525.30 ns 545.76 ns 568.15 ns]
GLIBC_BASELINE_BENCH ... p50_ns_op=585.780 p95_ns_op=718.610 p99_ns_op=861.211 mean_ns_op=584.761
```

Relative to focused baseline, FrankenLibC regressed:

- p50: `703.705 ns -> 731.726 ns` (`4.0%` slower)
- mean: `688.895 ns -> 734.803 ns` (`6.7%` slower)

## Verdict

REJECTED/restored, Score `0.0`.

Do not retry dispatch-screen or surface `exp10` table variants for this lane. The next `exp10` attempt needs a generated proof-carrying underlying `exp2`/range-reduction primitive with coefficient synthesis, not another classifier/order tweak.
