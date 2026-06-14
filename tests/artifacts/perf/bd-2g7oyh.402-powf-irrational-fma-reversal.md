# bd-2g7oyh.402 - powf_irrational FMA reversal keep

## Target

- Bead: `bd-2g7oyh.402`
- Workload: `glibc_baseline_math/powf_irrational`
- Symbol: `powf(x, 1.337)` for `x in [0.5, 2.5)`
- Worker: RCH `vmi1227854`
- Baseline commit: `6fdeee859`
- Lever: keep the accepted exact-exponent degree-12 Estrin polynomial and coefficient table, but evaluate each Estrin node as separate multiply plus add instead of `f64::mul_add`.

This is one source lever in `crates/frankenlibc-core/src/math/float32.rs`. The exponent-bit gate, base range, coefficient order, fallback paths, integer/half-integer fast paths, and special-value handling are unchanged.

## Baseline

Clean detached baseline worktree:

```text
/data/projects/.scratch/frankenlibc-bd-2g7oyh-402-baseline-20260614T095419Z
```

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-402-baseline-target-20260614T0954 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-402-baseline-criterion-20260614T0954 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 60 \
  --warm-up-time 1 --measurement-time 3
```

Results:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | 537.412 | 543.666 | 739.658 | 827.330 |
| old libm | 2584.764 | 2538.281 | 3328.750 | 3499.354 |
| host glibc | 448.856 | 455.455 | 598.671 | 618.963 |

## Post-benchmark

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-402-post-target-20260614T1005 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-402-post-criterion-20260614T1005 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 60 \
  --warm-up-time 1 --measurement-time 3
```

Results:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | 511.969 | 509.222 | 586.249 | 740.279 |
| old libm | 2356.398 | 2346.863 | 2960.142 | 3417.066 |
| host glibc | 464.485 | 475.251 | 561.000 | 597.357 |

Same-worker FrankenLibC delta:

- p50: `537.412 -> 511.969 ns/op`, `4.7%` faster.
- mean: `543.666 -> 509.222 ns/op`, `6.3%` faster.
- p95: `739.658 -> 586.249 ns/op`, `20.7%` faster.
- p99: `827.330 -> 740.279 ns/op`, `10.5%` faster.
- p50 gap to host: `88.556 ns -> 47.484 ns`.
- mean gap to host: `88.211 ns -> 33.971 ns`.

## Behavior proof

Core dense/random ULP proof:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-402-proof-core-20260614T0959 \
  cargo test -j 1 -p frankenlibc-core --lib \
  powf_profile_exp_1_337_poly_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed on `vmi1227854`; `powf 1.337 polynomial worst ULP = 2 at base 0.5`.

ABI/glibc differential proof:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-402-proof-abi-20260614T1002 \
  cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math \
  diff_powf_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed on `vmi1227854`.

Golden fixture SHA-256 values remained unchanged:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
97c9763cb656e69eb053ee55e50b9b620f8b70dff5228c0aeb4b7806e75c92b6  crates/frankenlibc-core/src/math/float32.rs
```

Isomorphism notes:

- Ordering/tie-breaking: not applicable; scalar math function.
- Floating point: the exact exponent branch changes from fused multiply-add nodes to separate multiply plus add nodes, so bit identity is intentionally not claimed. The accepted behavior contract is `<= 4 ULP` versus glibc on the profiled lane, and both core plus ABI proofs pass with worst ULP `2`.
- Dispatch: unchanged; only `exponent.to_bits() == 0x3fab_22d1` inside the existing positive finite medium-domain gate takes this branch.
- Fallback: unchanged for out-of-range bases, non-profile exponents, negative/zero/special bases, integer exponents, half-integers, infinities, and NaNs.
- RNG: production has no RNG; proof sweeps use deterministic xorshift seeds only.

## Validation

- `git diff --check -- crates/frankenlibc-core/src/math/float32.rs`: passed.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs`: blocked by pre-existing formatting drift elsewhere in the same file (`acoshf`/`nextafterf` helper lines and a pre-existing array literal); the powf hunk is already rustfmt-neutral and no formatter churn was accepted.
- RCH `vmi1227854` `cargo check -j 1 -p frankenlibc-core --lib`: passed with known pre-existing warnings.
- RCH `vmi1227854` `cargo check -j 1 -p frankenlibc-abi --test conformance_diff_math`: passed with known pre-existing warnings.
- RCH `vmi1227854` strict core clippy first failed only on known pre-existing duplicate-attribute/manual-range lints outside this powf hunk.
- RCH `vmi1227854` allowlisted core clippy passed under `-D warnings` with only the existing lint families allowlisted:
  `unused-attributes`, `dead-code`, `clippy::duplicated_attributes`, `clippy::manual_range_contains`, `clippy::excessive_precision`, `clippy::collapsible_if`, `clippy::manual_contains`, `clippy::type_complexity`, `clippy::unnecessary_map_or`.

## Score

Impact `2.0` x Confidence `4.0` / Effort `1.5` = `5.3`.

Verdict: KEPT. The lever is small but reproducibly improves p50/mean and materially reduces tails and host-gap residual on the same worker while preserving the accepted 4-ULP behavior envelope.

Next route: reprofile current head. If `powf_irrational` remains visible, do not keep retuning the rounding schedule; attack a genuinely different primitive such as a range-split f32 minimax/Estrin artifact or a generated log2/exp2 replacement with its own profile/proof gate.
