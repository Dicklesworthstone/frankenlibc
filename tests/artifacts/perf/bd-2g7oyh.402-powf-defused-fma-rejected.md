# bd-2g7oyh.402 powf irrational defused-FMA rejection

## Target

- Bead: `bd-2g7oyh.402`
- Workload: `glibc_baseline_math/powf_irrational`
- Symbol: `powf(x, 1.337)` for `x in [0.5, 2.5)`
- Worker: RCH `vmi1153651`
- Candidate: change the accepted exact-exponent Estrin evaluator from fused
  `f64::mul_add` nodes back to explicit multiply/add nodes.

The candidate was only a defused-FMA variant of the already-kept `.272` FMA
family and `.357` Estrin schedule. It was allowed to finish because it was the
current in-flight bead, but it is not a materially new primitive.

## Baseline

Clean detached current-HEAD worktree:
`/data/projects/.scratch/frankenlibc-bd402-baseline-20260614T0953Z`
at commit `6fdeee859`.

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd402-powf-baseline-target-20260614T0954 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd402-powf-baseline-criterion-20260614T0954 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

RCH rerouted the requested `vmi1227854` worker to `vmi1153651`, so the
candidate and proof gates used `vmi1153651` for same-worker comparison.

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC current | 1017.959 | 1051.790 | 1453.670 | 1566.754 |
| old libm | 4403.048 | 4657.175 | 6311.442 | 7347.243 |
| host glibc | 913.730 | 973.358 | 1534.049 | 1630.389 |

## Candidate Proof

Core ULP proof:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd402-powf-proof-core-20260614T1002 \
  cargo test -j 1 -p frankenlibc-core --lib \
  powf_profile_exp_1_337_poly_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed on RCH `vmi1153651`; worst ULP stayed `2` at base `0.5`.

ABI/glibc differential proof:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd402-powf-proof-abi-20260614T1007 \
  cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math \
  diff_powf_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result: passed on RCH `vmi1153651`.

Golden fixture SHA-256 values were unchanged:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

Isomorphism notes:

- Ordering/tie-breaking: scalar math function; not applicable.
- Floating point: only the exact exponent bits `0x3fab_22d1` inside the
  existing finite positive `[0.5, 2.5)` gate changed during the candidate.
  The dense/random ULP proof and ABI/glibc differential stayed within the
  existing `<= 4` ULP contract.
- Fallback preservation: every non-gated exponent and out-of-domain base kept
  the previous route.
- RNG: production path has no RNG; proof sweeps are deterministic.

## Candidate Benchmark

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd402-powf-post-target-20260614T1012 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd402-powf-post-criterion-20260614T1012 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | 1101.726 | 1136.004 | 1428.578 | 1635.023 |
| old libm | 4642.604 | 5132.808 | 8050.095 | 10169.525 |
| host glibc | 941.243 | 986.886 | 1353.060 | 1436.035 |

Same-worker delta against clean current-head baseline:

- p50: `1017.959 ns -> 1101.726 ns` (`8.2%` slower)
- mean: `1051.790 ns -> 1136.004 ns` (`8.0%` slower)
- p95 improved slightly (`1453.670 ns -> 1428.578 ns`), but the decisive p50
  and mean both regressed.

## Validation

- `git diff --check -- crates/frankenlibc-core/src/math/float32.rs`: passed.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs`:
  blocked by pre-existing formatting drift at unrelated `acoshf`/`erfcf` test
  lines in the same file; those formatter-only changes were not mixed into this
  perf closeout.

## Verdict

REJECTED and restored. Score `0.0`: proof-clean but negative p50/mean impact.

Do not retry FMA-vs-non-FMA toggles, Horner-vs-Estrin scheduling, degree-12
coefficient reshuffling, or the `.301` 16-segment degree-4 local-polynomial
family for this row. The next admissible powf/log route is a generated,
proof-carrying primitive: Remez/minimax or table-driven `log2f` / `2^r`
reconstruction with coefficient/proof hash, dense 4-ULP glibc replay, and
codegen/disassembly evidence.
