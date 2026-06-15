# bd-2g7oyh.407 pow_irrational dyadic-grid follow-up no-code closeout

## Target

- Bead: `bd-2g7oyh.407`
- Parent: `bd-2g7oyh`
- Follow-up source: `bd-2g7oyh.406` kept the exact-profile dispatch reorder for `pow(x, 1.337)`.
- Profile-backed gate: `glibc_baseline_math/pow_irrational`
- Workload: `pow(x, 1.337)` for `x in [0.5, 2.5)`
- Baseline source: `origin/main` commit `a189aa2f5`
- RCH worker: `vmi1227854`

## Current-Origin Baseline

The required baseline was taken before any source edit in the clean detached worktree
`/data/projects/.scratch/frankenlibc-pass109-pow-grid-20260615T0011`.

```text
glibc_baseline_math/pow_irrational/frankenlibc_core
                        time:   [447.21 ns 455.74 ns 463.76 ns]
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=81 p50_ns_op=454.890 p95_ns_op=520.746 p99_ns_op=581.000 mean_ns_op=463.956 throughput_ops_s=2161093.896 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/math/

glibc_baseline_math/pow_irrational/host_glibc
                        time:   [722.64 ns 744.23 ns 765.42 ns]
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=81 p50_ns_op=762.976 p95_ns_op=892.980 p99_ns_op=1002.000 mean_ns_op=770.675 throughput_ops_s=1337567.060 baseline_ref=artifacts/perf/glibc-baseline.md parity_proof_ref=crates/frankenlibc-core/src/math/
```

Baseline command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKERS=vmi1153651 RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd407-pow-baseline-target-20260615T0013 CRITERION_HOME=/data/tmp/frankenlibc-bd407-pow-baseline-criterion-20260615T0013 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/pow_irrational' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854` despite the `vmi1153651` preference. This is still valid for the closeout because no post-change comparison is needed after the no-code screen.

## Candidate Screen

No source lever was applied. The dyadic-grid table idea was based on the pre-`a189aa2f5` dispatch-order baseline. On current `origin/main`, the kept dispatch reorder already makes FrankenLibC faster than host on this focused row:

- FrankenLibC p50: `454.890 ns/op`
- Host glibc p50: `762.976 ns/op`
- FrankenLibC mean: `463.956 ns/op`
- Host glibc mean: `770.675 ns/op`

Applying a table for this exact profile would not be profile-backed against a current vs-host gap. The next pass should reprofile and attack a remaining residual instead of continuing this micro-family.

## Behavior Proof

Production source is unchanged by construction:

- Ordering/tie-breaking: not applicable; scalar math function.
- Floating point: unchanged; the existing exact-profile dispatch, coefficient artifact, Estrin evaluator, and fallback order remain the `a189aa2f5` implementation.
- Golden output: unchanged; no code path or fixture changed.
- RNG/allocation: not used by this production path.

## Verdict

NO-CODE REJECTED, Score `0.0`.

Do not continue the `pow_irrational` dyadic-grid/table micro-family unless a fresh current-head focused same-worker profile again shows a material vs-host gap. Reprofile and move to the next residual.
