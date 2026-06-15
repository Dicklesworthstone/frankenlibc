# bd-2g7oyh.408 exp10 focused gate no-code closeout

## Target

- Bead: `bd-2g7oyh.408`
- Parent: `bd-2g7oyh`
- Profile-backed gate: `glibc_baseline_math/exp10`
- Workload: `exp10(x)` for `x in [0.5, 2.5)`
- Baseline source: production source at `a189aa2f5`; later tracker-only commits did not change the `exp10` implementation
- RCH workers: broad route on `vmi1153651`; focused baseline selected `ovh-a`

## Broad Route Basis

Pass 109 current-head profile on `vmi1153651` showed a broad `exp10` residual:

```text
glibc_baseline_math/exp10/frankenlibc_core
GLIBC_BASELINE_BENCH ... p50_ns_op=816.959 mean_ns_op=1481.818

glibc_baseline_math/exp10/host_glibc
GLIBC_BASELINE_BENCH ... p50_ns_op=654.186 mean_ns_op=689.784
```

This was only routing evidence. Prior `exp10` source-level families are already no-retry without a deeper primitive:

- `bd-2g7oyh.382`: centered `10^(k/16)` table plus degree-12 Horner proved within contract but regressed.
- `bd-2g7oyh.388`: 1/64 fractional table plus degree-7 underlying `exp2` residual proved within contract but regressed.

The admissible next source route would be a generated proof-carrying replacement for the underlying `exp2` kernel, not another surface `exp10` table/residual micro-lever.

## Focused Baseline

The required focused baseline was taken before any source edit:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd407-exp10-baseline-target-20260615T0019 CRITERION_HOME=/data/tmp/frankenlibc-bd407-exp10-baseline-criterion-20260615T0019 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- '^glibc_baseline_math/exp10/' --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected `ovh-a` despite the `vmi1153651` preference. Because no source edit followed, this is sufficient for a no-code route closeout:

```text
glibc_baseline_math/exp10/frankenlibc_core
                        time:   [306.40 ns 323.93 ns 345.90 ns]
GLIBC_BASELINE_BENCH profile_id=exp10 impl=frankenlibc_core api_family=math symbol=exp10 workload="exp10(x) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=101 p50_ns_op=289.377 p95_ns_op=461.031 p99_ns_op=501.205 mean_ns_op=316.101

glibc_baseline_math/exp10/host_glibc
                        time:   [292.12 ns 294.12 ns 296.58 ns]
GLIBC_BASELINE_BENCH profile_id=exp10 impl=host_glibc api_family=math symbol=exp10 workload="exp10(x) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=101 p50_ns_op=295.325 p95_ns_op=391.375 p99_ns_op=416.000 mean_ns_op=312.050
```

Focused result: FrankenLibC is slightly faster at p50 (`289.377 ns` vs `295.325 ns`) and effectively tied at mean (`316.101 ns` vs `312.050 ns`, about `1.3%` slower). The broad mean tail did not reproduce as a material focused same-worker gap.

## Behavior Proof

No source was changed:

- Ordering/tie-breaking: not applicable to scalar math dispatch here.
- Floating point: unchanged; exact integer handling, the existing finite-band `libm::exp2(p) * (1.0 + e * ln2)` route, and the `libm::exp10` fallback remain byte-for-byte current source.
- Golden output: unchanged by construction; the existing exp10 proof corpus and ABI/glibc differential tests remain the active contract.
- RNG/allocation: not used by this production path.

## Verdict

NO-CODE REJECTED, Score `0.0`.

Do not retry surface `exp10` table/Horner or 1/64 residual variants. If `exp10` reappears with a material focused same-worker gap, attack the generated proof-carrying underlying `exp2` kernel primitive with its own coefficient artifact, golden SHA, ABI differential proof, and before/after RCH gate.
