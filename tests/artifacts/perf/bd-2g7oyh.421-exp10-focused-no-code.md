# bd-2g7oyh.421 exp10 focused no-code closeout

Date: 2026-06-15
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Pass 122 broad RCH profiling on current head selected double `exp10` as the
strongest apparent math residual:

```text
Worker: ovh-a
FrankenLibC exp10: Criterion [496.79 ns 502.22 ns 506.59 ns], p50/mean 493.488/418.227 ns
host glibc exp10: Criterion [301.09 ns 306.30 ns 314.20 ns], p50/mean 319.555/356.857 ns
```

Prior no-retry families remain active:

- `bd-2g7oyh.382`: centered `10^(k/16)` table plus Horner residual regressed.
- `bd-2g7oyh.388`: 1/64 fractional table plus degree-7 underlying `exp2`
  residual regressed.
- `bd-2g7oyh.411`: exact profile dispatch screen regressed.

No source was edited before the focused gate.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-421-exp10-baseline-target-20260615T1930 \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-421-exp10-baseline-criterion-20260615T1930 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'glibc_baseline_math/exp10/' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854` for the focused run.

```text
FrankenLibC exp10: Criterion [303.68 ns 311.62 ns 320.14 ns], p50/mean 324.710/336.409 ns
host glibc exp10: Criterion [328.07 ns 330.93 ns 334.14 ns], p50/mean 332.776/335.790 ns
```

The focused gate did not reproduce the broad residual. FrankenLibC is faster at
p50 and only 0.18 percent slower by mean on the same worker.

## Isomorphism

No production source changed. Exact integer handling, fallback ordering,
special-value behavior, floating-point results, errno/fenv routing,
ordering/tie-breaking, allocation behavior, and RNG behavior are unchanged by
construction.

Golden fixture sha256 values:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

## Verdict

NO-CODE REJECTED.

Score: `0.0`.

Do not attack double `exp10` from this broad row. Reprofile current head and
route to a different reproduced residual. If `exp10` reappears with a material
focused same-worker p50 and mean gap, the next admissible source route is a
generated proof-carrying `exp2` primitive replacement, not another surface
`exp10` table, residual, or dispatch-screen variant.
