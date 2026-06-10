# bd-2g7oyh.318: printf_g_6 focused gate

## Target

Fresh pass-44 broad RCH sweep at `83479686` on `vmi1227854` showed
`glibc_baseline_printf_float/printf_g_6` as an unowned residual:

- FrankenLibC: p50 `160.234 ns`, mean `274.315 ns`
- host glibc: p50 `136.014 ns`, mean `153.362 ns`

Prior `bd-2g7oyh.145` already kept the rounded-scientific reuse lever in
`format_g`, so this bead required a focused same-worker gate before any new
source edit. A repeated allocation/string-construction cleanup would only be
eligible if the focused gap remained material.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-318-printf-g6-baseline-target-20260610T062320Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-318-printf-g6-baseline-criterion-20260610T062320Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
printf_g_6 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854` and completed successfully.

Focused result:

- FrankenLibC: p50 `149.081 ns`, mean `149.691 ns`, p95 `169.648 ns`, p99 `298.254 ns`
- host glibc: p50 `138.463 ns`, mean `142.545 ns`, p95 `172.287 ns`, p99 `174.928 ns`

The focused same-worker gap collapsed to `1.08x` p50 and `1.05x` mean. That is
below the Score>=2.0 edit gate, so no source lever was attempted.

## Isomorphism / Golden State

No source was edited. `format_g` remains the existing rounded-scientific reuse
implementation from `bd-2g7oyh.145`.

- Ordering/tie-breaking: unchanged by construction.
- Floating-point behavior: unchanged by construction.
- RNG: not applicable.
- Golden outputs: unchanged by construction; current SHA-256 references:
  - `tests/conformance/fixtures/printf_conformance.json`
    `b8657a70042071e59636fe167d7ffdfb6ae25dab77a173056cec1465ae27c6ad`
  - `tests/conformance/printf_float_precision_completion_contract.v1.json`
    `37afdbe71744699be4a8a5c99e1492e8a5b9647fe19e34584f4751b7b8fc8fff`
  - `crates/frankenlibc-core/tests/printf_float_differential_probe.rs`
    `a987c9a85cc288fc84d6d378fbe36119983fffbc205170761d3100d837df59a2`

## Verdict

NO-CODE REJECTED, Score `0.0`.

The broad `printf_g_6` tail did not reproduce as a material focused gap on the
same worker. Do not repeat the `bd-2g7oyh.145` rounded-scientific reuse family.
Only return to `%g` with a material focused same-worker gap and a structurally
different safe-Rust formatting primitive backed by the printf differential and
golden SHA proof.
