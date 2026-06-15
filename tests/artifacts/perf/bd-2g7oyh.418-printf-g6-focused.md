# bd-2g7oyh.418 printf_g_6 focused no-code gate

Date: 2026-06-15
Agent: BoldFalcon
Worker: vmi1227854
Commit under test: 980de85bf8c40c3ccea5102a285f0ce108d125cb

## Route

Current-head broad RCH routing on ovh-a selected `glibc_baseline_printf_float/printf_g_6` as a possible residual:

- FrankenLibC p50/mean: 237.891 / 217.071 ns
- host glibc p50/mean: 132.461 / 140.820 ns

The broad run was treated as routing evidence only because prior campaign records show cross-worker and broad-sweep rows frequently flip under focused gates.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-418-baseline cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- printf_g_6 --sample-size 20 --warm-up-time 1 --measurement-time 3
```

Focused same-worker result on `vmi1227854`:

- FrankenLibC Criterion interval: [130.13 ns 133.24 ns 137.09 ns]
- FrankenLibC p50/mean: 137.676 / 145.831 ns
- host glibc Criterion interval: [160.88 ns 170.89 ns 183.97 ns]
- host glibc p50/mean: 187.001 / 735.151 ns

## Verdict

NO-CODE REJECTED. The focused gate does not reproduce a vs-host gap; FrankenLibC is faster than host on both p50 and mean on the focused worker.

Score: 0.0. No implementation source changed.

## Behavior Proof

Behavior is unchanged by construction:

- Ordering/tie-breaking: unchanged; no formatting path changed.
- Floating-point output: unchanged; `format_float` and all `%g` helpers are untouched.
- RNG/allocation behavior: unchanged; no code changed.
- Golden output: existing printf float differential/golden tests remain applicable; no new output was generated.

## Reroute

Do not optimize `printf_g_6` from the broad ovh-a row alone. Reprofile current head and select a target whose focused same-worker p50 and mean both reproduce a material gap.
