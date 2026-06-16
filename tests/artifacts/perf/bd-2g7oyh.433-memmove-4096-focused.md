# bd-2g7oyh.433 - memmove_4096 focused no-code closeout

Date: 2026-06-16
Agent: BoldFalcon
Worker: `vmi1227854`
Status: no-code rejected

## Target

Profile-backed row: `glibc_baseline_memmove_4096`

This pass rechecked the residual after the `bd-2g7oyh.432` evidence commit.
Prior no-retry families for this row include wrapper inlining, exact safe-slice
branchbacks, fixed chunk array copies, safe-SIMD copy panels, and surface
exact-copy lowering.

## Focused gate

RCH command:

```text
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion: `[29.365 ns 29.778 ns 30.203 ns]`
- FrankenLibC profile line: p50 `30.046 ns`, mean `32.378 ns`
- host glibc Criterion: `[28.344 ns 28.776 ns 29.240 ns]`
- host glibc profile line: p50 `29.190 ns`, mean `31.011 ns`

The focused same-worker gap collapsed to about `1.03x` by p50 and `1.04x` by
mean. That is not a credible source-edit target under the current one-lever
gate, especially after the prior rejected micro-family streak on this row.

## Behavior proof

Production source was unchanged. Byte order, copied prefix, returned count,
destination tail behavior, overlap semantics, floating-point state, RNG state,
allocation behavior, errno, locale, and existing memmove golden outputs are
unchanged by construction.

## Verdict

No-code rejected. Score: `0.0`.

Do not return to `memmove_4096` without a fresh material focused same-worker gap
and a materially different generated/backend-dispatch or ABI-level no-overlap
primitive.
