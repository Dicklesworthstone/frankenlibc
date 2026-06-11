# bd-2g7oyh.336 printf_g_6 focused baseline gate

Date: 2026-06-11
Agent: CodexOpt
Scope: no source edit

## Target

Pass 64 selected `printf_g_6` from the fresh broad RCH profile on `ovh-a`
after excluding peer-owned lanes and recent repeated string/memory gates:

| row | FrankenLibC p50 ns | host p50 ns | p50 ratio | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| broad `printf_g_6` | 229.443 | 134.945 | 1.700x | 236.423 | 150.441 |

Prior history:

- `bd-2g7oyh.145` kept the rounded-scientific reuse lever in `format_g`.
- `bd-2g7oyh.318` focused the same row on `vmi1227854` and collapsed to only
  `1.08x` p50 / `1.05x` mean, so no edit was attempted.

The canonical alien routing for stdio/parser/locale format paths points to
weighted VPA, semiring transducers, and algebraic normalization, which would be
eligible only after a material focused gap.

## Focused RCH Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env \
AGENT_NAME=CodexOpt FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass64-printf-g6-focused-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
printf_g_6 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 137.929 | 143.894 | 166.848 | 240.500 |
| host glibc | 141.195 | 147.909 | 179.119 | 220.500 |

Criterion intervals:

- FrankenLibC: `[139.64 ns, 143.87 ns, 147.89 ns]`
- host glibc: `[147.12 ns, 155.19 ns, 162.63 ns]`

## Decision

No-code rejected.

The focused remote gate reversed the broad-profile gap: FrankenLibC is faster
than host on p50 and mean for the target row. A `printf.rs` edit would violate
the profile-backed target rule.

Source and golden artifacts are unchanged by construction:

- `crates/frankenlibc-core/src/stdio/printf.rs` SHA-256:
  `123a26fd4a851a241dc22cbda89fbcdb8c369623c1a82fba40e8ae6d074f70c9`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` SHA-256:
  `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`
- `tests/conformance/fixtures/printf_conformance.json` SHA-256:
  `b8657a70042071e59636fe167d7ffdfb6ae25dab77a173056cec1465ae27c6ad`
- `tests/conformance/printf_float_precision_completion_contract.v1.json`
  SHA-256:
  `37afdbe71744699be4a8a5c99e1492e8a5b9647fe19e34584f4751b7b8fc8fff`
- `crates/frankenlibc-core/tests/printf_float_differential_probe.rs`
  SHA-256:
  `a987c9a85cc288fc84d6d378fbe36119983fffbc205170761d3100d837df59a2`

Ordering, tie-breaking, decimal rounding, floating-point behavior, RNG state,
and golden outputs are unchanged by construction.

Score: `(Impact 0 * Confidence 5) / Effort 1 = 0.0`.

## Next Route

Choose a different profile-backed unowned residual. Do not return to
`printf_g_6` without a material focused remote gap and a structurally different
stdio formatting primitive such as a generated `%g` digit transducer with full
printf differential and golden SHA proof.
