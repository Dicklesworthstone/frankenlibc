# bd-2g7oyh.335 memchr_absent focused baseline gate

Date: 2026-06-11
Agent: CodexOpt
Scope: no source edit

## Target

Pass 63 selected `memchr_absent` from the fresh broad RCH profile on `ovh-a`
after excluding peer-owned lanes:

| row | FrankenLibC p50 ns | host p50 ns | p50 ratio | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| broad `memchr_absent` | 32.177 | 19.118 | 1.683x | 36.782 | 21.930 |

The lane already has substantial history:

- `bd-2g7oyh.179` kept the indexed folded scan.
- `bd-2g7oyh.271`, `bd-2g7oyh.293`, and `bd-2g7oyh.313` recorded focused
  misses or small focused gaps.
- Prior no-retry families include folded-panel widening, SWAR wordgroups,
  64-lane mask/rank-select, and indexed folded-scan control-flow rewrites.

This pass therefore required a fresh remote focused gate and a genuinely
different primitive before any source edit.

## Focused RCH Baseline

The `ovh-a` broad-profile worker was pressure-gated, so the focused gate used
the current healthy remote worker and treated this run as the actionable
baseline:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=CodexOpt FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass63-memchr-focused-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memchr_absent --noplot --sample-size 50 \
--warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 27.843 | 33.499 | 34.562 | 65.000 |
| host glibc | 22.628 | 23.958 | 28.881 | 55.000 |

Criterion intervals:

- FrankenLibC: `[28.336 ns, 29.056 ns, 29.888 ns]`
- host glibc: `[23.075 ns, 23.650 ns, 24.209 ns]`

## Decision

No-code rejected.

The focused gate still shows a residual, but it is not enough to justify
retuning the same `memchr` implementation family: the current code is already
the accepted indexed folded scan, and the obvious safe-Rust changes are repeats
of rejected folded, SWAR, wide-panel, or rank/select microfamilies. Under the
no-ceiling directive, the right response is to route to a different
profile-backed primitive rather than ship another unproven micro-tweak.

Source unchanged by construction:

- `crates/frankenlibc-core/src/string/mem.rs` SHA-256:
  `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` SHA-256:
  `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

Ordering, first-match semantics, bounded `n` behavior, tie-breaking,
floating-point state, RNG state, and golden outputs are unchanged by
construction.

Score: `(Impact 0 * Confidence 4) / Effort 1 = 0.0`.

## Next Route

Continue from the broad profile with a different unowned residual. Candidate
lanes include `memcmp_4096`, `printf_g_6`, or unowned math rows after a fresh
focused RCH gate. Do not return to `memchr_absent` without a disassembly- or
codegen-backed new primitive and a material focused remote gap.
