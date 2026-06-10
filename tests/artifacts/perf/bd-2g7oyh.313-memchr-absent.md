# bd-2g7oyh.313 memchr_absent focused baseline miss

Date: 2026-06-10
Agent: BoldFalcon
Scope: no source edit

## Target

`bd-2g7oyh.313` was selected from the pass-39 broad RCH profile as an
unowned `memchr_absent` residual after excluding peer-owned `pow` and
`strncmp` lanes.

Fresh routing evidence on `vmi1227854` at pushed `f2b40b12`:

| profile row | FrankenLibC p50 ns | host p50 ns | p50 ratio | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| broad `memchr_absent` | 27.831 | 20.125 | 1.383x | 30.160 | 21.839 |

Prior rejected families for this function include folded-panel widening,
SWAR wordgroups, 64-lane rank/select, indexed folded scans, and earlier
focused-baseline misses. The bead required a focused same-worker baseline
before any edit.

## Focused Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd313-memchr-baseline-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memchr_absent --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 24.004 | 30.530 | 27.562 | 60.000 |
| host glibc | 21.634 | 24.369 | 30.125 | 73.938 |

The focused p50 gap collapsed to `1.11x` with only a `2.370 ns` absolute
gap. Mean remained `1.25x`, but the tail profile does not justify another
`memchr` code edit after the already rejected primitive families.

## Isomorphism

No source changed. First-match ordering, absent/present/tail semantics,
bounded `n` behavior, floating-point state, and RNG state are unchanged by
construction. Golden output SHA is unchanged by construction.

## Verdict

No-code rejected, Score `0.0`.

Next route: reprofile and attack a different measured residual such as
`memmove_4096`, or return to `memchr` only with a disassembly/codegen-backed
primitive and a focused baseline showing a material same-worker gap.
