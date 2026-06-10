# bd-2g7oyh.327 fnmatch_bracket focused gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

`bd-2g7oyh.327` screened `fnmatch_bracket` after pass 54 broad profiling on
`vmi1227854`.

Broad route basis:

| impl | p50 ns | mean ns |
| --- | ---: | ---: |
| FrankenLibC | 121.438 | 127.655 |
| host glibc | 90.413 | 94.919 |

The broad route was `1.343x` by p50 and `1.345x` by mean.

The candidate, only if the focused gap reproduced, was a safe-Rust
predecoded/branchless bracket-class path for repeated small literal bracket
atoms under the existing iterative star backtracker.

## Focused Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd327-fnmatch-bracket-baseline-target-20260610T1854 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_fnmatch_bracket --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`, matching the broad worker. Remote build:
`29879662679165343`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 108.024 | 111.921 | 142.302 | 150.000 |
| host glibc | 121.371 | 115.346 | 130.250 | 190.090 |

The focused gate reversed the broad result: FrankenLibC was faster by p50 and
slightly faster by mean.

## Isomorphism

No source code changed.

- Bracket parsing and malformed-bracket behavior: unchanged by construction.
- Negation/range/class/collation behavior: unchanged by construction.
- PATHNAME/PERIOD/CASEFOLD/NOESCAPE/LEADING_DIR semantics: unchanged by construction.
- Star retry ordering and tie-breaking: unchanged by construction.
- Floating point and RNG: not involved.
- Source SHA-256:
  - `crates/frankenlibc-core/src/string/fnmatch.rs`
    `9f4ca2c734f7c4ebbdfa6f6093257f9057e81d46193b4d3a14105afc42804e0d`

## Verdict

NO-CODE REJECTED. Score `0.0`.

No source edit is permitted because the focused same-worker baseline did not
reproduce a material gap. Only return to this fnmatch bracket route with a
material focused same-worker gap and a structurally different predecoded or
branchless bracket-class primitive.
