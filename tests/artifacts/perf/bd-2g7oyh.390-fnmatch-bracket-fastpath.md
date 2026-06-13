# bd-2g7oyh.392 fnmatch bracket focused gate

Date: 2026-06-13
Agent: BoldFalcon
Head: fd847b96922f0d5d69712d732cb2ee7ec26fd4ad

Note: this artifact filename keeps the pre-rebase local bead suffix
`bd-2g7oyh.390`; the actual tracker row was renumbered to `bd-2g7oyh.392`
after upstream concurrently used `.390` for malloc and `.391` for memmove.

## Target

`glibc_baseline_fnmatch_bracket/fnmatch_bracket`

Workload: `*[ab]*[ab]*[ab]*[ab]*[ab]*c` against `ababababababababab`
with `FnmatchFlags::NONE`.

The current-head routing slice on RCH worker `vmi1227854` showed a material
possible residual:

- FrankenLibC p50/mean: `132.118 / 130.951 ns`
- host glibc p50/mean: `95.531 / 102.216 ns`

Prior bead `bd-2g7oyh.327` had already shown this row can collapse on focused
runs, so this bead required a fresh focused baseline before any source edit.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass90-fnmatch-baseline-target \
CRITERION_HOME=/data/tmp/frankenlibc-pass90-fnmatch-baseline-criterion \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_fnmatch_bracket --noplot --sample-size 80 \
--warm-up-time 1 --measurement-time 4
```

RCH selected worker: `vmi1153651`.

Focused result:

- FrankenLibC Criterion interval: `[262.82 ns 273.55 ns 285.42 ns]`
- FrankenLibC emitted p50/mean: `254.445 / 267.271 ns`
- host glibc Criterion interval: `[230.13 ns 242.91 ns 264.06 ns]`
- host glibc emitted p50/mean: `230.232 / 261.935 ns`

## Verdict

No source edit. The focused same-worker gap collapsed to `1.105x` by p50 and
`1.020x` by mean, with host outliers overlapping the FrankenLibC p95 range.
That is not a keepable Score>=2.0 target.

Candidate not attempted: tiny literal bracket-set fast path for `[ab]`.

Behavior parity is unchanged by construction:

- Ordering/tie-breaking: no source changed.
- Bracket syntax, negation, ranges, classes, collation, escape handling: no
  source changed.
- PATHNAME/PERIOD/CASEFOLD/LEADING_DIR: no source changed.
- FP/RNG/allocation state: untouched.
- Golden-output SHA: unchanged by construction because no source or test corpus
  changed.

Score: `0.0`.

Next route: do not retry this bracket row unless a future focused same-worker
baseline reproduces a material gap. Move to the next profile-backed residual
with a different primitive.
