# bd-2g7oyh.317 - fnmatch_bracket focused gate

Date: 2026-06-10
Agent: BoldFalcon
Status: no-code rejected

## Target

`fnmatch` bracket/star no-match workload:

- pattern: `*[ab]*[ab]*[ab]*[ab]*[ab]*c`
- text: `ababababababababab`
- flags: `0`
- expected result: no match

The target came from the broad RCH sweep after `bd-2g7oyh.315`, where
`fnmatch_bracket` appeared as an unowned residual:

- FrankenLibC: p50 `115.125 ns`, mean `118.399 ns`
- host glibc: p50 `81.651 ns`, mean `87.296 ns`
- worker: `vmi1227854`

The existing production route is `fnmatch_simple`, an iterative single-backtrack
matcher with shared `bracket_match_one` parsing. No source was edited before the
focused baseline.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-317-fnmatch-bracket-baseline-target-20260610T060752Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-317-fnmatch-bracket-baseline-criterion-20260610T060752Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_fnmatch_bracket --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected worker `vmi1227854`.

Criterion summary:

| implementation | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 98.556 | 101.339 | 137.599 | 139.561 |
| host glibc | 96.061 | 100.718 | 122.684 | 135.000 |

Criterion confidence interval:

- FrankenLibC: `[103.62 ns, 111.74 ns, 119.49 ns]`
- host glibc: `[89.277 ns, 92.365 ns, 95.956 ns]`

## Behavior Proof

No source files were edited. Match ordering, wildcard tie-breaking, bracket
semantics, PATHNAME/PERIOD/CASEFOLD/NOESCAPE behavior, floating-point behavior,
and RNG behavior are unchanged by construction.

Source/oracle hashes:

- `crates/frankenlibc-core/src/string/fnmatch.rs`: `9f4ca2c734f7c4ebbdfa6f6093257f9057e81d46193b4d3a14105afc42804e0d`
- `crates/frankenlibc-abi/tests/conformance_diff_fnmatch_glob.rs`: `ed958c528d39d57cb476ae998f86d412c935c1a8d6746af40634cd44a5bc92d7`
- `crates/frankenlibc-abi/tests/fnmatch_differential_fuzz.rs`: `700b7e8a2a81a66147a87310473d0a0684768cb0f44089650e2d3078e208db72`

## Verdict

Rejected with no code change. The focused same-worker gate collapsed the broad
gap to a small, non-material delta:

- p50 ratio: `1.03x` (`98.556 / 96.061`)
- mean ratio: `1.01x` (`101.339 / 100.718`)

Score: `0.0`.

No `fnmatch_bracket` source lever should be attempted from this broad-sweep
evidence. If this row reappears with a material focused same-worker gap, the
next route should be a structurally different safe-Rust bracket/star no-match
primitive with dense live-glibc differential coverage, not a local tweak to the
current backtrack loop.
