# bd-2g7oyh.501 Timing Fast Path Reject

Date: 2026-06-21
Agent: cod-a / BlackThrush
Decision: REJECTED, source reverted

## Hypothesis

After the vDSO parser and `__vdso_time` work, the remaining `clock_gettime` and
`time` losses looked like wrapper residue. The attempted lever was a narrow
fast/slow-path split:

- skip optional pointer validation only for `time(NULL)`;
- add a direct vDSO call for common `clock_gettime` clock ids when the output
  pointer is a likely current-stack object.

This was intentionally separate from the previously rejected vDSO pointer-cache
family.

## Baseline Routing Run

Command:

```text
AGENT_NAME=cod-a BR_AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1 RCH_WORKER=ovh-a RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Worker: `ovh-a`

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 3.00 ns | 5.98 ns | 0.50x | WIN |
| `strtol_dec_long` | 6.19 ns | 12.80 ns | 0.48x | WIN |
| `strtol_hex` | 9.59 ns | 12.87 ns | 0.75x | WIN |
| `atoi_short` | 2.80 ns | 7.08 ns | 0.39x | WIN |
| `atoi_long` | 7.91 ns | 13.66 ns | 0.58x | WIN |
| `atol_short` | 2.57 ns | 6.41 ns | 0.40x | WIN |
| `atol_long` | 7.86 ns | 13.22 ns | 0.59x | WIN |
| `atoll_short` | 2.56 ns | 6.19 ns | 0.41x | WIN |
| `atoll_long` | 7.69 ns | 12.95 ns | 0.59x | WIN |
| `strtod_int` | 9.14 ns | 23.50 ns | 0.39x | WIN |
| `strtod_simple` | 20.60 ns | 43.55 ns | 0.47x | WIN |
| `strtod_sci` | 15.25 ns | 30.90 ns | 0.49x | WIN |
| `rand` | 2.14 ns | 4.42 ns | 0.48x | WIN |
| `getenv_hit` | 7.90 ns | 13.28 ns | 0.60x | WIN |
| `getenv_miss` | 14.29 ns | 29.25 ns | 0.49x | WIN |
| `clock_gettime` | 22.41 ns | 18.78 ns | 1.19x | LOSS |
| `time` | 3.36 ns | 2.10 ns | 1.60x | LOSS |
| `pthread_self` | 1.90 ns | 1.68 ns | 1.13x | LOSS |

Scorecard: 15 WIN / 0 NEUTRAL / 3 LOSS.

## Rejected Candidate Gate

The first draft was discarded as stale evidence because it would have validated
`time(tloc)` too late for non-null bad pointers. It also failed the perf gate on
`ovh-a`: `clock_gettime` stayed 1.19x and `time` worsened to 1.67x.

The corrected candidate preserved validation before any non-null store and was
then measured via:

```text
AGENT_NAME=cod-a BR_AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1 RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

RCH selected `vmi1152480` despite the worker hint.

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 4.37 ns | 8.61 ns | 0.51x | WIN |
| `strtol_dec_long` | 5.50 ns | 9.73 ns | 0.56x | WIN |
| `strtol_hex` | 10.38 ns | 16.64 ns | 0.62x | WIN |
| `atoi_short` | 2.72 ns | 6.01 ns | 0.45x | WIN |
| `atoi_long` | 8.86 ns | 18.07 ns | 0.49x | WIN |
| `atol_short` | 2.67 ns | 5.09 ns | 0.53x | WIN |
| `atol_long` | 9.12 ns | 17.79 ns | 0.51x | WIN |
| `atoll_short` | 3.38 ns | 9.35 ns | 0.36x | WIN |
| `atoll_long` | 9.65 ns | 10.85 ns | 0.89x | WIN |
| `strtod_int` | 13.10 ns | 42.07 ns | 0.31x | WIN |
| `strtod_simple` | 28.43 ns | 73.39 ns | 0.39x | WIN |
| `strtod_sci` | 19.13 ns | 43.10 ns | 0.44x | WIN |
| `rand` | 3.07 ns | 4.41 ns | 0.70x | WIN |
| `getenv_hit` | 11.93 ns | 17.31 ns | 0.69x | WIN |
| `getenv_miss` | 21.33 ns | 27.26 ns | 0.78x | WIN |
| `clock_gettime` | 31.57 ns | 26.45 ns | 1.19x | LOSS |
| `time` | 3.97 ns | 2.22 ns | 1.79x | LOSS |
| `pthread_self` | 2.83 ns | 1.89 ns | 1.49x | LOSS |

Scorecard: 15 WIN / 0 NEUTRAL / 3 LOSS.

## Conformance And Revert

Candidate correctness gates before rejection:

```text
rch exec -- cargo test -j 1 -p frankenlibc-abi --test conformance_diff_clock -- --nocapture --test-threads=1
```

Result: 6 passed, 0 failed; reported 4 clock-family functions and 0 divergences
vs glibc.

```text
rch exec -- cargo test -j 1 -p frankenlibc-abi --test time_abi_test vdso -- --nocapture --test-threads=1
```

Result: 10 passed, 0 failed.

Post-reject action: manually reverted the timing source hunk. `time_abi.rs` has
zero diff after revert and `rustfmt --edition 2024 --check
crates/frankenlibc-abi/src/time_abi.rs` passes.

Post-revert focused conformance:

```text
AGENT_NAME=cod-a BR_AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a rch exec -- cargo test -j 1 -p frankenlibc-abi --test conformance_diff_clock -- --nocapture --test-threads=1
```

Result on `vmi1152480`: 6 passed, 0 failed; 4 clock-family functions and 0
divergences vs glibc.

## Routing

Do not retry this micro-family:

- null-only `time()` validation skip;
- direct stack-output vDSO helper before the regular `clock_gettime` checks;
- vDSO pointer-cache/TLS-hit-counter variants already rejected in prior ledger
  rows.

The next timing route needs a deployed LD_PRELOAD/runtime-ready harness or a
deeper runtime-ready/vDSO gate redesign. Criterion-only wrapper reshuffling is
not a credible enough path to dominate glibc here.
