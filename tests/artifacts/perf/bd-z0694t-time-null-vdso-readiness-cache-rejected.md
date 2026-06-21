# bd-z0694t: `time(NULL)` cached vDSO readiness gate rejected

Date: 2026-06-21
Agent: cod-a / BlackThrush
Worker: rch `hz1`
Target dir requested: `/data/projects/.rch-targets/frankenlibc-cod-a`
Remote worker target rewrite: `/data/projects/frankenlibc/.rch-target-hz1-pool-2740363b0b76e0a08f9b35b4f209a994`

## Candidate

Cache a one-way `vDSO resolution is currently allowed` boolean for the null
`time(NULL)` hot path after the first successful runtime-ready and
pipeline-inactive check. This did not cache vDSO function pointers and did not
change `clock_gettime` or non-null `time(tloc)`.

The candidate was structurally separate from the previously rejected vDSO
pointer-cache family, but same-worker measurement rejected it.

## Baseline

Command:

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2
```

Baseline was current head before the candidate on worker `hz1`.

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 4.68 ns | 8.65 ns | 0.54x | WIN |
| `strtol_dec_long` | 8.95 ns | 18.51 ns | 0.48x | WIN |
| `strtol_hex` | 12.65 ns | 18.51 ns | 0.68x | WIN |
| `atoi_short` | 4.33 ns | 9.88 ns | 0.44x | WIN |
| `atoi_long` | 11.73 ns | 19.44 ns | 0.60x | WIN |
| `atol_short` | 4.02 ns | 8.65 ns | 0.47x | WIN |
| `atol_long` | 11.62 ns | 18.51 ns | 0.63x | WIN |
| `atoll_short` | 3.72 ns | 8.65 ns | 0.43x | WIN |
| `atoll_long` | 11.32 ns | 18.51 ns | 0.61x | WIN |
| `strtod_int` | 13.61 ns | 34.88 ns | 0.39x | WIN |
| `strtod_simple` | 29.95 ns | 66.17 ns | 0.45x | WIN |
| `strtod_sci` | 22.24 ns | 45.07 ns | 0.49x | WIN |
| `rand` | 3.10 ns | 6.38 ns | 0.49x | WIN |
| `getenv_hit` | 11.43 ns | 18.86 ns | 0.61x | WIN |
| `getenv_miss` | 20.70 ns | 27.40 ns | 0.76x | WIN |
| `clock_gettime` | 31.77 ns | 30.54 ns | 1.04x | NEUTRAL |
| `time` | 4.94 ns | 2.79 ns | 1.78x | LOSS |
| `pthread_self` | 1.86 ns | 2.47 ns | 0.75x | WIN |

Baseline scorecard: 16 WIN / 1 NEUTRAL / 1 LOSS.

## Candidate Result

Same command, same worker `hz1`, candidate source applied.

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 5.42 ns | 10.81 ns | 0.50x | WIN |
| `strtol_dec_long` | 11.19 ns | 23.14 ns | 0.48x | WIN |
| `strtol_hex` | 12.96 ns | 18.51 ns | 0.70x | WIN |
| `atoi_short` | 4.02 ns | 10.19 ns | 0.39x | WIN |
| `atoi_long` | 11.49 ns | 19.74 ns | 0.58x | WIN |
| `atol_short` | 3.72 ns | 8.65 ns | 0.43x | WIN |
| `atol_long` | 11.32 ns | 18.51 ns | 0.61x | WIN |
| `atoll_short` | 3.72 ns | 8.95 ns | 0.42x | WIN |
| `atoll_long` | 11.32 ns | 18.82 ns | 0.60x | WIN |
| `strtod_int` | 13.58 ns | 34.88 ns | 0.39x | WIN |
| `strtod_simple` | 29.95 ns | 66.17 ns | 0.45x | WIN |
| `strtod_sci` | 22.24 ns | 44.79 ns | 0.50x | WIN |
| `rand` | 2.79 ns | 6.68 ns | 0.42x | WIN |
| `getenv_hit` | 11.43 ns | 18.94 ns | 0.60x | WIN |
| `getenv_miss` | 21.01 ns | 28.71 ns | 0.73x | WIN |
| `clock_gettime` | 31.77 ns | 30.54 ns | 1.04x | NEUTRAL |
| `time` | 5.56 ns | 2.79 ns | 2.00x | LOSS |
| `pthread_self` | 1.86 ns | 2.47 ns | 0.75x | WIN |

Candidate scorecard: 16 WIN / 1 NEUTRAL / 1 LOSS.

Target result: `time(NULL)` worsened from 4.94 ns to 5.56 ns, and the glibc
ratio worsened from 1.78x to 2.00x. The full scorecard shape did not improve.

## Decision

Rejected and source reverted. `crates/frankenlibc-abi/src/time_abi.rs` was
restored to zero local diff after the measurement.

Do not retry this boolean readiness-cache micro-family. The residual `time`
loss should be routed to a deployed LD_PRELOAD/vvar-level proof or a deeper
runtime-ready/vDSO gate redesign with a tighter focused harness.

## Validation

Candidate focused test before rejection:

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- cargo test -j 1 -p frankenlibc-abi --test time_abi_test vdso -- --nocapture --test-threads=1
```

Result: 10 passed, 0 failed, 80 filtered out.

Post-revert conformance:

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- cargo test -j 1 -p frankenlibc-abi --test conformance_diff_clock -- --nocapture --test-threads=1
```

Result: 6 passed, 0 failed; coverage report: 4 functions, 0 divergences.

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- cargo test -j 1 -p frankenlibc-abi --test conformance_diff_time -- --nocapture --test-threads=1
```

Result: 12 passed, 0 failed; coverage report: 6 functions, 326 calls, 0 divergences.
