# bd-2g7oyh.493 default hot-hit stat bypass reject

Date: 2026-06-19
Agent: BlackThrush / cod-b
Workspace: `/data/projects/frankenlibc`

## Target

Residual `getgrgid(0)` p50 gap after `bd-2g7oyh.492`.

Rejected candidates:

- Candidate A: for default `/etc/group`, skip the per-call stat/fingerprint
  probe when the same gid result is already materialized in TLS and no
  `FRANKENLIBC_GROUP_PATH` override changed.
- Candidate B: Candidate A plus a libc `getenv` probe for the common unset
  override path.

Neither source change was landed.

## Baseline

Command:

```bash
RCH_WORKER=hz2 RCH_PREFERRED_WORKER=hz2 RCH_WORKERS=hz2 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b-493-baseline \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b-493-baseline/criterion-bd-2g7oyh-493-baseline-hz2-20260619T0602 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Worker: `hz2`.

| Workload | FrankenLibC p50 | glibc p50 | Ratio | Verdict |
|---|---:|---:|---:|---|
| `getgrnam_root` | 9.522 us | 23.909 us | 0.398x | WIN |
| `getgrgid_0` | 15.068 us | 14.968 us | 1.007x | NEUTRAL |

## Candidate A

Command:

```bash
RCH_WORKER=hz2 RCH_PREFERRED_WORKER=hz2 RCH_WORKERS=hz2 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-493-default-hot-skipstat-hz2-20260619T0610 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Worker: `hz2`.

| Workload | FrankenLibC p50 | glibc p50 | Ratio | Verdict |
|---|---:|---:|---:|---|
| `getgrnam_root` | 9.798 us | 25.077 us | 0.391x | WIN guard |
| `getgrgid_0` | 10.056 us | 9.029 us | 1.114x | LOSS |

`getgrgid_0` target details: mean ratio `1.115x`, p95 ratio `1.111x`, p99 ratio
`1.115x`.

Action: rejected/not landed. FrankenLibC's absolute p50 improved versus the
clean `hz2` baseline, but same-run glibc was still faster and the target failed
the p50 win gate.

## Candidate B

Command:

```bash
RCH_WORKER=hz2 RCH_PREFERRED_WORKER=hz2 RCH_WORKERS=hz2 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BlackThrush FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  CRITERION_HOME=/data/projects/.rch-targets/frankenlibc-cod-b/criterion-bd-2g7oyh-493-getenv-hot-skipstat-hz2-20260619T0618 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- glibc_baseline_grp_lookup \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Worker actually selected by `rch`: `hz1`; absolute times are not compared to
the `hz2` baseline.

| Workload | FrankenLibC p50 | glibc p50 | Ratio | Verdict |
|---|---:|---:|---:|---|
| `getgrnam_root` | 16.181 us | 40.272 us | 0.402x | WIN guard |
| `getgrgid_0` | 16.152 us | 10.022 us | 1.612x | LOSS |

`getgrgid_0` target details: mean ratio `1.613x`, p95 ratio `1.422x`, p99 ratio
`1.379x`.

Action: rejected/not landed. The libc `getenv` probe did not make the
default-only stat bypass competitive.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/grp_abi.rs crates/frankenlibc-abi/tests/grp_abi_test.rs`:
  passed for both candidates in scratch.
- `cargo test -p frankenlibc-abi --test grp_abi_test getgrgid_hot_lookup_reuses_tls_result_and_invalidates_on_reload -- --nocapture`:
  passed for both candidates.
- The source candidates were kept out of `main`; no source revert was required
  in the main checkout.

## Retry Predicate

Do not retry default-source-only stat/env bypasses for `getgrgid(0)`.

Next route: a materially different NSS structure, such as a per-generation gid
index over the parsed group snapshot or a shared immutable metadata epoch that
removes lookup work without relying on default-path special casing.
