# bd-2g7oyh.443 - pass161 powf_irrational focused gate no-code

Date: 2026-06-16
Agent: BoldFalcon
Worker: vmi1227854
Head: 7ae26faa8

Note: this closeout was created locally as `bd-2g7oyh.442` / pass160, then re-keyed to `bd-2g7oyh.443` / pass161 during rebase because `origin/main` used `.442` for the peer memcmp256 rejection.

## Command

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 RCH_BUILD_SLOTS=1 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass160-powf-irrational-target-vmi1227854 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass160-powf-irrational-criterion-vmi1227854 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/powf_irrational --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3 \
  2>&1 | tee /data/tmp/frankenlibc-pass160-powf-irrational-vmi1227854.log
```

RCH completed successfully:

```text
[RCH] remote vmi1227854 (267.3s)
```

Log SHA-256:

```text
98e06bb19706c7f7c438004a9093c218f520fcf4ef9bb87405313a886189006e  /data/tmp/frankenlibc-pass160-powf-irrational-vmi1227854.log
```

## Focused result

Rows are nanoseconds per op.

| Implementation | Criterion interval | p50 | p95 | p99 | Mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| frankenlibc_core | [413.52, 424.52, 434.90] | 405.220 | 488.940 | 512.765 | 411.767 |
| frankenlibc_old_libm | [2141.9, 2200.8, 2257.5] | 2107.698 | 2526.174 | 2730.312 | 2160.551 |
| host_glibc | [406.33, 412.75, 418.66] | 412.806 | 468.632 | 522.617 | 416.578 |

Focused gate result: the pass159 broad residual collapsed and reversed. FrankenLibC is faster than host glibc by `1.019x` p50 and `1.012x` mean on the same worker.

## Behavior proof

No source changed. Behavior is unchanged by identity:

- `powf` special-case ordering is unchanged.
- signed zero, NaN, Inf, negative-base integer-exponent handling, rounding envelope, errno/fenv behavior, allocation behavior, locale behavior, and RNG state are untouched.
- `crates/frankenlibc-core/src/math/float32.rs` SHA-256 remains `63175ec480d85c563d373be973eb85ce33ff68ef106a7fa239aef6a0217751aa`.
- Golden outputs are unchanged because no implementation code or fixtures changed.

## Verdict

Verdict: NO-CODE ROUTED OUT. Score: 0.0.

No `powf_irrational` source lever is profile-backed on this focused same-worker gate. Do not retry surface `powf` coefficient retunes or polynomial scheduling without a fresh material focused gap and a generated/proof-carrying underlying primitive.

Next route: focused `memcmp_4096` gate from the pass159 broad profile. The `strcpy_4096` row is intentionally skipped for now because pass157 already closed it as a recent no-code/codegen-blocked no-repeat lane.
