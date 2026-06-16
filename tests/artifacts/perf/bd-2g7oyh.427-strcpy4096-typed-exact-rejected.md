# bd-2g7oyh.427 - strcpy_4096 typed exact-source/destination rejection

Target: `glibc_baseline_strcpy_4096`

## Routing Evidence

Pass 141 broad RCH profile on `vmi1227854` after `e7ec99f9a` selected
`strcpy_4096` as the largest remaining string residual:

- FrankenLibC Criterion `[65.995 ns 67.196 ns 68.448 ns]`, p50/mean
  `66.951/68.569 ns`
- host glibc Criterion `[39.625 ns 40.383 ns 41.096 ns]`, p50/mean
  `42.167/44.624 ns`

Prior no-retry families: word/SWAR NUL certificates, global NUL certificates,
prefix-helper attributes, terminal splitting, array-copy lowering,
dispatch-hoisting, and public-wrapper inlining.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-427-strcpy-baseline-target-20260616T0342 CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-427-strcpy-baseline-criterion-20260616T0342 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion `[56.617 ns 60.313 ns 66.065 ns]`, p50/mean
  `52.958/59.362 ns`
- host glibc Criterion `[39.292 ns 40.476 ns 41.727 ns]`, p50/mean
  `38.209/39.258 ns`

## Candidate

One source lever: type the exact `4096 + NUL` specialization through
`[u8; 4097]` source/destination references, then run the existing
`strcpy_4096_terminated` scan/copy algorithm unchanged.

This targeted generated bounds/copy lowering only. It did not change the
512-byte NUL certificate, first-NUL resolution order, terminal-boundary
bulk-copy rule, destination-tail preservation, panic behavior, FP behavior,
RNG behavior, allocation behavior, errno behavior, or locale behavior.

## Behavior Proof

Local touched-file checks while the candidate was present:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
```

Both passed.

Fixture SHAs:

```text
27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89  tests/conformance/fixtures/string_ops.json
b5509edb2fc90403daf10fbef4944369aff58e26569d6a03b77b6317c646667f  tests/conformance/fixtures/strlen_strict.json
```

RCH proof command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUST_TEST_THREADS rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-427-strcpy-proof-target-20260616T0348 cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result on `vmi1227854`: passed 7/7 filtered tests, including:

- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden transcript SHA asserted by the test remained:

```text
fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401
```

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-427-strcpy-post-target-20260616T0350 CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-427-strcpy-post-criterion-20260616T0350 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Result:

- candidate FrankenLibC Criterion `[52.649 ns 54.084 ns 55.606 ns]`,
  p50/mean `51.803/83.761 ns`
- host glibc Criterion `[30.851 ns 32.188 ns 33.750 ns]`, p50/mean
  `30.939/33.244 ns`

Same-worker candidate delta versus focused baseline:

- Criterion center improved `60.313 -> 54.084 ns`
- p50 barely improved `52.958 -> 51.803 ns`
- mean regressed `59.362 -> 83.761 ns`
- p95/p99 regressed to `100.000/204.957 ns`

## Verdict

REJECTED-RESTORED, Score `0.0`.

The candidate failed the keep gate because its small p50 improvement came with
large mean and tail regressions. Source was restored; `git diff --
crates/frankenlibc-core/src/string/str.rs` is empty.

Next route: do not retry typed exact-source/destination lowering for
`strcpy_4096`. Return only with a genuinely different generated/disassembly
primitive or ABI-level no-overlap/terminal certificate after a fresh focused
same-worker gate.
