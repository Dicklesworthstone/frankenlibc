# bd-2g7oyh.436 - strcpy_4096 SWAR NUL-certificate rejection

Date: 2026-06-16
Agent: BoldFalcon
Worker: vmi1227854
Target: `glibc_baseline_strcpy_4096`
Verdict: REJECTED-RESTORED
Score: 0.0

## Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass139-strcpy4096-baseline-target-20260616T0310 CRITERION_HOME=/data/tmp/frankenlibc-pass139-strcpy4096-baseline-criterion-20260616T0310 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC Criterion: `[52.826 ns 53.515 ns 54.249 ns]`
- FrankenLibC profile line: p50 `54.033 ns/op`, mean `61.965 ns/op`
- Host Criterion: `[35.172 ns 36.095 ns 37.084 ns]`
- Host profile line: p50 `35.208 ns/op`, mean `36.361 ns/op`

The focused same-worker gap reproduced a material terminal-copy residual.

## Candidate

One lever only: replace the exact 4096-byte `strcpy` terminal path's eight 512-byte SIMD NUL probes with safe native-word SWAR NUL probes.

The candidate changed only the early-NUL certificate used by `strcpy_4096_terminated`. Early-NUL cases still returned through `copy_strcpy_prefix_terminal_from`; no-early-NUL terminal-boundary cases still copied the same `4097` bytes; no-NUL/panic behavior and destination suffix preservation stayed under the existing tests.

## Behavior Proof

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUST_TEST_THREADS rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass139-strcpy4096-proof-target-20260616T0316 cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result: passed 7/7 focused tests while the candidate was present.

Covered tests included:

- `test_strcpy_basic`
- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_copies_long_terminated_slice`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden SHA:

```text
test_strcpy_golden_transcript_sha256 = fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401
```

Isomorphism notes: the candidate's SWAR probe answered only whether a 512-byte block contained any NUL. It did not choose the first NUL position, copy bytes, modify return counts, touch ordering/tie-breaking, or introduce FP/RNG/allocation behavior. Any positive certificate fell through to the existing ordered prefix resolver, and the final committed source restores the pre-candidate implementation.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass139-strcpy4096-post-target-20260616T0318 CRITERION_HOME=/data/tmp/frankenlibc-pass139-strcpy4096-post-criterion-20260616T0318 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC Criterion: `[216.91 ns 223.20 ns 229.77 ns]`
- FrankenLibC profile line: p50 `225.583 ns/op`, mean `226.187 ns/op`
- Host Criterion: `[31.141 ns 31.773 ns 32.466 ns]`
- Host profile line: p50 `33.312 ns/op`, mean `34.044 ns/op`

Same-worker self delta:

- Criterion center: `53.515 ns -> 223.20 ns`
- p50: `54.033 ns -> 225.583 ns`
- mean: `61.965 ns -> 226.187 ns`

## Restoration

The candidate source was manually restored after rejection.

```text
git diff -- crates/frankenlibc-core/src/string/str.rs
# empty

sha256sum crates/frankenlibc-core/src/string/str.rs
4cbad75cfcf39690e96b2f16fa4aa52cc9046ecbd3ac0ed9c99b77c7fdb95926  crates/frankenlibc-core/src/string/str.rs
```

## No-retry Route

Do not retry word/SWAR NUL certificates, global NUL certificates, prefix-helper attributes, terminal splitting, array-copy lowering, or public-wrapper inlining for `strcpy_4096`.

Only return to this target with a fresh focused same-worker gate and a materially different primitive: generated/backend-dispatch terminal/no-overlap copy lowering, ABI-level classification, or another proof-carrying codegen route.
