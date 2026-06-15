# bd-2g7oyh.412 - strcpy_4096 array-copy codegen rejection

## Target

- Bead: `bd-2g7oyh.412`
- Profile row: `glibc_baseline_strcpy_4096`
- Worker: `ovh-a`
- Source surface: `crates/frankenlibc-core/src/string/str.rs`
- Source baseline: `0c5ce808e61e94ab3f05c6f4b091f88d3ad3021a`

The pass was selected from the current-head broad RCH routing slice after
`bd-2g7oyh.410` landed. `strcpy_4096` remained the strongest reproduced string
residual by p50 and mean. Prior no-retry families include final-block
rank-select, certified-block `copy_from_slice`, whole-string scan-then-bulk-copy,
uniform-run certificates, generic fused scan/store retunes, and the already-kept
exact-size unrolled path.

## Focused Baseline

Command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKERS=ovh-a RCH_WORKER=ovh-a \
  RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
  RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass113-strcpy-baseline-target-20260615T0430 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass113-strcpy-baseline-criterion-20260615T0430 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 60 --warm-up-time 1 \
  --measurement-time 3
```

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | `[51.360 ns 53.642 ns 56.508 ns]` | `60.827` | `69.735` | `92.625` | `175.500` |
| host glibc | `[37.814 ns 37.932 ns 38.093 ns]` | `38.001` | `39.366` | `40.716` | `50.000` |

Focused residual reproduced by p50 (`1.60x`) and mean (`1.77x`).

## Candidate

One source lever in the exact `4096 + NUL` specialization only:

- Add a no-early-NUL certificate over the 4096-byte payload using the existing
  eight `block_has_nul_512` folded NUL checks.
- If the payload is NUL-free, convert the already-bounded prefixes to
  `[u8; 4096]` references and assign `*dst = *src`, then write the known final
  NUL.
- If any interior NUL exists, fall through to the existing ordered exact path.

This intentionally tested a generated store strategy distinct from the prior
safe-slice `copy_from_slice` and per-block SIMD-store paths. Early-NUL behavior
remained on the old path, preserving the no-overwrite contract for destination
bytes after the first terminator.

## Behavior Proof

Command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKERS=ovh-a RCH_WORKER=ovh-a \
  RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
  RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUST_TEST_THREADS \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-412-strcpy-proof-target-20260615T0434 \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result on `ovh-a`: passed `7/7` filtered tests, including:

- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden transcript SHA-256 stayed:

```text
fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401
```

Isomorphism:

- First-NUL ordering unchanged: the candidate only took the array-copy branch
  after every 512-byte payload certificate proved there was no interior NUL.
- Early-NUL exact-size sources fell through to the existing left-to-right
  resolver; bytes after the copied terminator stayed untouched.
- No changes touched ordering/tie-breaking, floating point, RNG, allocation, or
  errno behavior.

Local touched-file validation:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
```

Both passed.

## Post Benchmark

Command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKERS=ovh-a RCH_WORKER=ovh-a \
  RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
  RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-412-strcpy-post-target-20260615T0436 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-412-strcpy-post-criterion-20260615T0436 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 60 --warm-up-time 1 \
  --measurement-time 3
```

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | `[65.112 ns 68.622 ns 72.252 ns]` | `72.674` | `67.925` | `77.328` | `85.634` |
| host glibc | `[37.904 ns 38.070 ns 38.287 ns]` | `37.930` | `39.313` | `41.375` | `55.000` |

Same-worker FrankenLibC delta:

- p50 regressed `60.827 -> 72.674 ns` (`19.5%` slower).
- mean improved `69.735 -> 67.925 ns` (`2.6%` faster), not enough to offset
  the p50 regression.
- vs-host p50 gap widened from `1.60x` to `1.92x`.

## Restore

The source lever was restored.

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed
- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs`: passed
- Restored `str.rs` SHA-256:
  `0305360b0772daceb7c7920e2e025204be11d92f4737a2d9d15fc1933f4929e8`

## Decision

REJECTED-RESTORED, Score `0.0`.

Do not retry this no-early-NUL array-copy codegen path for `strcpy_4096`. The
next route is a fresh focused gate for another profile-backed residual rather
than another copy-shape micro-lever on this row.
