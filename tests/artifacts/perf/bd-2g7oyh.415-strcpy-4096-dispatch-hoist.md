# bd-2g7oyh.416 - strcpy_4096 dispatch-hoist rejection

## Target

- Bead: `bd-2g7oyh.416`
- Profile row: `glibc_baseline_strcpy_4096`
- Worker: `ovh-a`
- Source surface: `crates/frankenlibc-core/src/string/str.rs`
- Source baseline: `79cae5f2830ea2ec860b1ed440e72bcbc81c0694`

Re-keyed from local `bd-2g7oyh.415` after `origin/main` used `.415` for a
`strlen_4096` rejection. The artifact filename retains the pre-rebase bead id.

Current-head broad routing after `bd-2g7oyh.414` left `strcpy_4096` as the
largest clean string residual: FrankenLibC p50/mean `57.187/56.898 ns` vs host
glibc p50/mean `38.944/40.796 ns`. Prior no-retry families include final-block
rank-select, per-certified-block `copy_from_slice` lowering, whole-string
scan-then-bulk-copy, uniform-run certificates, generic fused scan/store retunes,
the already-kept exact-size unrolled path, and exact no-early-NUL array-copy
codegen.

## Focused Baseline

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd415-strcpy-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-bd415-strcpy-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 \
  --measurement-time 3
```

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | `[45.723 ns 46.454 ns 47.209 ns]` | `48.555` | `48.838` | n/a | n/a |
| host glibc | `[37.624 ns 37.774 ns 37.944 ns]` | `37.740` | `40.039` | n/a | n/a |

Focused residual reproduced by p50 (`1.29x`) and mean (`1.22x`).

## Candidate

One source lever in `strcpy` dispatch only:

- Check `src.len() == 4097`, `dest.len() >= 4097`, and `src[4096] == 0`
  before the generic `src.last().copied() == Some(0) && dest.len() >= src.len()`
  branch.
- Route the exact profiled shape directly to `strcpy_4096_terminated`.
- Remove the duplicate exact-size check inside the generic branch.

This was a control-flow/codegen lever, not another copy-shape probe. It tried to
avoid the generic last-byte/destination-size guard on the profiled hot shape.
Every short, no-NUL, too-small-destination, early-NUL, and non-4097 source kept
the old resolver path.

## Behavior Proof

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  RUST_TEST_THREADS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd415-strcpy-proof-target \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture \
  --test-threads=1
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

- First-NUL ordering unchanged: exact-size sources still use
  `strcpy_4096_terminated`, which resolves the first NUL left-to-right inside
  the first positive 512-byte certificate.
- Early-NUL exact-size sources preserve destination bytes after the copied
  terminator.
- Too-small destination, no-NUL panic behavior, return counts, and copied bytes
  are unchanged.
- Floating-point, RNG, allocation, locale, and errno behavior are not involved.

Local touched-file validation:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
```

Both passed.

## Post Benchmark

Command:

```bash
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
  RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
  RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd415-strcpy-post-target \
  CRITERION_HOME=/data/tmp/frankenlibc-bd415-strcpy-post-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 \
  --measurement-time 3
```

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | `[51.769 ns 52.811 ns 53.823 ns]` | `52.031` | `53.363` | `57.395` | `63.795` |
| host glibc | `[47.914 ns 48.024 ns 48.135 ns]` | `48.103` | `49.235` | `49.500` | `70.000` |

Same-worker FrankenLibC delta:

- p50 regressed `48.555 -> 52.031 ns` (`7.2%` slower).
- mean regressed `48.838 -> 53.363 ns` (`9.3%` slower).
- Criterion center regressed `46.454 -> 52.811 ns` (`13.7%` slower).

The host row also drifted slower in the post run, but the self-regression is
enough to reject the lever without using host-relative scoring.

## Restore

The source lever was restored.

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed
- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs`: passed
- Restored `str.rs` SHA-256:
  `0305360b0772daceb7c7920e2e025204be11d92f4737a2d9d15fc1933f4929e8`

## Decision

REJECTED-RESTORED, Score `0.0`.

Do not retry exact-shape dispatch-hoisting for `strcpy_4096`. The current row
has now exhausted near-surface copy-shape and dispatch-shape families; continue
with a fresh profile-backed residual or a deeper generated-code string primitive
only if a new same-worker gate proves a material gap.
