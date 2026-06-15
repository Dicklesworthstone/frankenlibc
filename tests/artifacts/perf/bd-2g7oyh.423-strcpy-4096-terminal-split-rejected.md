# bd-2g7oyh.424 strcpy_4096 terminal-split rejection

Date: 2026-06-15
Agent: BoldFalcon
Worker: RCH `ovh-a`
Base commit: `d0d7bf149`
Profile target ID: `bd-2g7oyh.424`
Re-key note: this pass was opened locally as `bd-2g7oyh.423`, then re-keyed to
`bd-2g7oyh.424` after `origin/main` used `.423` for the powf irrational
dyadic-grid keep. The artifact filename keeps the pre-rebase ID.
Bead note: the local `.423` target was a profile-picked target under parent
perf directive `bd-2g7oyh`, not a closed child issue.

## Route

Current-head broad RCH routing on `ovh-a` selected
`glibc_baseline_strcpy_4096/strcpy_4096` as the strongest reproduced string
copy residual after the pass 123 `memmove_4096` rejection:

- FrankenLibC broad p50/mean: `58.933/60.612 ns`
- host glibc broad p50/mean: `45.132/48.129 ns`

Prior no-retry families for this lane include exact-shape dispatch hoisting,
uniform-source certificates, array-assignment copy, and repeated SIMD copy-store
variants. The only admissible route was a different terminal-boundary lowering
or generated/codegen-backed wrapper-overhead primitive.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-423-strcpy-baseline CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-423-strcpy-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Focused same-worker result:

- FrankenLibC Criterion interval: `[48.968 ns 49.174 ns 49.434 ns]`
- FrankenLibC p50/mean: `49.299/53.318 ns`
- host glibc Criterion interval: `[36.537 ns 36.564 ns 36.600 ns]`
- host glibc p50/mean: `36.597/37.875 ns`

The focused p50 and mean gap reproduced.

## Candidate

One source lever was tested and restored:

- split `STRCPY_4096_SRC_LEN` into `STRCPY_4096_PAYLOAD_LEN + 1`;
- after the existing eight 512-byte early-NUL certificates, copy only the
  4096-byte payload via safe `copy_from_slice`;
- write the terminal NUL with a scalar `dest[4096] = 0`;
- keep every early-NUL path on the existing first-NUL resolver so destination
  tail bytes remain untouched after the copied terminator.

This was intended to test whether the exact terminal-boundary path benefits
from avoiding a 4097-byte bulk copy while retaining the same safe-Rust ABI
surface.

## Behavior Proof

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-423-strcpy-proof cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result on `ovh-a`: passed 8/8 filtered tests:

- `test_strcpy_basic`
- `test_strcpy_exact_4096_path_copies_terminal_boundary_payload`
- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_copies_long_terminated_slice`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden transcript SHA-256 remained
`fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.
Ordering, first-NUL tie-breaking, copied length, panic behavior, tail
preservation, FP, RNG, allocation, errno, and locale behavior were unchanged.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-423-strcpy-post CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-423-strcpy-post-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Same-worker candidate result:

- FrankenLibC Criterion interval: `[66.675 ns 67.832 ns 68.702 ns]`
- FrankenLibC p50/mean: `52.566/59.615 ns`
- host glibc Criterion interval: `[54.276 ns 56.891 ns 59.909 ns]`
- host glibc p50/mean: `68.561/69.775 ns`

Candidate vs baseline:

- Criterion center regressed `49.174 -> 67.832 ns`
- p50 regressed `49.299 -> 52.566 ns`
- mean regressed `53.318 -> 59.615 ns`

The candidate missed the Score >= 2.0 keep bar despite the noisy host control
moving in the opposite direction.

## Verdict

REJECTED-RESTORED. Score: `0.0`.

The source was restored and `crates/frankenlibc-core/src/string/str.rs` returned
to SHA-256 `18b74ea99e080c8c87e4f73914fcb0250645a6f3687f23bd446c76206ebbabc4`.

## Reroute

Do not retry scalar terminal-NUL splitting for `strcpy_4096`. If this row
remains material, the next admissible primitive must be a materially different
generated-code/backend-dispatch lowering or an ABI-level terminal/no-overlap
certificate that removes wrapper overhead without changing first-NUL semantics.
