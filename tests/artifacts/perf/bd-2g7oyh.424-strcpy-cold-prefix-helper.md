# bd-2g7oyh.424 - strcpy_4096 cold prefix-helper rejection

Date: 2026-06-16
Agent: BoldFalcon
Target: `glibc_baseline_strcpy_4096`
Worker: `vmi1227854`
Base commit: `d743e72f2`

## Profile-backed target

Current-head broad RCH routing on `vmi1227854` selected `strcpy_4096` as the
strongest fresh string residual after the `bd-2g7oyh.431` `memchr_absent`
exact-dispatch rejection:

- FrankenLibC broad p50/mean: `49.657/49.985 ns`
- host glibc broad p50/mean: `29.955/30.690 ns`

The initial focused same-worker baseline before source edit reproduced the gap:

- FrankenLibC Criterion interval: `[54.478 ns 56.346 ns 58.503 ns]`
- FrankenLibC p50/mean: `55.892/76.916 ns`
- host glibc Criterion interval: `[37.451 ns 38.597 ns 39.864 ns]`
- host glibc p50/mean: `35.997/37.856 ns`

Prior exhausted `strcpy_4096` families include final-block rank-select,
per-certified-block `copy_from_slice`, scan-then-bulk-copy, uniform-run
certificates, dispatch hoist, array-copy lowering, scalar terminal split,
terminal-boundary bulk-copy, and public wrapper inlining. This pass uses a
different codegen/layout lever: keep the rare early-NUL prefix resolver out of
the hot exact terminal-boundary path.

After the initial proof and post-benchmark, `origin/main` advanced before push.
The commit was rebased onto `7a6152b77`, and the same focused gate was rerun
against the actual rebased parent and candidate. The rebased gate rejected the
lever, so source was restored before publication.

## One lever tested and restored

The tested source lever marked `copy_strcpy_prefix_terminal_from` as cold and
non-inlined:

```rust
#[cold]
#[inline(never)]
fn copy_strcpy_prefix_terminal_from(...)
```

The helper is used only after a 512-byte certificate has detected an early NUL.
The no-early-NUL exact 4096-byte path performs the same eight certificate
checks and the same terminal-boundary safe slice copy.

The candidate changed no branch predicate, byte-copy order, first-NUL
resolution rule, panic rule, or destination-tail rule. After the rebased
benchmark rejected the lever, the source was restored to the parent shape.

## Behavior proof

RCH command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-424-strcpy-proof-20260616T0203-target cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result: passed 7/7 filtered tests:

- `test_strcpy_basic`
- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_copies_long_terminated_slice`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden transcript SHA-256 remained
`fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.

Isomorphism proof:

- Ordering and tie-breaking: unchanged; the first NUL is still located by the
  same scalar resolver after the same early-NUL certificate.
- Tail behavior: unchanged; early-NUL tests prove bytes after the copied
  terminator remain untouched.
- Exact 4096 terminal-boundary behavior: unchanged; the no-early-NUL path uses
  the same `dest[..4097].copy_from_slice(src)` operation.
- Panic behavior: unchanged; the no-NUL synthetic-room panic test still fires.
- Floating-point, RNG, allocation, errno, and locale behavior: untouched by this
  string-helper codegen attribute change.

Fixture/source SHAs:

- `crates/frankenlibc-core/src/string/str.rs` after restore: `4cbad75cfcf39690e96b2f16fa4aa52cc9046ecbd3ac0ed9c99b77c7fdb95926`
- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`

## Initial post-benchmark

RCH command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-424-strcpy-post-20260616T0208-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-424-strcpy-post-20260616T0208-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Post result:

- FrankenLibC Criterion interval: `[49.688 ns 50.555 ns 51.616 ns]`
- FrankenLibC p50/mean: `51.412/55.301 ns`
- host glibc Criterion interval: `[42.769 ns 43.784 ns 44.848 ns]`
- host glibc p50/mean: `45.377/49.502 ns`

Same-worker self delta:

- Criterion center: `56.346 -> 50.555 ns`, `10.3%` lower
- p50: `55.892 -> 51.412 ns`, `8.0%` lower
- mean: `76.916 -> 55.301 ns`, `28.1%` lower

This initial result was not published because `origin/main` advanced before
push.

## Rebased parent gate

Baseline command on parent `origin/main` `7a6152b77`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-424-rebase-baseline-20260616T0225-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-424-rebase-baseline-20260616T0225-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Parent baseline result:

- FrankenLibC Criterion interval: `[49.828 ns 50.661 ns 51.522 ns]`
- FrankenLibC p50/mean: `48.965/50.152 ns`
- host glibc Criterion interval: `[33.335 ns 34.086 ns 34.849 ns]`
- host glibc p50/mean: `33.648/36.488 ns`

Rebased candidate post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-424-rebase-post-20260616T0228-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-424-rebase-post-20260616T0228-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Rebased candidate result:

- FrankenLibC Criterion interval: `[50.098 ns 50.935 ns 51.757 ns]`
- FrankenLibC p50/mean: `49.634/51.725 ns`
- host glibc Criterion interval: `[44.044 ns 44.819 ns 45.544 ns]`
- host glibc p50/mean: `45.243/46.416 ns`

Same-worker candidate delta against the rebased parent:

- Criterion center: `50.661 -> 50.935 ns`, `0.5%` slower
- p50: `48.965 -> 49.634 ns`, `1.4%` slower
- mean: `50.152 -> 51.725 ns`, `3.1%` slower

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed
- RCH `cargo check -j 1 -p frankenlibc-core --lib`: passed while the candidate was present
- Source was restored after rejection; final source diff against parent is empty

The benchmark build still reports the pre-existing unrelated
`crates/frankenlibc-core/src/string/regex.rs:1536` `prefilter_skips`
dead-code warning; this pass does not touch `regex.rs`.

## Verdict

REJECTED-RESTORED.

Score: `0.0`.

Do not retry prefix-helper attribute reshaping. If `strcpy_4096` remains
material, the next admissible route must be a generated/backend-dispatch or
ABI/codegen primitive that changes lowering more deeply, with a fresh focused
gate on the actual parent before any source edit.
