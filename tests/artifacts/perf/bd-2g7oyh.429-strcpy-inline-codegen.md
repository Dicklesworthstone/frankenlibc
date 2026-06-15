# bd-2g7oyh.429 - strcpy_4096 public inline codegen keep

Date: 2026-06-15
Agent: BoldFalcon
Target: `glibc_baseline_strcpy_4096`
Worker: `vmi1227854`

## Profile-backed target

Pass 130 broad routing on pushed head `a837be086` showed `strcpy_4096` as the strongest fresh string residual that survived the current no-retry filters:

- FrankenLibC p50/mean: `52.344/53.923 ns`
- Host p50/mean: `46.488/49.194 ns`

Focused same-worker baseline reproduced a material gap:

- FrankenLibC Criterion: `[60.346 ns 60.773 ns 61.217 ns]`
- FrankenLibC p50/mean: `60.763/62.426 ns`
- Host Criterion: `[43.242 ns 43.590 ns 43.939 ns]`
- Host p50/mean: `43.777/43.878 ns`

Prior exhausted `strcpy_4096` families: final-block rank-select, per-certified-block `copy_from_slice`, scan-then-bulk-copy, uniform-run certificate, dispatch hoist, array-copy lowering, and terminal-NUL split. The previous keep was the terminal-boundary bulk-copy primitive. This pass uses a smaller but different codegen lever: expose the already-specialized terminal-boundary path to callers through an always-inlined public wrapper, rather than reshaping the copy algorithm again.

## One lever

Add `#[inline(always)]` to `frankenlibc_core::string::strcpy`.

The implementation body and all branch predicates are unchanged. Inlining allows the benchmark caller to specialize away one public wrapper boundary around the exact-size terminal-boundary certificate.

## Behavior proof

RCH command:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result: passed 7/7 filtered tests:

- `test_strcpy_basic`
- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_copies_long_terminated_slice`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_strcpy_stops_at_first_nul_without_touching_trailing_dest`

Golden transcript SHA: `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.

Preserved by construction and tests: first-NUL ordering, destination tail preservation after early NUL, copied-length return, no-NUL panic behavior, exact 4096 terminal-boundary behavior, floating-point behavior, RNG behavior, allocation behavior, errno behavior, and locale behavior.

Fixture/source SHAs:

- `crates/frankenlibc-core/src/string/str.rs`: `4cbad75cfcf39690e96b2f16fa4aa52cc9046ecbd3ac0ed9c99b77c7fdb95926`
- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`

## Post-benchmark

RCH command:

```bash
RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Post result:

- FrankenLibC Criterion: `[50.014 ns 50.561 ns 51.102 ns]`
- FrankenLibC p50/mean: `49.015/49.895 ns`
- Host Criterion: `[43.188 ns 43.926 ns 44.645 ns]`
- Host p50/mean: `42.249/44.958 ns`

Same-worker self delta:

- p50: `60.763 -> 49.015 ns`, `19.3%` lower
- mean: `62.426 -> 49.895 ns`, `20.1%` lower
- Criterion center: `60.773 -> 50.561 ns`, `16.8%` lower

The row still trails host, so future work should not return to scalar terminal-NUL splitting or copy reshaping. If `strcpy_4096` remains material, the next route is generated/backend-dispatch or ABI/codegen specialization with a new focused gate.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed
- RCH `cargo check -j 1 -p frankenlibc-core --all-targets`: passed
- RCH strict `cargo clippy -j 1 -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated pre-existing `crates/frankenlibc-core/src/resolv/mod.rs:316` `clippy::explicit_counter_loop`
- RCH allowlisted `cargo clippy -j 1 -p frankenlibc-core --all-targets -- -D warnings -A clippy::explicit_counter_loop`: passed

## Verdict

KEPT.

Score: `(Impact 3.5 x Confidence 4.5) / Effort 1.0 = 15.8`.
