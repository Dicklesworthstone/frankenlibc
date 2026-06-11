# bd-2g7oyh.332 - memmove_4096 focused copy-codegen gate

Date: 2026-06-11
Status: NO-CODE REJECTED
Score: 0.0

## Target

Fresh broad RCH profile selected `memmove_4096` as the best clean unowned
copy target after excluding peer-owned `pow`/`exp.rs` work (`bd-2g7oyh.125`)
and peer-owned `strncmp`/`str.rs` work (`bd-2g7oyh.65`).

- Broad RCH build: `29879662679165885`
- Worker: `vmi1227854`
- Project: `frankenlibc-pass59-20260611T0410-9459d06c`
- Command: `cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench`
- Broad row: FrankenLibC p50 `44.720 ns`, mean `47.749 ns`; host glibc p50 `36.799 ns`, mean `42.710 ns`

Prior no-ship families for this surface include safe portable-SIMD copy panels
and page/copy-shape `memmove` attempts. Any source edit therefore required a
material focused same-worker remote reproduction and a structurally different
safe-Rust codegen/alignment/no-overlap primitive.

## Focused Gate

Attempt 1 used the focused benchmark filter:

`RCH_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --sample-size 30 --warm-up-time 1 --measurement-time 2`

The emitted benchmark row was:

- FrankenLibC p50 `41.436 ns`, mean `44.889 ns`
- host glibc p50 `37.070 ns`, mean `42.315 ns`

This attempt did not appear in RCH recent-build telemetry as a `memmove_4096`
remote build, so it is not counted as same-worker proof.

Attempt 2 used explicit `rch exec`:

`RCH_WORKER=vmi1227854 RCH_VISIBILITY=summary rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --sample-size 30 --warm-up-time 1 --measurement-time 2`

RCH reported local fallback:

`[RCH] local (no admissible workers: critical_pressure=1,insufficient_slots=1)`

The local fallback row was:

- FrankenLibC p50 `42.382 ns`, mean `44.875 ns`
- host glibc p50 `35.922 ns`, mean `37.473 ns`

This is routing context only and is not counted as keep/reject remote proof.

The only subsequent RCH recent-build entry for the same project was build
`29879662679165895`, but its command was recorded as
`glibc_baseline_math/asinh`, not `glibc_baseline_memmove_4096`.

## Isomorphism

No source file was edited.

- Ordering: unchanged by construction.
- Tie-breaking: unchanged by construction.
- Floating point and RNG: not involved.
- Overlap semantics: unchanged by construction.
- `crates/frankenlibc-core/src/string/mem.rs` sha256: `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- `tests/conformance/fixtures/string_memory_full.json` sha256: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/memcpy_strict.json` sha256: `6bdd6fb00bff508d07eb985bdc7c258a1a10f8ea96de72cf7e392483e886c233`

## Verdict

Rejected before source edit. The broad profile justified opening the bead, but
the focused gate did not produce a confirmed remote same-worker `memmove_4096`
run. Editing on local fallback evidence would violate the profile-backed target
rule, especially on a surface with recent rejected copy-panel and page/copy-shape
families.

Next route: reprofile when a clean RCH worker is available and pick a different
reproduced unowned residual. Only return to `memmove_4096` with a material
focused remote gap and a codegen-backed safe-Rust primitive that is structurally
different from the prior copy-panel/page families.
