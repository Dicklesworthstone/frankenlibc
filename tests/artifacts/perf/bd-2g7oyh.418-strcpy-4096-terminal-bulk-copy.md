# bd-2g7oyh.420 - strcpy_4096 Terminal-boundary Bulk-copy Keep

Date: 2026-06-15
Agent: BoldFalcon
Worker: RCH `ovh-a`
Base commit: `99e286699`
Re-key note: this pass was opened locally as `bd-2g7oyh.418`, then re-keyed
to `bd-2g7oyh.420` after `origin/main` used `.418` for `printf_g_6` and
`.419` for `memset_4096`. The artifact filename keeps the pre-rebase ID.

## Route

Pass 119 broad RCH Criterion profile on `ovh-a` selected `glibc_baseline_strcpy_4096`
as the strongest fresh residual that was not a previously exhausted family:

- FrankenLibC broad p50/mean: `94.278/88.815 ns`
- host glibc broad p50/mean: `38.244/40.839 ns`

The lane was rechecked before editing because prior `strcpy_4096` exact-dispatch
and array-copy attempts had rejected.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-418-baseline-target-20260615T1903 CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-418-baseline-criterion-20260615T1903 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_strcpy_4096' --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion interval: `[64.204 ns 67.295 ns 70.685 ns]`
- FrankenLibC p50/mean: `76.703/86.104 ns`
- host glibc Criterion interval: `[50.299 ns 52.446 ns 54.845 ns]`
- host glibc p50/mean: `50.706/60.214 ns`

## One Lever

For the exact profiled shape (`4096` payload bytes plus the terminating NUL),
`strcpy_4096_terminated` now first certifies that none of the eight 512-byte
payload blocks contains an early NUL. If an early NUL is present, it copies only
the prefix through the first NUL and preserves destination tail bytes. If the
payload is NUL-free, it performs one safe bulk `copy_from_slice` over all
`4097` bytes.

This is a different lowering regime from the rejected exact-dispatch hoist and
array-assignment attempts: it avoids repeated SIMD `copy_to_slice` stores on the
common terminal-boundary case while keeping the existing first-NUL resolver for
tail-preserving cases.

## Behavior Proof

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-418-proof-lib-target-20260615T1910 cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture
```

RCH selected `ovh-a`. Result: passed 7/7 filtered tests.

Covered invariants:

- first-NUL ordering and copied byte count unchanged
- exact 4096 path preserves destination tail after early NUL
- long generic fused path still copies through the first NUL
- no-NUL too-small destination panic behavior unchanged
- golden transcript unchanged: `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`
- no FP, RNG, allocation, errno, locale, or tie-breaking surface is touched

The initial unscoped `cargo test -p frankenlibc-core strcpy` failed before
running these tests because unrelated integration test
`strftime_buffer_differential_probe.rs` does not compile against the current
`BrokenDownTime` fields. The scoped `--lib` proof above avoids that unrelated
test and directly proves the changed `strcpy` implementation.

## Validation Notes

- `cargo fmt --check --package frankenlibc-core` fails on broad pre-existing
  formatting drift in unrelated files.
- `rustfmt --check crates/frankenlibc-core/src/string/str.rs` still reports
  pre-existing formatting drift in the import order and `stpncpy`; it reports no
  diff in the new hunk.
- RCH compiles emitted the existing duplicate `#[inline]` warnings in math
  modules and the existing `regex.rs` dead-code warning; the new `strcpy` helper
  warning from the first draft was removed before scoring.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-418-post-target-20260615T1912 CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-418-post-criterion-20260615T1912 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_strcpy_4096' --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion interval: `[49.765 ns 49.874 ns 50.024 ns]`
- FrankenLibC p50/mean: `49.899/51.358 ns`
- host glibc Criterion interval: `[46.803 ns 46.903 ns 47.021 ns]`
- host glibc p50/mean: `46.871/48.507 ns`

Same-worker self improvement:

- p50: `76.703 -> 49.899 ns` (`1.54x`, `34.9%` lower)
- mean: `86.104 -> 51.358 ns` (`1.68x`, `40.4%` lower)
- Criterion center: `67.295 -> 49.874 ns` (`1.35x`, `25.9%` lower)

Remaining host gap on the same post run:

- p50: `49.899/46.871 = 1.06x`
- mean: `51.358/48.507 = 1.06x`

## Verdict

KEPT.

Score: `(Impact 4.0 x Confidence 4.5) / Effort 2.0 = 9.0`.

Next route: reprofile current head. Do not retry exact dispatch-hoisting,
array-assignment copy, or repeated SIMD copy-store variants for this lane. If
`strcpy_4096` remains material after this keep, the next primitive must attack
remaining call/wrapper/codegen overhead with a different generated lowering or
ABI-level no-overlap/terminal certificate.
