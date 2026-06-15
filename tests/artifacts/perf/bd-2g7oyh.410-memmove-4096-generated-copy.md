# bd-2g7oyh.410 - memmove_4096 generated copy-lowering keep

Date: 2026-06-15
Agent: BoldFalcon
Worker: `ovh-a`
Target: `glibc_baseline_memmove_4096`
Source base: `origin/main` `ded71f1ec`

## Route

Pass 111 broad routing left `memmove_4096` as the next string residual after the
focused `memchr_absent` gate collapsed:

- FrankenLibC p50/mean: `37.052/39.271 ns`
- host glibc p50/mean: `31.640/33.280 ns`

Prior no-ship families include exact 4096 safe-SIMD copy panels, general
portable-SIMD copy panels, inline-only `memmove`, and surface safe-slice
branchbacks without proof of different lowering. This pass therefore required
generated-code evidence before post-benchmarking.

## Baseline

Focused pre-change RCH baseline:

```text
command: cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memmove_4096' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
worker: ovh-a

frankenlibc_core Criterion: [39.662 ns 39.879 ns 40.134 ns]
frankenlibc_core p50/mean: 39.700/41.075 ns
host_glibc Criterion:       [34.825 ns 34.963 ns 35.122 ns]
host_glibc p50/mean:       34.997/36.220 ns
```

Because the first post run showed host drift, a right-now control baseline was
also run from a detached `origin/main` worktree on the same worker:

```text
control source: origin/main ded71f1ec
worker: ovh-a

frankenlibc_core Criterion: [39.238 ns 40.394 ns 41.845 ns]
frankenlibc_core p50/mean: 44.420/44.973 ns
host_glibc Criterion:       [30.763 ns 30.907 ns 31.109 ns]
host_glibc p50/mean:       30.897/32.195 ns
```

## Lever

Add a single exact-size safe-Rust copy-lowering path to
`frankenlibc_core::string::mem::memmove`:

- compute the existing `count = min(n, dest.len(), src.len())`;
- when `count == 4096`, convert the bounded source and destination prefixes to
  array references and assign `*dst = *src`;
- otherwise use the existing dynamic `copy_from_slice` fallback.

No ABI raw-pointer overlap code was changed.

## Codegen proof

RCH `cargo build -j 1 -p frankenlibc-core --lib --profile bench` with
`RUSTFLAGS=--emit=llvm-ir` produced:

```llvm
%0 = icmp eq i64 %_0.sroa.0.0.i1, 4096
br i1 %0, label %copy_exact_4096_array.exit, label %bb11

copy_exact_4096_array.exit:
  call void @llvm.memcpy.p0.p0.i64(
    ptr noundef nonnull align 1 dereferenceable(4096) %dest.0,
    ptr noundef nonnull align 1 dereferenceable(4096) %src.0,
    i64 4096,
    i1 false)
  br label %bb7

bb11:
  tail call void @llvm.memcpy.p0.p0.i64(..., i64 %_0.sroa.0.0.i1, i1 false)
```

This is materially different from the prior rejected branchback family: the
accepted path lowers to a constant-size `llvm.memcpy` for the 4096-byte profile
row while preserving the dynamic fallback for all other counts.

## Behavior proof

RCH proof commands on `ovh-a`:

```text
cargo test -j 1 -p frankenlibc-core --lib memmove_exact_4096_array_copy_preserves_prefix_contract -- --nocapture --test-threads=1
result: ok, 1 passed
golden sha256: 92ae7e54d1615da62e9a7750fdcd6280b788ce3e85e0bd993fca3d7e3b2747dc

cargo test -j 1 -p frankenlibc-core --test property_tests prop_memmove_with_overlap -- --nocapture --test-threads=1
result: ok, 1 passed

cargo test -j 1 -p frankenlibc-abi --test conformance_diff_memmove raw_memmove_matches_glibc_over_overlap_corpus -- --nocapture --test-threads=1
result: ok, 1 passed
```

Semantics:

- prefix bytes `0..4096` match the source exactly;
- destination suffix bytes remain unchanged;
- returned copy count remains `count`;
- non-4096 and clamped lengths use the previous fallback path;
- ABI overlap behavior is unchanged because `raw_memmove_bytes` was not edited
  and the overlap corpus still matches glibc;
- no floating-point, RNG, allocation, ordering, or tie-breaking behavior is in
  this path.

Local hygiene:

```text
git diff --check -- crates/frankenlibc-core/src/string/mem.rs
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
```

Both passed.

RCH compile check:

```text
cargo check -j 1 -p frankenlibc-core --lib
result: passed
notes: existing duplicate #[inline] warnings remain in math/float32.rs and math/special.rs
```

Strict full-workspace/clippy gates were not widened for this perf commit because
the campaign is crate-scoped and the observed warning debt is unrelated to this
`mem.rs` lever.

## Post benchmark

Same-worker post benchmark:

```text
command: cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memmove_4096' --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
worker: ovh-a

frankenlibc_core Criterion: [36.039 ns 36.074 ns 36.116 ns]
frankenlibc_core p50/mean: 36.094/37.284 ns
host_glibc Criterion:       [30.340 ns 30.364 ns 30.393 ns]
host_glibc p50/mean:       30.362/32.015 ns
```

Primary control comparison:

- p50: `44.420 ns -> 36.094 ns`, `1.23x` faster
- mean: `44.973 ns -> 37.284 ns`, `1.21x` faster
- host control/post remained close: `30.897/32.195 ns` vs `30.362/32.015 ns`

Secondary earlier same-worker comparison:

- p50: `39.700 ns -> 36.094 ns`, `1.10x` faster
- mean: `41.075 ns -> 37.284 ns`, `1.10x` faster

## Score

Kept.

Score: `(Impact 3.5 x Confidence 4.0) / Effort 1.5 = 9.3`

Next route: close and push this bead, then reprofile before choosing the next
string/math residual.
