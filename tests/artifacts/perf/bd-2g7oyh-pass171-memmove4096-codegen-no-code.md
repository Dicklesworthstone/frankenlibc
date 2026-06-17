# bd-2g7oyh.455 pass171 memmove_4096 codegen no-code route-out

## Target

- Bead: `bd-2g7oyh.455`
- Parent: `bd-2g7oyh`
- Profile: `glibc_baseline_memmove_4096`
- Reason: pass168 local routing profile showed `memmove_4096` still slower on the current head (`38.875/42.372 ns` p50/mean vs host `32.948/36.317 ns`).
- Constraint: `ts1`/remote RCH is offline, so this pass used local crate-scoped Cargo/Criterion with isolated target directories and `-j 1`.

## Focused Baseline

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass171-memmove-baseline-target CRITERION_HOME=/data/tmp/frankenlibc-pass171-memmove-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion interval: `[38.956 ns 39.690 ns 40.502 ns]`
- FrankenLibC p50/mean: `38.159/41.634 ns`
- Host glibc Criterion interval: `[34.469 ns 35.188 ns 35.898 ns]`
- Host glibc p50/mean: `33.397/36.983 ns`
- Ratio: `1.143x` p50, `1.126x` mean
- Log SHA-256: `aeba11e933d565ccf0c403ccc1242d7b200aef94b85a2615653c8e9126683e04`

## Codegen Gate

Command:

```bash
env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass171-memmove-codegen-target RUSTFLAGS="--emit=llvm-ir,asm" cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Result:

- Codegen log SHA-256: `c45ab87e18d0ee503991267cd13baa45ef5534bf0dd11b7f65d636b1fe952b2f`
- Source SHA-256 (`crates/frankenlibc-core/src/string/mem.rs`): `7a5a805155bcef52063389dd55e439af8e6dab5160dff49974eb784d429a671d`
- LLVM IR: `/data/tmp/frankenlibc-pass171-memmove-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.ll`
- Assembly: `/data/tmp/frankenlibc-pass171-memmove-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.s`

The optimized `frankenlibc_core::string::mem::memmove` symbol already has both retained exact-4096 lowering families:

- Full-slice exact branch: lines `203915-203931` branch on `n == 4096 && dest.len() == 4096 && src.len() == 4096`, then call `llvm.memcpy(..., i64 4096, false)`.
- Clamped exact-count fallback: lines `203933-203939` call `llvm.memcpy(..., i64 4096, false)` from the `copy_exact_4096_array` path.
- Generic fallback: lines `203949-203950` call dynamic-length `llvm.memcpy(..., %count, false)`.
- Assembly symbol lines `196841-196884` collapse both exact branches into one `movl $4096` / `callq *memcpy@GOTPCREL(%rip)` path, with dynamic-count fallback only after the exact-count branch fails.

## No-Repeat Screen

No source change was made. The available source levers repeat closed families:

- wrapper inlining
- exact safe-slice branchbacks
- fixed chunk array copies
- safe-SIMD copy panels
- surface exact-copy lowering
- exact 4096 copy-shape retunes

The remaining gap is backend/libc `memcpy` call overhead or host implementation detail after the two accepted safe-Rust exact-copy lowerings. A new source edit would need a materially different backend-generated primitive or ABI-level no-overlap classification proof; this pass did not find one.

## Behavior Proof

Identity proof: production source is unchanged. The following are unchanged by construction:

- copied prefix bytes
- return count
- destination suffix preservation
- safe-core non-overlap behavior
- ABI overlap behavior
- allocation behavior
- errno and locale state
- FP and RNG state
- existing memmove golden outputs `92ae7e54d1615da62e9a7750fdcd6280b788ce3e85e0bd993fca3d7e3b2747dc` and `4e441a3533bb2c10cd5649981d395744213e09a336746b5a3458fee4057205ec`

## Verdict

NO-CODE ROUTED OUT. Score `0.0`.

Next route: reprofile current head locally before selecting another residual. Do not return to `memmove_4096` without a fresh material focused gap and a genuinely different backend/generated or ABI-level no-overlap primitive.
