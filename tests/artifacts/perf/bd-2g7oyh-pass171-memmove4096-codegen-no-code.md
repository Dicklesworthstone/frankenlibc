# bd-2g7oyh.455 pass171 memmove_4096 codegen no-code route-out

## Target

- Bead: `bd-2g7oyh.455`
- Parent: `bd-2g7oyh`
- Profile: `glibc_baseline_memmove_4096`
- Reason: pass168 local routing profile showed `memmove_4096` still slower on the current head (`38.875/42.372 ns` p50/mean vs host `32.948/36.317 ns`).
- Constraint: `ts1`/remote RCH is offline, so this pass used local crate-scoped Cargo/Criterion with isolated target directories and `-j 1`.
- Checkout: clean detached worktree `/data/tmp/frankenlibc-pass171-clean-20260617T074538Z` at `45cfd09d4`. The shared checkout had unrelated uncommitted `mem.rs` dirt, so clean-worktree evidence is authoritative for this artifact.

## Focused Baseline

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass171-clean-baseline-target CRITERION_HOME=/data/tmp/frankenlibc-pass171-clean-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion interval: `[41.027 ns 41.859 ns 42.689 ns]`
- FrankenLibC p50/mean: `39.300/41.972 ns`
- Host glibc Criterion interval: `[35.022 ns 35.689 ns 36.373 ns]`
- Host glibc p50/mean: `33.843/36.323 ns`
- Ratio: `1.161x` p50, `1.156x` mean
- Log SHA-256: `d9b47e42bdb2242eb038d1bd0a71da6bc4a1536a0ab52343593bdb226ecb84a7`

## Codegen Gate

Command:

```bash
env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass171-clean-codegen-target RUSTFLAGS="--emit=llvm-ir,asm" cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Result:

- Codegen log SHA-256: `d6681260603f0a8b13c7708e7a44c9179edd1e801d28717d26680309da50261f`
- Source SHA-256 (`crates/frankenlibc-core/src/string/mem.rs`): `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`
- LLVM IR: `/data/tmp/frankenlibc-pass171-clean-codegen-target/release/deps/frankenlibc_core-740e8827c32a4be2.ll`
- Assembly: `/data/tmp/frankenlibc-pass171-clean-codegen-target/release/deps/frankenlibc_core-740e8827c32a4be2.s`

The optimized `frankenlibc_core::string::mem::memmove` symbol already has both retained exact-4096 lowering families:

- Full-slice exact branch: lines `203852-203868` branch on `n == 4096 && dest.len() == 4096 && src.len() == 4096`, then call `llvm.memcpy(..., i64 4096, false)`.
- Clamped exact-count fallback: lines `203870-203876` call `llvm.memcpy(..., i64 4096, false)` from the `copy_exact_4096_array` path.
- Generic fallback: lines `203886-203887` call dynamic-length `llvm.memcpy(..., %count, false)`.
- Assembly symbol lines `196785-196828` collapse both exact branches into one `movl $4096` / `callq *memcpy@GOTPCREL(%rip)` path, with dynamic-count fallback only after the exact-count branch fails.

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
