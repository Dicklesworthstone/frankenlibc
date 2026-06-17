# bd-2g7oyh.460 pass176 strcpy4096 backend-gate route-out

Date: 2026-06-17
Agent: BoldFalcon
Target: `glibc_baseline_strcpy_4096`
Mode: local fallback, `RCH_REQUIRE_REMOTE=0`, crate-scoped cargo/Criterion only

## Profile-backed target

Pass175 current-head local routing selected `strcpy_4096` as the largest material residual after `strlen_4096` flipped in FrankenLibC's favor:

- FrankenLibC p50/mean: `63.651/65.613 ns`
- host glibc p50/mean: `42.912/46.304 ns`

The live bead required a fresh focused baseline before any lever and forbade retrying prior source-shape families around the existing eight-block NUL-certificate path.

## Focused local baseline

Clean detached worktree: `/data/tmp/frankenlibc-pass176-strcpy-20260617T0844`

Command:

```text
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass176-strcpy-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass176-strcpy-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Baseline results:

- FrankenLibC Criterion interval: `[66.682 ns 68.011 ns 69.334 ns]`
- FrankenLibC p50/mean: `65.037/66.514 ns`
- host glibc Criterion interval: `[44.017 ns 44.882 ns 45.787 ns]`
- host glibc p50/mean: `43.832/45.391 ns`
- baseline log sha256: `b21521c9940cde2bf4bb2f8556950e37cc0bfa2efdd5446dfbd67a7cf88684ad`

This reproduces a material focused residual.

## Backend/codegen screen

Current source hash:

- `crates/frankenlibc-core/src/string/str.rs`: `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`

Codegen command:

```text
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass176-strcpy-codegen-target \
  RUSTFLAGS='--emit=llvm-ir,asm' \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Hashes:

- codegen log sha256: `67798bbf49b9333560263bdb2bcda61080dc6cbbac05d23602a00deca90a8807`
- LLVM IR sha256: `cdcbf433a374c60d83a4e1d5d071d7d1c78b3f4ba35115b81122de87ed226c5d`
- ASM sha256: `0056785d393672262cdac799be6968b9694d6671bcc0c3c51a69e96db2ab2fd8`

Relevant generated IR for the exact 4097-byte source case:

- `icmp eq i64 %src.1, 4097` dispatches to the exact path.
- The exact path loads eight 64-byte panels per 512-byte block and folds with `llvm.umin.v64i8`, then compares against zero and bitcasts the mask to an integer.
- The first-NUL fallback remains scalar inside the first positive 512-byte block.
- The terminal no-early-NUL case lowers to `llvm.memcpy.p0.p0.i64(..., i64 4097, i1 false)`.

Relevant generated ASM shows the same shape:

- `cmpq $4097, %rcx` dispatch.
- vector `movdqu` loads plus packed-min/zero-mask checks for the 512-byte panels.
- late terminal route moves `4097` into the copy length and branches to the memcpy call path.

## No-code verdict

No source lever was attempted because the current generated artifact already has the backend properties that prior source edits tried to coerce:

- exact-size dispatch for `src.len() == 4097`
- vectorized NUL certificate over the NUL-free prefix
- scalar first-NUL resolution only for the positive block
- terminal inclusive-NUL bulk copy through generated memcpy

Prior no-repeat families for this lane include word/SWAR/global NUL certificates, terminal splitting, public wrapper inlining, copy-store variants, scan-only certificate plus bulk copy, and uniform-source/certified-block copy-shape retunes. A new source edit in that family would be a repeat without a new profile-backed mechanism.

Behavior proof is identity: implementation source is unchanged. First-NUL ordering, copied byte order, returned count, destination-tail preservation, panic behavior, overlap policy, allocation, errno, locale, floating-point state, and RNG state are untouched. Existing `strcpy` golden SHA contracts remain the active behavior proof.

Score: `0.0` (`no source change; route-out only`)

Next route: reprofile current head and select the next material residual. If `strcpy_4096` is revisited, it needs a fundamentally different generated/backend or ABI-level primitive, not another source-shape retune of the eight-block NUL-certificate path.
