# bd-vdtxsb - memcmp slice-compare codegen rejection

## Target

- Bead: `bd-vdtxsb`
- Surface: `glibc_baseline_memcmp_4096`
- Route: generated-code/load-test primitive for lexicographic `memcmp` without reusing prior no-ship families.

## Baseline

Current-head reprofile from clean detached worktree
`/data/projects/.scratch/frankenlibc-pass107-reprofile-20260614T2330` at
`1e133c62a`, with RCH remote execution on `vmi1153651`.

Focused row:

| Row | FrankenLibC p50 / mean | host glibc p50 / mean | Gap |
| --- | ---: | ---: | ---: |
| `memcmp_4096` | `87.173 / 90.894 ns` | `61.383 / 63.447 ns` | `1.42x / 1.43x` |

Other sampled rows did not outrank this target:

- `strncasecmp_256_equal`: FrankenLibC `23.033 / 26.458 ns`, host `24.939 / 28.923 ns`.
- `memmove_4096`: FrankenLibC `66.986 / 71.370 ns`, host `59.620 / 63.951 ns`.
- `memchr_absent`: FrankenLibC `47.888 / 52.264 ns`, host `51.249 / 56.302 ns`.
- `powf_irrational`: FrankenLibC `1103.297 / 1149.165 ns`, host `988.957 / 1623.780 ns`.

## Candidate Screen

One scratch-only source candidate replaced the manual first-difference resolver
with safe Rust slice lexicographic comparison:

```rust
a[..count].cmp(&b[..count])
```

This was tested only in the clean scratch worktree. No production source was
staged or committed from the candidate.

Touched-file formatting screen in the scratch worktree passed:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
```

RCH codegen build:

```text
RCH_BUILD_SLOTS=1 \
RCH_WORKERS=vmi1153651 \
RCH_WORKER=vmi1153651 \
RCH_PREFERRED_WORKER=vmi1153651 \
RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CARGO_BUILD_JOBS,RUSTFLAGS \
rch exec -- env \
  AGENT_NAME=BoldFalcon \
  CARGO_BUILD_JOBS=1 \
  RUSTFLAGS=--emit=asm \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bdvdtxsb-memcmp-slicecmp-asm-target-20260614T2342 \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

RCH selected worker `vmi1227854` for the assembly build and completed
successfully. The build emitted only pre-existing project warnings plus dead-code
warnings from the scratch candidate making the old manual helpers unused.

## Codegen Verdict

The emitted assembly for `frankenlibc_core::string::mem::memcmp` was:

```asm
.section .text._RNvNtNtCseLlvQfU1WFy_16frankenlibc_core6string3mem6memcmp,"ax",@progbits
_RNvNtNtCseLlvQfU1WFy_16frankenlibc_core6string3mem6memcmp:
    callq *memcmp@GOTPCREL(%rip)
```

That is not admissible for FrankenLibC core. A core `memcmp` implementation
cannot lower to a host-libc or recursive `memcmp` call, so the candidate fails
before performance benchmarking.

## Behavior Proof

Behavior is unchanged by construction in `main`:

- The slice-compare source candidate was confined to the scratch worktree.
- No production implementation source was staged.
- `memcmp` ordering, first-difference tie-breaking, zero-length behavior,
  min-length clamping, floating-point behavior, and RNG behavior are unchanged.

## Verdict

Rejected before post-benchmark.

- Score: `0.0`
- Reason: disallowed `memcmp@GOTPCREL` lowering in the exact core `memcmp` symbol.
- Do not retry this slice-lexicographic-compare route.

Next route: use a materially different generated-code/load primitive with a
pre-benchmark assembly proof that the hot symbol remains self-contained and does
not call host libc `memcmp` or `bcmp`.
