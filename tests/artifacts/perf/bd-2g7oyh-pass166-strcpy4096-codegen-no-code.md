# bd-2g7oyh.448 pass 166 strcpy_4096 codegen gate

## Target

- Parent: `bd-2g7oyh`
- Child: `bd-2g7oyh.448`
- Mode: local codegen-first route while `ts1`/remote RCH is offline
- Source edits: none

Pass 166 inspected the current generated `strcpy_4096` path after pass 165
showed it as the top remaining local residual:

- FrankenLibC p50/mean `72.331/78.849 ns`
- host p50/mean `43.931/47.172 ns`
- ratio `1.647x/1.672x`

## Command

```bash
env AGENT_NAME=BoldFalcon \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass166-strcpy-codegen-target \
  RUSTFLAGS="--emit=llvm-ir,asm" \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

The local crate-scoped build passed with only the existing unrelated warnings.

Generated artifact hashes:

```text
44ba4acb9faaf1ae5c07115c10ae4b0600e362b46499fb3ed189398992d81c04  /data/tmp/frankenlibc-pass166-strcpy-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.ll
0462e506c4b3303488ece79eb605088c35bdcbf61e48267a8cd362ea218685ee  /data/tmp/frankenlibc-pass166-strcpy-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.s
807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd  crates/frankenlibc-core/src/string/str.rs
```

## Codegen Findings

The optimized LLVM IR for
`frankenlibc_core::string::str::strcpy` already contains the retained
exact-length specialization for `src.1 == 4097`.

Observed path shape:

- eight 512-byte NUL-free certificate blocks for the exact 4097-byte case
- per-block `<64 x i8>` vector loads and `llvm.umin.v64i8` reductions
- early-NUL byte resolver preserving first-NUL ordering and copied length
- direct vector stores for NUL-free 512-byte blocks
- terminal `llvm.memcpy` for the copied inclusive-NUL prefix
- no source-level opportunity that differs from the prior no-repeat families

Representative IR locations in the generated file:

- `208904..209606`: exact `4097` switch arm and first set of 512-byte
  certificate blocks
- `209606`: unified `strcpy.exit` preserving the copied-count result
- later in the same function: bulk copy loop using `copy_nul_free_block_512`
  vector stores and a terminal prefix `llvm.memcpy`

This confirms the current source is already expressing the available safe-Rust
terminal/certificate primitive that prior passes required.

## Isomorphism Proof

No source changed in pass 166.

`git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs` passed.

First-NUL ordering, copied byte order, returned count, destination-tail
preservation, panic behavior, overlap policy, allocation behavior, errno/locale
state, floating-point state, RNG state, and existing golden outputs are
unchanged by identity.

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

Do not retry the documented `strcpy_4096` families without a genuinely
different generated/backend primitive. Closed families now include SWAR/global
NUL certificates, prefix-helper attributes, terminal splitting, dispatch
hoists, array-copy lowering, typed exact-source/destination lowering, public
wrapper inlining, repeated SIMD stores, scan-only bulk-copy certificates,
copy-shape retunes, terminal-boundary bulk-copy, and this local codegen gate.

Next profile-backed route from pass 165: `memchr_absent` focused/codegen gate.
