# bd-2g7oyh.445 memcmp_4096 pass 163 codegen no-code route

## Target

- Parent: `bd-2g7oyh`
- Child: `bd-2g7oyh.445`
- Workload: `glibc_baseline_memcmp_4096`
- Source target: `crates/frankenlibc-core/src/string/mem.rs`
- Current source SHA-256:
  `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`

Pass 162 established the local focused baseline while `ts1`/remote RCH was
offline by directive:

| row | Criterion low | Criterion center | Criterion high | p50 | mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | 55.296 ns | 56.194 ns | 57.232 ns | 56.801 ns | 61.046 ns |
| host glibc | 37.800 ns | 38.468 ns | 39.149 ns | 37.879 ns | 39.147 ns |

Pass 162's source lever regressed and was restored. Pass 163 therefore did not
edit source; it inspected backend output before considering another
`memcmp_4096` attempt.

## Local Codegen Command

```bash
env AGENT_NAME=BoldFalcon \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass163-memcmp4096-codegen-target \
  RUSTFLAGS="--emit=llvm-ir,asm" \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Result: passed in the local bench profile. Existing unrelated warnings remained
in `iconv`, `eucjisx0213_tables`, and `regex`.

Generated artifacts:

```text
44ba4acb9faaf1ae5c07115c10ae4b0600e362b46499fb3ed189398992d81c04  /data/tmp/frankenlibc-pass163-memcmp4096-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.ll
0462e506c4b3303488ece79eb605088c35bdcbf61e48267a8cd362ea218685ee  /data/tmp/frankenlibc-pass163-memcmp4096-codegen-target/release/deps/frankenlibc_core-6253bb5504e3510e.s
```

## Backend Evidence

The optimized IR has a direct `4096` switch arm in
`frankenlibc_core::string::mem::memcmp`:

```llvm
switch i64 %_0.sroa.0.0.i95, label %bb13 [
  i64 16, label %...
  i64 4096, label %bb7.i
  i64 256, label %bb10
]

bb7.i:
  %_34.i.val = load <64 x i8>, ptr %_34.i, align 1
  %_44.i.val = load <64 x i8>, ptr %_44.i, align 1
  %1 = xor <64 x i8> %_44.i.val, %_34.i.val
  %2 = or <64 x i8> %1, %acc.sroa.0.0.i239
```

The matching assembly inside the same symbol is self-contained:

```asm
cmpq    $4096, %r8
jne     .LBB1222_11
pxor    %xmm0, %xmm0
movq    $-64, %rax
pxor    %xmm1, %xmm1
pxor    %xmm3, %xmm3
pxor    %xmm2, %xmm2
.LBB1222_4:
movdqu  64(%rdi,%rax), %xmm4
movdqu  80(%rdi,%rax), %xmm5
movdqu  96(%rdi,%rax), %xmm6
movdqu  112(%rdi,%rax), %xmm7
movdqu  64(%rdx,%rax), %xmm8
pxor    %xmm4, %xmm8
por     %xmm8, %xmm0
```

There is no `memcmp@GOTPCREL` or `bcmp@GOTPCREL` call inside
`frankenlibc_core::string::mem::memcmp`; crate-wide `memcmp`/`bcmp` references
seen by `rg` belong to unrelated generated string comparisons or other symbols.

## Isomorphism Proof

No source changed in pass 163.

- `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs`: passed.
- `mem.rs` SHA-256 remained
  `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`.
- Ordering, first-difference tie-breaking, equal-buffer return, short-length
  clamping, floating-point state, RNG state, allocation behavior, locale state,
  and the pass 162 golden `memcmp` hashes remain unchanged by identity.

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

The codegen artifact disproves the libc-call hypothesis for the current
`memcmp_4096` hot symbol and shows the backend already creates four independent
SSE2 accumulators from the existing safe-Rust source. That makes another manual
dependency split, superfold, rank/select, broadword extraction, slice/array
equality lowering, cross-crate inline, chunk cursor, or XOR/test-zero retune a
repeat of rejected families without a new primitive.

Next route: do not edit `memcmp_4096` again until a materially different
generated/backend primitive is available. Use the pass 159 routing table and
focus the next admissible residual, with `malloc_free_256` as the next candidate
if a local focused gate reproduces while remote RCH remains offline.
