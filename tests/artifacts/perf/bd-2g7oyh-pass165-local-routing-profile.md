# bd-2g7oyh.447 pass 165 local routing profile

## Target

- Parent: `bd-2g7oyh`
- Child: `bd-2g7oyh.447`
- Mode: local routing profile while `ts1`/remote RCH is offline
- Source edits: none

Pass 165 reprofiled the remaining material rows after pass 163 routed out
`memcmp_4096` source families and pass 164 routed out `malloc_free_256`.

## Command

```bash
env AGENT_NAME=BoldFalcon \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass164-malloc-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass165-routing-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' \
  --noplot --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log SHA-256:

```text
0a91cb6587158b61f275aaf3b48321cf7e230454de13a2f0db4e2bf2cf877c96  /data/tmp/frankenlibc-pass165-routing-local.log
```

## Material Rows

| row | FL p50 | host p50 | p50 ratio | FL mean | host mean | mean ratio | route |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `strcpy_4096` | 72.331 ns | 43.931 ns | 1.647x | 78.849 ns | 47.172 ns | 1.672x | next: codegen-first |
| `memchr_absent` | 30.252 ns | 20.769 ns | 1.457x | 32.286 ns | 22.320 ns | 1.447x | next after strcpy/codegen |
| `strlen_4096` | 25.955 ns | 20.379 ns | 1.274x | 28.972 ns | 21.948 ns | 1.320x | material but recent no-repeat families |
| `memcmp_256` | 5.856 ns | 4.457 ns | 1.314x | 6.881 ns | 6.134 ns | 1.122x | requires generated/backend primitive |
| `memmove_4096` | 42.514 ns | 37.262 ns | 1.141x | 46.149 ns | 39.657 ns | 1.164x | smaller residual |
| `memcmp_4096` | 46.891 ns | 43.055 ns | 1.089x | 52.980 ns | 48.644 ns | 1.089x | pass 163 routed out source families |
| `exp10` | 336.377 ns | 323.563 ns | 1.040x | 363.353 ns | 337.140 ns | 1.078x | small math residual |
| `powf_irrational` | 397.895 ns | 375.422 ns | 1.060x | 412.747 ns | 383.459 ns | 1.076x | recent focused no-code lane |
| `printf_g_6` | 142.942 ns | 139.466 ns | 1.025x | 151.294 ns | 145.060 ns | 1.043x | too small |

Closed/faster rows in this local sweep:

- `memset_4096`: FL mean `37.990 ns` vs host `44.980 ns`; Criterion center
  `33.326 ns` vs host `35.536 ns`.
- `log`, `log2`, `log10`, `log1p`, `exp10f`, `log10f`, and `log2f` were
  faster than host or not a source-edit target in this sweep.

## Isomorphism Proof

No source changed in pass 165.

`git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs
crates/frankenlibc-core/src/string/mem.rs crates/frankenlibc-core/src/math
crates/frankenlibc-core/src/stdio` passed.

String ordering, NUL termination, destination-tail preservation, memcmp
tie-breaking, math floating-point behavior, printf formatting, allocation
behavior, RNG state, locale state, errno/fenv behavior, and existing golden
outputs are unchanged by identity.

## Verdict

ROUTING ONLY, Score `0.0`.

`strcpy_4096` is the clear top local residual, but previous passes already
closed or rejected terminal exact-copy, NUL-free certificate, prefix-helper,
dispatch-hoist, array-copy lowering, public-wrapper inlining, repeated SIMD
stores, scan-only bulk-copy, and copy-shape retune families. The next pass must
therefore be codegen-first: inspect the current `strcpy_4096` emitted IR/asm and
only edit source if the backend artifact exposes a materially different safe-Rust
primitive.
