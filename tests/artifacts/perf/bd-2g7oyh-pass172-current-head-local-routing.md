# bd-2g7oyh.456 pass172 current-head local routing profile

## Target

- Bead: `bd-2g7oyh.456`
- Parent: `bd-2g7oyh`
- Profile: current-head filtered local Criterion routing sweep
- Constraint: `ts1`/remote RCH is offline, so this pass used local crate-scoped Cargo/Criterion with isolated target directories and `-j 1`.

## Command

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass172-routing-target CRITERION_HOME=/data/tmp/frankenlibc-pass172-routing-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' --noplot --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Result:

- Exit: `0`
- Log: `/data/tmp/frankenlibc-pass172-routing.log`
- Log SHA-256: `14b30c7f8f3b27a6e8393266ec6b96ca78bc4665d0235836c59932421faec246`
- Note: the log contains embedded NUL bytes from benchmark output; rows below use the NUL-normalized `GLIBC_BASELINE_BENCH` lines.

## Current Residual Table

| Row | FrankenLibC p50/mean ns | Host p50/mean ns | Ratio p50/mean | Route |
| --- | ---: | ---: | ---: | --- |
| `memcmp_4096` | `69.660 / 74.952` | `46.757 / 57.868` | `1.490x / 1.295x` | Fresh no-repeat/codegen route-out from pass 162/163; do not repeat source families. |
| `strlen_4096` | `28.259 / 30.459` | `20.478 / 22.857` | `1.380x / 1.333x` | Next focused gate: material and not part of the current memcmp/memmove/strcpy/memchr route-out streak. |
| `memmove_4096` | `41.070 / 55.998` | `35.111 / 40.281` | `1.170x / 1.390x` | Fresh pass171 no-code route-out; codegen already collapses exact-4096 paths to `memcpy`. |
| `strcpy_4096` | `64.641 / 66.184` | `45.881 / 59.593` | `1.409x / 1.111x` | Fresh pass169 no-code route-out; codegen matches prior exact-4097 artifact. |
| `memchr_absent` | `23.155 / 24.618` | `19.717 / 21.121` | `1.174x / 1.166x` | Fresh pass167 no-code route-out after repeated rejected memchr families. |
| `printf_g_6` | `143.001 / 157.161` | `136.663 / 144.544` | `1.046x / 1.087x` | Small residual; not selected ahead of `strlen_4096`. |
| `memcmp_256` | `5.551 / 6.835` | `5.400 / 6.292` | `1.028x / 1.086x` | Small current residual plus fresh pass170 codegen route-out. |
| `exp10` | `329.787 / 349.471` | `330.506 / 343.859` | `0.998x / 1.016x` | No focused edit target on current evidence. |
| `memset_4096` | `33.224 / 36.499` | `34.572 / 36.559` | `0.961x / 0.998x` | Already at or ahead of host on p50/mean in this pass. |
| `powf_irrational` | `366.967 / 384.643` | `388.314 / 401.295` | `0.945x / 0.959x` | Faster than host. |
| `log`, `log2`, `log10`, `log1p`, `exp10f`, `log10f`, `log2f` | See log | See log | FrankenLibC faster on p50/mean | No focused edit target. |

## Behavior Proof

Identity proof: no implementation source changed in this routing pass. `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs crates/frankenlibc-core/src/string/str.rs crates/frankenlibc-core/src/math crates/frankenlibc-core/src/stdio crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` passed.

Ordering/tie-breaking, first-NUL/first-difference behavior, floating-point results, RNG state, allocation behavior, errno/locale state, and existing golden outputs are unchanged by construction.

## Verdict

ROUTING ONLY. Score `0.0`.

Next route: create a focused `strlen_4096` generated/backend primitive gate. Candidate primitive family should come from the alien-graveyard string-scan lane: a genuinely different safe-Rust scan certificate or backend lowering, not a repeat of recently rejected memchr/memcmp panel retunes.
