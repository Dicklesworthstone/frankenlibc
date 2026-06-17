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
- Log SHA-256: `e64ae271d6f33b58dfc32cd856e672775f7f268bf62ef724e43e415fe5ea4506`
- Note: the log contains embedded NUL bytes from benchmark output; rows below use the NUL-normalized `GLIBC_BASELINE_BENCH` lines.

## Current Residual Table

| Row | FrankenLibC p50/mean ns | Host p50/mean ns | Ratio p50/mean | Route |
| --- | ---: | ---: | ---: | --- |
| `memcmp_4096` | `69.660 / 74.952` | `46.757 / 57.868` | `1.490x / 1.295x` | Fresh no-repeat/codegen route-out from pass 162/163; do not repeat source families. |
| `strlen_4096` | `28.259 / 30.459` | `20.478 / 22.857` | `1.380x / 1.333x` | Next focused gate: material and not part of the current memcmp/memmove/strcpy/memchr route-out streak. |
| `memmove_4096` | `38.566 / 43.577` | `32.549 / 35.247` | `1.185x / 1.236x` | Fresh pass171 no-code route-out; codegen already collapses exact-4096 paths to `memcpy`. |
| `strcpy_4096` | `53.807 / 58.271` | `39.878 / 42.865` | `1.349x / 1.359x` | Fresh pass169 no-code route-out; codegen matches prior exact-4097 artifact. |
| `memchr_absent` | `22.158 / 24.195` | `19.550 / 21.243` | `1.133x / 1.139x` | Fresh pass167 no-code route-out after repeated rejected memchr families. |
| `printf_g_6` | `143.001 / 157.161` | `136.663 / 144.544` | `1.046x / 1.087x` | Small residual; not selected ahead of `strlen_4096`. |
| `memcmp_256` | `5.551 / 6.835` | `5.400 / 6.292` | `1.028x / 1.086x` | Small current residual plus fresh pass170 codegen route-out. |
| `exp10` | `316.587 / 327.994` | `321.777 / 348.941` | `0.984x / 0.940x` | Faster than host on p50/mean. |
| `memset_4096` | `33.224 / 36.499` | `34.572 / 36.559` | `0.961x / 0.998x` | Already at or ahead of host on p50/mean in this pass. |
| `powf_irrational` | `382.706 / 400.134` | `360.878 / 405.726` | `1.060x / 0.986x` | Mixed p50/mean, no focused edit target ahead of `strlen_4096`. |
| `log` | `338.881 / 385.268` | `328.369 / 354.578` | `1.032x / 1.087x` | Small residual, not selected. |
| `log2` | `169.750 / 178.240` | `318.379 / 331.076` | `0.533x / 0.538x` | Faster than host. |
| `log10` | `395.771 / 423.294` | `475.849 / 491.070` | `0.831x / 0.862x` | Faster than host. |
| `log1p` | `428.205 / 446.021` | `493.313 / 508.340` | `0.868x / 0.877x` | Faster than host. |
| `exp10f` | `247.586 / 255.401` | `305.523 / 316.013` | `0.810x / 0.808x` | Faster than host. |
| `log10f` | `167.028 / 178.798` | `331.633 / 342.647` | `0.504x / 0.522x` | Faster than host. |
| `log2f` | `168.324 / 172.497` | `306.910 / 327.629` | `0.548x / 0.526x` | Faster than host. |

## Behavior Proof

Identity proof: no implementation source changed in this routing pass. `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs crates/frankenlibc-core/src/string/str.rs crates/frankenlibc-core/src/math crates/frankenlibc-core/src/stdio crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` passed.

Ordering/tie-breaking, first-NUL/first-difference behavior, floating-point results, RNG state, allocation behavior, errno/locale state, and existing golden outputs are unchanged by construction.

## Verdict

ROUTING ONLY. Score `0.0`.

Next route: create a focused `strlen_4096` generated/backend primitive gate. Candidate primitive family should come from the alien-graveyard string-scan lane: a genuinely different safe-Rust scan certificate or backend lowering, not a repeat of recently rejected memchr/memcmp panel retunes.
