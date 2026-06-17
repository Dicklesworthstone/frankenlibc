# bd-2g7oyh.461 pass177 current-head local routing profile

Date: 2026-06-17
Agent: BoldFalcon
Mode: local fallback, `RCH_REQUIRE_REMOTE=0`, crate-scoped cargo/Criterion only
Profiled commit: `17f47bb6ba64ead47ca888d93c495320a1f16b5b`
Clean worktree: `/data/tmp/frankenlibc-pass177-profile-20260617T085936Z`

## Commands

String rows:

```text
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass177-profile-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass177-profile-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|log)' \
  --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

The first filter matched the string rows. Supplemental math/stdio filter against the same worktree and target:

```text
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass177-profile-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass177-profile-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'printf_g_6|powf_irrational|exp10|/log' \
  --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Log hashes:

- string log sha256: `4017408cfa68371398aa01b936201a1bdea7c082a1edbc1187fd0c2241fffd81`
- math/stdio log sha256: `c6f9859d9bc036a327238a3dcdfaf53f8cc325874662ab98fa26369e4f474ee4`

## Route table

| row | FL p50 | host p50 | p50 ratio | FL mean | host mean | mean ratio | route |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `memset_4096` | `34.301` | `33.812` | `1.014x` | `37.032` | `35.715` | `1.037x` | no material gap |
| `strlen_4096` | `18.696` | `21.416` | `0.873x` | `20.803` | `22.985` | `0.905x` | FL faster |
| `memcmp_256` | `5.732` | `4.773` | `1.201x` | `7.527` | `5.624` | `1.338x` | residual, recent no-repeat/codegen route-outs |
| `memcmp_4096` | `46.250` | `44.898` | `1.030x` | `49.264` | `46.913` | `1.050x` | small residual |
| `memmove_4096` | `40.253` | `34.089` | `1.181x` | `42.358` | `36.703` | `1.154x` | residual, recent no-repeat/codegen route-outs |
| `strcpy_4096` | `61.304` | `41.032` | `1.494x` | `62.910` | `43.735` | `1.439x` | material but pass176 just routed current backend/source family out |
| `memchr_absent` | `30.737` | `19.500` | `1.576x` | `32.337` | `24.509` | `1.319x` | next focused target |
| `printf_g_6` | `130.738` | `132.106` | `0.990x` | `137.919` | `147.581` | `0.935x` | FL faster |
| `log` | `328.852` | `337.623` | `0.974x` | `348.309` | `360.740` | `0.966x` | FL faster |
| `log2` | `181.227` | `321.033` | `0.565x` | `190.186` | `344.661` | `0.552x` | FL faster |
| `log10` | `411.395` | `517.665` | `0.795x` | `430.031` | `548.392` | `0.784x` | FL faster |
| `exp10` | `321.547` | `321.830` | `0.999x` | `332.016` | `342.832` | `0.968x` | parity/faster |
| `log1p` | `449.206` | `490.644` | `0.916x` | `473.815` | `520.406` | `0.910x` | FL faster |
| `powf_irrational` | `383.328` | `367.547` | `1.043x` | `426.884` | `383.888` | `1.112x` | smaller residual |
| `exp10f` | `252.909` | `326.978` | `0.773x` | `264.518` | `335.449` | `0.789x` | FL faster |
| `log10f` | `167.719` | `340.500` | `0.493x` | `172.667` | `350.859` | `0.492x` | FL faster |
| `log2f` | `167.709` | `307.738` | `0.545x` | `172.882` | `322.060` | `0.537x` | FL faster |

## Identity proof

No source files were changed in the clean profiling worktree. This command passed:

```text
git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs \
  crates/frankenlibc-core/src/string/str.rs \
  crates/frankenlibc-core/src/math \
  crates/frankenlibc-core/src/stdio \
  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Ordering, tie-breaking, floating-point state, RNG state, allocation behavior, locale, errno, and all golden-output contracts are unchanged by construction.

## Decision

Routing only. Score: `0.0`.

Next target: focused `memchr_absent` baseline. It now has a fresh material p50 and mean gap (`30.737/32.337 ns` vs host `19.500/24.509 ns`). Prior `memchr_absent` passes already ruled out folded-panel widening, exact-4096 dispatch, contains certificates, loop/tail rearrangement, SWAR word-group scans, rank/select, indexed folded scans, wrapper inlining, and hot/cold outlining. The next lever must therefore be a fundamentally different generated/backend-dispatch or ABI-level primitive, not another panel-width or loop-shape edit.
