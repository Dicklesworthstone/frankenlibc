# bd-2g7oyh pass175: current-head local routing profile

## Scope

- Bead: `bd-2g7oyh.459`
- Commit profiled: `6d297c9decb33914cb5a6568f86218b76b1e647e`
- Worktree: `/data/tmp/frankenlibc-pass175-profile-20260617T083435Z`
- Mode: local Criterion because `ts1`/remote RCH is offline.
- Source edits: none.

## Command

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass175-routing-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass175-routing-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' \
  --noplot --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `/data/tmp/frankenlibc-pass175-routing.log`

Log SHA-256: `737ebbe2358f1fd863d6f8e61cd8028274f43fcabc5d6bda853bd4ef0c2719de`

## Rows

| Row | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `memset_4096` | `33.120 / 37.702` | `33.208 / 34.800` | p50 parity; mean-only small tail, not next edit |
| `strlen_4096` | `18.135 / 20.689` | `20.625 / 22.575` | flipped in FrankenLibC favor; no source edit |
| `memcmp_256` | `5.408 / 6.278` | `4.367 / 5.544` | material but recent no-repeat/codegen route-out |
| `memcmp_4096` | `47.933 / 49.327` | `43.278 / 45.423` | small residual and recent no-repeat/codegen route-out |
| `printf_g_6` | `135.289 / 144.414` | `133.262 / 147.477` | mean reversed in FrankenLibC favor |
| `memmove_4096` | `44.104 / 45.924` | `35.301 / 37.540` | material but recent codegen route-out |
| `strcpy_4096` | `63.651 / 65.613` | `42.912 / 46.304` | largest material current residual |
| `memchr_absent` | `23.750 / 24.898` | `21.027 / 26.361` | mean reversed in FrankenLibC favor |
| `log` | `351.139 / 358.595` | `335.582 / 349.427` | small residual |
| `log2` | `184.161 / 186.548` | `352.351 / 366.784` | FrankenLibC faster |
| `log10` | `409.886 / 430.159` | `475.724 / 491.186` | FrankenLibC faster |
| `exp10` | `318.051 / 332.413` | `328.469 / 338.612` | FrankenLibC faster |
| `log1p` | `478.042 / 486.870` | `459.142 / 475.826` | small residual |
| `powf_irrational` | `364.093 / 378.144` | `358.378 / 371.386` | small residual |
| `exp10f` | `249.031 / 261.048` | `308.399 / 332.142` | FrankenLibC faster |
| `log10f` | `165.861 / 173.245` | `325.750 / 344.433` | FrankenLibC faster |
| `log2f` | `159.505 / 175.967` | `327.016 / 336.349` | FrankenLibC faster |

## Identity proof

No implementation source changed in this routing pass. This command passed in the clean worktree:

```bash
git diff --exit-code -- \
  crates/frankenlibc-core/src/string/mem.rs \
  crates/frankenlibc-core/src/string/str.rs \
  crates/frankenlibc-core/src/math \
  crates/frankenlibc-core/src/stdio \
  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

## Decision

Routing-only closeout, Score `0.0` because no source lever was attempted.

Next target: `strcpy_4096`, because it is the largest current material residual at `63.651/65.613 ns` vs host `42.912/46.304 ns`. Prior manual source families and codegen-only route-outs are no-repeat; the next focused bead must test a materially different generated/backend or ABI-level primitive, not another source-shape retune of the existing eight-block NUL-certificate path.
