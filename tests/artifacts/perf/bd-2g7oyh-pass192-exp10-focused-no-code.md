# bd-2g7oyh.474 pass192 exp10 focused no-code

Date: 2026-06-17T11:12:00Z

Head: `81be9a23b chore(perf): route out strcpy pass 191`

Reason: pass190 broad routing showed `exp10` as a material non-string residual after focused `strlen_4096` and `strcpy_4096` route-outs. Before any math source edit, this pass ran a focused local gate.

## Focused Gate

The first filter was too specific and ran no samples; the retained focused gate used the broader `exp10` filter and parsed the double-precision `exp10` rows separately from `exp10f`.

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass192-baseline2-target-20260617T1110 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  exp10 --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass192-exp10-baseline.log`

Log SHA-256: `36a03160816df5755c50c9254775aa3eda75c447933020ef6b774da15c94a8e0`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC `exp10` | `313.626` | `319.671` | `[313.72 ns 315.51 ns 317.96 ns]` |
| host glibc `exp10` | `320.825` | `333.199` | `[329.66 ns 335.69 ns 341.76 ns]` |

The focused row reversed the broad profile: FrankenLibC is faster by `1.023x` p50 and `1.042x` mean.

Guard row:

| Impl | p50 ns/op | mean ns/op |
| --- | ---: | ---: |
| FrankenLibC `exp10f` | `269.625` | `274.358` |
| host glibc `exp10f` | `332.769` | `339.907` |

## Behavior Proof

No source changes were made. Isomorphism is identity:

- IEEE special cases, integer exactness, fallback bits, rounding/NaN/Inf behavior: unchanged.
- Errno/fenv policy, allocation/RNG/locale state: unchanged.
- Golden outputs: unchanged by identity.

Source hash:

- `crates/frankenlibc-core/src/math/float.rs`: `0484402c2b45c76023999595dbec00f4af026462f56529a526a78c7c4d044b1f`

## Verdict

NO-CODE ROUTED OUT. Score `0.0`: no implementation lever attempted because focused `exp10` is already faster than host.

Next route: reprofile current head. Do not edit `exp10` from the pass190 broad row alone; require a fresh focused regression before any future source lever.
