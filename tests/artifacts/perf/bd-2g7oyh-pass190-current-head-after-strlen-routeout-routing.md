# bd-2g7oyh.472 pass190 current-head routing profile

Date: 2026-06-17T11:05:00Z

Head: `19972710b chore(perf): route out strlen pass 189`

Reason: reprofile current `origin/main` after pass189 focused `strlen_4096` routed out without source changes. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and a crate-scoped target directory.

## Command

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass190-target-20260617T1100 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log|malloc_free_64|malloc_free_256' \
  --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `target/perf-logs/bd-2g7oyh-pass190-primary.log`

Log SHA-256: `623b0177baace1ea39916acff4246cf0c4726f9c4d9efd1b30155e8e581a66e1`

## Primary rows

| Profile | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `strcpy_4096` | `65.900 / 67.242` | `40.901 / 43.451` | largest current material residual; fresh pass183 keep, so next pass must focused-confirm before any different primitive |
| `memchr_absent` | `32.273 / 33.581` | `20.786 / 22.342` | still material but pass187 just kept exact absence certificate; do not stack another memchr edit without focused confirmation and different path |
| `memmove_4096` | `38.744 / 43.194` | `35.527 / 38.054` | smaller/fresh route-out |
| `exp10` | `347.062 / 360.760` | `313.282 / 324.182` | material-ish; string rows remain larger |
| `powf_irrational` | `380.236 / 424.781` | `357.552 / 401.929` | broad residual but pass161 focused gate reversed; needs focused confirmation before edit |
| `log` | `348.954 / 357.873` | `332.708 / 345.922` | small/no edit |
| `memcmp_256` | `5.212 / 6.134` | `4.036 / 4.776` | small/recent route-out |
| `memcmp_4096` | `45.668 / 48.654` | `45.681 / 47.307` | parity/no edit |
| `malloc_free_256` | `5.110 / 6.058` | `5.016 / 5.961` | parity/no edit |
| `memset_4096` | `34.876 / 37.006` | `36.715 / 39.072` | faster than host |
| `strlen_4096` | `18.000 / 20.599` | `21.975 / 26.016` | faster than host |
| `malloc_free_64` | `4.937 / 6.172` | `5.343 / 7.117` | faster than host |
| `printf_g_6` | `135.083 / 143.162` | `141.364 / 149.346` | faster than host |
| `log2` | `176.854 / 182.140` | `345.612 / 354.953` | faster than host |
| `log10` | `454.262 / 459.089` | `496.414 / 514.580` | faster than host |
| `log1p` | `463.578 / 473.300` | `515.022 / 549.367` | faster than host |
| `exp10f` | `255.521 / 266.441` | `321.871 / 333.688` | faster than host |
| `log10f` | `158.315 / 162.741` | `321.714 / 332.350` | faster than host |
| `log2f` | `161.042 / 168.389` | `319.136 / 331.267` | faster than host |

## Behavior proof

This pass made no source changes. Isomorphism is identity:

- Ordering/tie-breaking: unchanged for all profiled string and math APIs.
- Floating point: unchanged; no math source or rounding path edited.
- RNG/allocation/errno/locale state: unchanged.
- Golden-output behavior: unchanged by identity; source diff check passed for `crates/frankenlibc-core` and `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`.

Source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `04795966abfaab92fb33447804ae206199ab945c31942da842568cb37799ee12`
- `crates/frankenlibc-core/src/string/str.rs`: `63af120d4c9ee3a3af6db0ec78f48d210b8d87dc17df67fdcdab8be975506d92`
- `crates/frankenlibc-core/src/math/float32.rs`: `63175ec480d85c563d373be973eb85ce33ff68ef106a7fa239aef6a0217751aa`
- `crates/frankenlibc-core/src/malloc/allocator.rs`: `2ca1fd83bf633e1397dde64d6425701a21fee79b7d7a953b3ca8104c0833229d`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `c506824bbc9d1919cb2143c307a583ba053d405214d76611eec3e34e0e71adc0`

Validation:

```bash
git diff --exit-code -- crates/frankenlibc-core crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Result: passed.

## Verdict

ROUTING ONLY. Score `0.0` because no implementation lever was attempted.

Next route: focus `strcpy_4096` before editing. Do not repeat the kept pass179 strlen-prefix copy or pass183 certified scan-copy families; any source lever must be algorithmically different and pass focused baseline/post proof.
