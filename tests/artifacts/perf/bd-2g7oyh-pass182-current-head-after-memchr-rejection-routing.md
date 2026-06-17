# bd-2g7oyh.465 pass182 current-head routing profile

Date: 2026-06-17T10:07:09Z

Head: `d290c2fdc chore(perf): reject memchr mask-fold pass181`

Reason: reprofile current `origin/main` after the remote pass181 `memchr_absent` explicit mask-fold rejection. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and a crate-scoped target directory.

## Command

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass182-target-20260617T1004 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' \
  --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `target/perf-logs/bd-2g7oyh-pass182-primary.log`

Log SHA-256: `720c7f3fe8a0702d9080ffae2376501ebfa7e17e1c35b59215c45a61b0816502`

## Primary rows

| Profile | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `memmove_4096` | `39.115 / 41.753` | `32.921 / 35.227` | material but fresh pass171 codegen route-out |
| `memcmp_256` | `5.075 / 6.028` | `3.986 / 4.853` | small and fresh pass170 codegen route-out |
| `memchr_absent` | `23.198 / 25.169` | `18.571 / 22.558` | still profile-backed on p50; requires broadword/SWAR primitive, not mask retune |
| `memcmp_4096` | `45.787 / 51.362` | `43.178 / 46.077` | small and fresh pass163 route-out |
| `memset_4096` | `36.641 / 39.395` | `34.637 / 36.086` | small/no edit |
| `strcpy_4096` | `56.217 / 59.336` | `53.008 / 54.367` | much closer after pass179; no immediate edit |
| `log` | `361.009 / 365.755` | `346.062 / 358.598` | small/no edit |
| `strlen_4096` | `19.912 / 23.588` | `21.330 / 23.107` | p50 faster, mean parity |
| `printf_g_6` | `133.389 / 143.195` | `136.204 / 145.177` | faster than host |
| `log2` | `192.218 / 193.512` | `335.815 / 346.624` | faster than host |
| `log10` | `396.007 / 420.041` | `475.657 / 496.199` | faster than host |
| `exp10` | `323.000 / 345.658` | `351.578 / 366.255` | faster than host |
| `log1p` | `442.290 / 478.250` | `480.124 / 507.411` | faster than host |
| `powf_irrational` | `357.347 / 370.197` | `370.500 / 385.270` | faster than host |
| `exp10f` | `252.105 / 264.395` | `304.191 / 312.430` | faster than host |
| `log10f` | `161.500 / 169.827` | `336.454 / 358.952` | faster than host |
| `log2f` | `164.252 / 170.730` | `311.875 / 323.007` | faster than host |

## Behavior proof

This pass made no source changes. Isomorphism is identity:

- Ordering/tie-breaking: unchanged for all profiled string and math APIs.
- Floating point: unchanged; no math source or rounding path edited.
- RNG/allocation/errno/locale state: unchanged.
- Golden-output behavior: unchanged by identity; source diff check passed for `crates/frankenlibc-core` and `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`.

Source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`
- `crates/frankenlibc-core/src/string/str.rs`: `688e4035527b60080dbacd52ffa6bb223c872ea62301692873ed84ce245fa3d5`
- `crates/frankenlibc-core/src/math/float32.rs`: `63175ec480d85c563d373be973eb85ce33ff68ef106a7fa239aef6a0217751aa`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `c506824bbc9d1919cb2143c307a583ba053d405214d76611eec3e34e0e71adc0`

Validation:

```bash
git diff --exit-code -- crates/frankenlibc-core crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Result: passed.

## Verdict

ROUTING ONLY. Score `0.0` because no implementation lever was attempted.

Next route: focus `memchr_absent` only with an algorithmically different broadword/SWAR aggregation primitive. Do not retry explicit folded mask-OR, direct control-mask groups, panel-width retunes, target-feature dispatch, or codegen-only closeout families.
