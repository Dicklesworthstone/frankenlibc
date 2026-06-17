# bd-2g7oyh.470 pass188 current-head routing profile

Date: 2026-06-17T10:58:00Z

Head: `6e06dbc1b perf(string): certify exact memchr4096 absence`

Reason: reprofile current `origin/main` after the kept pass187 exact-4096 `memchr_absent` absence certificate. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and a crate-scoped target directory.

## Command

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass188-target-20260617T1052 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log|malloc_free_64|malloc_free_256' \
  --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `target/perf-logs/bd-2g7oyh-pass188-primary.log`

Log SHA-256: `724032a42f41d296d951fd18b790f09ef7cb7fb14d67c957dc8ca4d8214c4b6b`

## Primary rows

| Profile | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `memchr_absent` | `39.110 / 44.169` | `20.068 / 21.749` | broad row noisy after focused pass187 keep; do not stack a second memchr edit without a fresh focused confirmation and different shape |
| `strlen_4096` | `28.658 / 33.768` | `21.342 / 23.009` | next admissible non-repeat target; requires different primitive from slice-position or explicit 512B zero-mask families |
| `memset_4096` | `36.910 / 37.880` | `31.790 / 33.007` | broad residual but pass185 focused gate collapsed/rejected `slice::fill`; do not repeat without focused confirmation |
| `strcpy_4096` | `84.968 / 100.197` | `70.361 / 122.893` | p50 slower but mean faster; fresh pass183 keep/no immediate repeat |
| `memmove_4096` | `38.705 / 42.876` | `33.733 / 41.103` | small/fresh route-out |
| `memcmp_256` | `5.172 / 6.119` | `3.700 / 4.733` | small/recent route-out |
| `powf_irrational` | `375.600 / 396.845` | `357.567 / 371.693` | material-ish but pass161 focused gate reversed; needs focused confirmation before edit |
| `log` | `345.936 / 377.199` | `340.372 / 345.791` | small/no edit before focused confirmation |
| `exp10` | `341.651 / 353.774` | `325.540 / 356.548` | p50 small, mean parity/faster |
| `malloc_free_64` | `5.481 / 7.933` | `5.175 / 7.023` | small/no edit |
| `malloc_free_256` | `4.995 / 5.763` | `4.818 / 5.703` | parity/no edit |
| `printf_g_6` | `133.353 / 139.963` | `142.855 / 158.267` | faster than host |
| `log2` | `172.110 / 178.603` | `331.819 / 344.385` | faster than host |
| `log10` | `411.855 / 425.108` | `503.058 / 513.356` | faster than host |
| `log1p` | `435.081 / 457.539` | `475.938 / 509.394` | faster than host |
| `exp10f` | `259.252 / 272.871` | `324.375 / 335.998` | faster than host |
| `log10f` | `159.559 / 188.629` | `356.309 / 368.259` | faster than host |
| `log2f` | `165.804 / 174.541` | `321.547 / 329.139` | faster than host |

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

Next route: focus `strlen_4096`. Do not repeat the rejected slice-position/compiler-iterator lowering or explicit 512-byte zero-mask accumulation families; a source edit must use a deeper exact-size absence/certificate or backend/codegen shape and must be kept only with focused baseline/post proof.
