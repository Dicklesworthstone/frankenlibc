# bd-2g7oyh.464 pass180 current-head routing profile

Date: 2026-06-17T09:47:22Z

Head: `fbc7a40a8 perf(string): reuse strlen for exact strcpy4096`

Reason: reprofile current `origin/main` after the kept pass179 `strcpy_4096` strlen-prefix copy lever. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and a crate-scoped target directory.

## Command

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass180-target-20260617T0943 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' \
  --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `target/perf-logs/bd-2g7oyh-pass180-primary.log`

Log SHA-256: `bc04b80ec9cedd4f8052a27c9b1c5d21c515015c587f283417fc1ecdcc453ed8`

## Primary rows

| Profile | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `memchr_absent` | `32.418 / 34.902` | `19.668 / 21.555` | top p50+mean residual; eligible only for a different generated/backend primitive |
| `strcpy_4096` | `66.416 / 70.222` | `41.215 / 43.939` | still material after pass179; do not return to the old NUL-certificate copy family |
| `powf_irrational` | `436.239 / 425.462` | `370.920 / 385.499` | smaller residual than string scans |
| `memcmp_256` | `5.038 / 5.898` | `3.977 / 4.884` | small and fresh no-repeat/codegen route-out |
| `memmove_4096` | `38.002 / 40.927` | `36.675 / 38.964` | small and fresh no-repeat route-out |
| `memcmp_4096` | `43.888 / 46.196` | `41.406 / 44.233` | small and fresh no-repeat route-out |
| `memset_4096` | `33.381 / 34.952` | `34.643 / 36.121` | faster than host |
| `strlen_4096` | `17.950 / 20.090` | `19.521 / 21.274` | faster than host |
| `printf_g_6` | `132.521 / 139.961` | `134.094 / 141.828` | faster than host |
| `log` | `337.905 / 348.816` | `363.031 / 368.198` | faster than host |
| `log2` | `189.521 / 194.986` | `366.800 / 370.660` | faster than host |
| `log10` | `465.138 / 489.701` | `495.160 / 516.684` | faster than host |
| `exp10` | `330.285 / 350.292` | `331.867 / 346.704` | parity/no edit |
| `log1p` | `467.833 / 476.068` | `472.881 / 491.944` | faster on mean |
| `exp10f` | `260.500 / 269.581` | `316.695 / 325.872` | faster than host |
| `log10f` | `161.340 / 170.213` | `329.842 / 345.495` | faster than host |
| `log2f` | `174.184 / 178.090` | `325.941 / 335.177` | faster than host |

## Behavior proof

This pass made no source changes. Isomorphism is identity:

- Ordering/tie-breaking: unchanged for all string and math functions.
- Floating point: unchanged; no math source or rounding path edited.
- RNG/allocation/errno/locale state: unchanged.
- Golden-output behavior: unchanged by identity; source diff check passed for `crates/frankenlibc-core` and `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`.

Source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`
- `crates/frankenlibc-core/src/string/str.rs`: `688e4035527b60080dbacd52ffa6bb223c872ea62301692873ed84ce245fa3d5`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `c506824bbc9d1919cb2143c307a583ba053d405214d76611eec3e34e0e71adc0`

Validation:

```bash
git diff --exit-code -- crates/frankenlibc-core crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Result: passed.

## Verdict

ROUTING ONLY. Score `0.0` because no implementation lever was attempted.

Next route: focus `memchr_absent` only with a fundamentally different generated/backend primitive. The fresh pass180 profile shows a material p50 and mean gap, but prior `memchr_absent` passes already exhausted panel retunes and codegen-only closeouts. The next candidate must be a deeper safe-Rust primitive, for example a portable-SIMD/SWAR scan shape that avoids repeating the rejected panel families and does not require unsafe target-feature dispatch.
