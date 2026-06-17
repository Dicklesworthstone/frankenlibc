# bd-2g7oyh.468 pass186 current-head routing profile

Date: 2026-06-17T10:39:00Z

Head: `18235a6cc chore(perf): reject memset fill pass185`

Reason: reprofile current `origin/main` after pass185 rejected the `memset_4096` `slice::fill` lever and restored `mem.rs`. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and a crate-scoped target directory.

## Command

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass186-target-20260617T1036 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log|malloc_free_64|malloc_free_256' \
  --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `target/perf-logs/bd-2g7oyh-pass186-primary.log`

Log SHA-256: `fd0cb360017f7754622e9db55a74451416cce1b884ffad9fd6829b01ba26c919`

## Primary rows

| Profile | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `memchr_absent` | `29.663 / 32.483` | `20.822 / 22.358` | largest clean residual; next focus requires a fundamentally different primitive from recent mask-fold attempts |
| `strcpy_4096` | `51.595 / 53.199` | `44.073 / 46.911` | material but fresh pass183 keep; do not immediately repeat |
| `memmove_4096` | `38.360 / 42.526` | `33.750 / 35.907` | material but fresh pass171 route-out |
| `memcmp_256` | `5.067 / 6.080` | `4.004 / 4.911` | small; recent pass170/182 route-out |
| `log` | `327.644 / 349.467` | `326.554 / 336.859` | p50 parity; mean small/no edit before focused confirmation |
| `exp10` | `339.933 / 352.735` | `326.473 / 343.547` | small/no edit |
| `memset_4096` | `33.309 / 36.727` | `35.419 / 37.645` | faster than host after pass185 rejection; no edit |
| `strlen_4096` | `19.719 / 22.170` | `19.769 / 21.701` | p50 parity/faster; mean small/no edit |
| `memcmp_4096` | `45.232 / 48.301` | `42.463 / 46.824` | small/fresh route-out |
| `malloc_free_64` | `5.060 / 5.819` | `4.815 / 6.006` | p50 small, mean faster; no edit |
| `malloc_free_256` | `4.727 / 5.640` | `4.812 / 5.827` | faster than host |
| `printf_g_6` | `129.000 / 139.650` | `134.000 / 143.346` | faster than host |
| `powf_irrational` | `357.704 / 367.101` | `366.018 / 380.353` | faster than host |
| `log2` | `173.987 / 185.273` | `370.569 / 372.540` | faster than host |
| `log10` | `403.808 / 422.653` | `473.930 / 509.221` | faster than host |
| `log1p` | `455.370 / 474.908` | `485.478 / 509.345` | faster than host |
| `exp10f` | `257.109 / 269.478` | `307.207 / 320.129` | faster than host |
| `log10f` | `173.134 / 199.856` | `333.736 / 341.915` | faster than host |
| `log2f` | `159.283 / 165.264` | `307.047 / 319.315` | faster than host |

## Behavior proof

This pass made no source changes. Isomorphism is identity:

- Ordering/tie-breaking: unchanged for all profiled string and math APIs.
- Floating point: unchanged; no math source or rounding path edited.
- RNG/allocation/errno/locale state: unchanged.
- Golden-output behavior: unchanged by identity; source diff check passed for `crates/frankenlibc-core` and `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`.

Source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d`
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

Next route: focus `memchr_absent` with a deeper algorithmically different primitive. Do not retry explicit folded mask OR, control-mask aggregation, panel-width retunes, target-feature dispatch, or codegen-only closeout families. A source edit must attack a different scan shape such as scalar broadword absence with a different dependency graph or an exact-size safe array/codegen artifact.
