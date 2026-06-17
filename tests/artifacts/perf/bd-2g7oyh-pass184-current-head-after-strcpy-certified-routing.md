# bd-2g7oyh.466 pass184 current-head routing profile

Date: 2026-06-17T10:33:00Z

Head: `e5903aa83 fix(math): correct f128 ABI for rounding + sqrt + fma (bd-9z5ikz batch 2)`

Reason: reprofile current `origin/main` after the kept remote pass183 `strcpy_4096` certified scan-copy lever plus f128 ABI batches. `ts1` is offline, so this pass used local `rch` with `RCH_REQUIRE_REMOTE=0` and a crate-scoped target directory.

## Command

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass184-target-20260617T1021 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' \
  --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log: `target/perf-logs/bd-2g7oyh-pass184-primary.log`

Log SHA-256: `a79314dbacea61efe235554ddf214104de1520d638bf683b753e9002267eaef3`

## Primary rows

| Profile | FrankenLibC p50/mean ns | Host p50/mean ns | Route |
| --- | ---: | ---: | --- |
| `memchr_absent` | `30.484 / 33.324` | `19.714 / 21.498` | largest, but fresh mask/SWAR rejection streak; do not repeat |
| `strcpy_4096` | `58.064 / 59.222` | `41.574 / 45.555` | still material, but fresh pass183 certified scan-copy keep |
| `memmove_4096` | `42.821 / 43.817` | `36.705 / 37.926` | material but fresh pass171 route-out |
| `memcmp_256` | `5.484 / 6.255` | `4.132 / 4.919` | small and fresh pass170 route-out |
| `memset_4096` | `38.542 / 41.351` | `35.271 / 36.537` | next tractable non-fresh target |
| `memcmp_4096` | `47.109 / 53.428` | `44.684 / 46.660` | small/fresh route-out |
| `log` | `352.093 / 486.328` | `328.000 / 340.689` | p50 small, mean tail needs focused confirmation before edit |
| `powf_irrational` | `403.065 / 410.972` | `388.870 / 395.185` | small/no edit |
| `strlen_4096` | `18.878 / 21.782` | `21.102 / 22.435` | faster than host |
| `printf_g_6` | `127.767 / 137.250` | `150.940 / 155.774` | faster than host |
| `log2` | `179.413 / 185.710` | `320.500 / 350.800` | faster than host |
| `log10` | `401.287 / 414.853` | `525.269 / 527.712` | faster than host |
| `exp10` | `327.979 / 343.519` | `332.257 / 342.574` | parity/no edit |
| `log1p` | `438.001 / 462.779` | `488.563 / 509.363` | faster than host |
| `exp10f` | `274.824 / 279.264` | `323.250 / 339.020` | faster than host |
| `log10f` | `159.148 / 166.719` | `340.533 / 348.478` | faster than host |
| `log2f` | `159.077 / 165.716` | `312.456 / 325.382` | faster than host |

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
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `c506824bbc9d1919cb2143c307a583ba053d405214d76611eec3e34e0e71adc0`

Validation:

```bash
git diff --exit-code -- crates/frankenlibc-core crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Result: passed.

## Verdict

ROUTING ONLY. Score `0.0` because no implementation lever was attempted.

Next route: focus `memset_4096` with a library-lowering primitive (`slice::fill`/backend memset exposure) because the larger `memchr_absent`, `strcpy_4096`, `memmove_4096`, and `memcmp_256` rows are fresh no-repeat lanes.
