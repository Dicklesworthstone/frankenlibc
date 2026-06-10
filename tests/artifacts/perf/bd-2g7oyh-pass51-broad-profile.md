# bd-2g7oyh pass 51 broad profile

Date: 2026-06-10
Agent: BoldFalcon
Worker: `ovh-a`
Source commit: `35527fc1`

## Command

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass51-broad-profile-target-20260610T1821 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
'glibc_baseline_(memcpy_4096|memset_4096|strlen_4096|strcmp_256_equal|memcmp_4096|malloc_free_64|malloc_free_256|malloc_free_large|qsort_128_i32|strchr_absent|strncmp_256_equal|strncasecmp_256_equal|memmove_4096|strrchr_absent|strcpy_4096|memchr_absent|strspn_long|strpbrk_absent|strcasestr_absent|memmem_absent|strstr_absent|strtol_short|printf_float|fnmatch_bracket|math/(log2f|tanhf|expm1f|exp10f|pow|powf))' \
--noplot --sample-size 30 --warm-up-time 1 --measurement-time 2
```

RCH selected `ovh-a`.

## Routing Rows

| profile row | FrankenLibC p50 ns | host p50 ns | p50 ratio | FrankenLibC mean ns | host mean ns | route |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `memcpy_4096` | 42.857 | 34.214 | 1.253x | 56.371 | 38.631 | selected for focused gate |
| `memmove_4096` | 45.837 | 32.353 | 1.417x | 50.483 | 46.361 | excluded: fresh focused no-code closeout under `bd-2g7oyh.314`; only revisit with material focused gate and non-panel primitive |
| `strcpy_4096` | 46.431 | 39.828 | 1.166x | 71.441 | 52.276 | excluded: fresh source-lever rejection under `bd-2g7oyh.322` |
| `fnmatch_bracket` | 98.136 | 86.199 | 1.138x | 110.447 | 101.254 | excluded: fresh focused no-code closeout under `bd-2g7oyh.317` |
| `log2f` | 316.183 | 291.209 | 1.086x | 350.200 | 296.445 | excluded: prior focused no-code closeout; small p50 gap |
| `malloc_free_64` | 8.530 | 6.557 | 1.301x | 9.982 | 7.386 | excluded: allocator focused gate just collapsed; do not reopen without material focused evidence |
| `malloc_free_256` | 5.380 | 4.678 | 1.150x | 6.365 | 6.839 | excluded: mean already faster; `bd-2g7oyh.323` closed no-code |
| `memset_4096` | 41.135 | 40.565 | 1.014x | 42.711 | 44.839 | no target |
| `strlen_4096` | 27.846 | 28.154 | 0.989x | 34.877 | 37.067 | no target |
| `strtol_short` | 6.658 | 13.301 | 0.501x | 7.672 | 16.159 | no target; recent keep holds |
| `qsort_128_i32` | 614.398 | 2255.000 | 0.272x | 632.357 | 2493.247 | no target |
| `strspn_long` | 49.307 | 127.266 | 0.387x | 62.823 | 151.132 | no target |
| `strpbrk_absent` | 165.991 | 185.803 | 0.893x | 170.510 | 188.325 | no target |
| `expm1f` | 186.895 | 476.844 | 0.392x | 188.754 | 444.796 | no target |
| `tanhf` | 268.062 | 353.616 | 0.758x | 300.285 | 355.414 | no target; recent keep holds |

Peer-owned exclusions:

- `pow*` and `powf*` remain covered by the active `MossyFern` parity-risk lane.
- `strncmp_256_equal` remains covered by the active `SilverCedar` lane even though this broad profile did not show a gap.

## Decision

Open/focus `bd-2g7oyh.324` for `memcpy_4096`, but require a focused same-worker
baseline before any source edit. Prior no-ship families are exact full-slice
branching (`bd-2g7oyh.44`) and exact 4096 portable-SIMD tiled copy
(`bd-2g7oyh.274`).
