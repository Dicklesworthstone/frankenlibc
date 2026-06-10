# bd-2g7oyh pass 54 broad profile

Date: 2026-06-10
Agent: BoldFalcon
Status: ROUTING EVIDENCE

## Command

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass54-broad-profile-target-20260610T1842 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
--noplot --sample-size 30 --warm-up-time 1 --measurement-time 2
```

RCH selected `vmi1227854`; remote build `29879662679165318`.

## Routing Rows

| profile | FrankenLibC p50 ns | FrankenLibC mean ns | host p50 ns | host mean ns | route |
| --- | ---: | ---: | ---: | ---: | --- |
| `fnmatch_bracket` | 121.438 | 127.655 | 90.413 | 94.919 | selected for focused gate |
| `strncasecmp_256_equal` | 11.562 | 13.406 | 9.415 | 11.137 | follow-up candidate |
| `memcmp_4096` | 51.503 | 57.188 | 46.528 | 51.686 | follow-up candidate |
| `strlen_4096` | 24.938 | 26.430 | 20.976 | 24.344 | recent rejected/restored lane |
| `memmove_4096` | 31.947 | 33.591 | 28.160 | 32.048 | recent no-code lane |
| `strcpy_4096` | 50.309 | 64.013 | 41.921 | 44.110 | recent rejected/restored lane |
| `malloc_free_64` | 6.121 | 7.703 | 4.324 | 6.443 | focused-collapsed under `.326` |
| `malloc_free_256` | 6.099 | 7.663 | 3.614 | 5.750 | focused-collapsed under `.323` |
| `pow_irrational` | 892.039 | 918.545 | 659.071 | 660.979 | peer-owned pow lane |
| `powf_irrational` | 537.700 | 535.197 | 443.801 | 447.665 | peer-owned pow lane |

## Faster Or Non-target Rows

Representative rows where FrankenLibC was already faster or not a clean route:
`memcpy_4096`, `strcmp_256_equal`, `scanf_hex_long`, `strtol_long`,
`strtol_short`, `strtol_hex_long`, `strtoul_long`, `strtoul_hex_long`,
`scanf_long`, `malloc_free_large`, `printf_f_6`, `qsort_128_i32`,
`strchr_absent`, `strrchr_absent`, `strspn_long`, `memmem_absent`,
`strstr_absent`, `strcasestr_absent`, `wcsstr_absent`,
`fnmatch_adversarial`, `fnmatch_pathname`, `mbsrtowcs_ascii`, and
`wcsrtombs_ascii`.

## Decision

Open `bd-2g7oyh.327` for a focused same-worker `fnmatch_bracket` gate. If the
focused gap reproduces materially, the only admissible primitive is a
structurally different safe-Rust predecoded or branchless bracket-class path for
small repeated literal bracket atoms under the existing iterative star
backtracker.

Excluded repeated micro-routes: allocator metadata/layout/lifecycle work, recent
copy/string scan families, peer-owned pow work, and peer-owned `strncmp`.
