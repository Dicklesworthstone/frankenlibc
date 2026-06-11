# bd-2g7oyh pass 72 broad profile

Date: 2026-06-11
Agent: BoldFalcon
Worker: `vmi1153651`
Source commit: `d16e46a7`
Status: routing evidence only

Note: this artifact filename was created before upstream landed pass 71 as
`bd-2g7oyh.343` for `strcpy_4096`; the `log2f` bead was renumbered to
`bd-2g7oyh.344` during integration.

## Command

```text
RCH_WORKER=vmi1293453 RCH_PREFERRED_WORKER=vmi1293453 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass71-broad-profile-20260611 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
--noplot --sample-size 30 --warm-up-time 1 --measurement-time 2
```

RCH selected `vmi1153651`.

## Routing Rows

| profile row | FrankenLibC p50 ns | host p50 ns | p50 ratio | FrankenLibC mean ns | host mean ns | route |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `log2f` | 739.233 | 476.835 | 1.550x | 905.478 | 496.611 | selected for focused gate `bd-2g7oyh.344`; prior `.316` collapsed on another worker, so source edit required same-worker proof first |
| `exp10f` | 667.769 | 476.123 | 1.403x | 701.770 | 487.213 | excluded: prior `.275` focused miss; revisit only with fresh focused gate after `log2f` route |
| `exp10` | 739.000 | 606.843 | 1.218x | 783.041 | 606.867 | excluded: prior `.334` focused miss |
| `strlen_4096` | 46.831 | 40.729 | 1.150x | 62.916 | 47.912 | excluded: prior dual-512 rejection; needs codegen/disassembly-level new primitive |
| `malloc_free_64` | 10.990 | 8.324 | 1.320x | 14.713 | 10.173 | excluded: pass 70 just screened allocator; only larger slab/LIFO plus lazy observability artifact is admissible |
| `malloc_free_256` | 9.932 | 8.322 | 1.194x | 12.539 | 9.933 | allocator family excluded as above |
| `memcmp_4096` | 74.940 | 69.728 | 1.075x | 79.196 | 75.650 | excluded: pass 69 load-shape lever rejected; needs materially different codegen/load-test artifact |
| `strncmp_256_equal` | 13.167 | 11.047 | 1.192x | 16.113 | 13.610 | excluded: peer-owned by SilverCedar (`bd-2g7oyh.65`) |
| `pow_irrational` | 3060.314 | 1597.975 | 1.915x | 3032.386 | 1700.313 | excluded: peer-owned by MossyFern (`bd-2g7oyh.125`) |
| `powf_irrational` | 1305.681 | 931.265 | 1.402x | 1346.053 | 983.898 | excluded: peer-owned pow lane |

Rows where FrankenLibC was already faster or effectively tied were not targeted:
`scanf_hex_long`, `scanf_long`, `strtol_*`, `strtoul_*`, `printf_g_6`,
`qsort_128_i32`, `strchr_absent`, `strrchr_absent`, `strpbrk_absent`,
`memchr_absent`, `exp`, `sin`, `cos`, `sinh`, `cosh`, `tanh`, `log10`,
`expm1`, `log1p`, `tan`, `atan`, `asinh`, `erf`, `tgamma`, `lgamma`,
`exp_wide`, `memmem_absent`, `strstr_absent`, `strcasestr_absent`,
`wcsstr_absent`, `fnmatch_adversarial`, `fnmatch_pathname`, `mbsrtowcs_ascii`,
and `wcsrtombs_ascii`.

## Decision

Open/focus `bd-2g7oyh.344` for `log2f`, but require a focused same-worker
baseline before any source edit. The admissible source route is a true f32
reduced-domain/minimax-style primitive, not the already rejected f64 widening
route.
