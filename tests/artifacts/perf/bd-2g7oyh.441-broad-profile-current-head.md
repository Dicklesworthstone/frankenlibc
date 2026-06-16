# bd-2g7oyh.441 current-head broad profile

Date: 2026-06-16
Agent: BoldFalcon
Status: routing evidence

## Target

Reprofile current pushed head `c724ca593` in clean detached worktree
`/data/projects/.scratch/frankenlibc-perf-boldfalcon-20260616` after the
pass 147 `strncasecmp_256_equal` focused no-code route-out.

The main checkout had peer-owned iconv/Cargo/beads changes, so this pass did
not touch that tree.

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass148-broad-target-20260616T1953
CRITERION_HOME=/data/tmp/frankenlibc-pass148-broad-criterion-20260616T1953
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_ --noplot --sample-size 40 --warm-up-time 0.5
--measurement-time 2
```

RCH selected worker `ovh-a`; the run completed remote-only in about 609
seconds.

## Residuals

| row | impl | Criterion interval | p50 ns | mean ns |
| --- | --- | --- | ---: | ---: |
| `memchr_absent` | FrankenLibC | `[27.237 ns 27.385 ns 27.580 ns]` | 27.445 | 28.951 |
| `memchr_absent` | host glibc | `[17.848 ns 18.106 ns 18.390 ns]` | 18.000 | 19.736 |
| `strcpy_4096` | FrankenLibC | `[60.952 ns 61.264 ns 61.655 ns]` | 61.661 | 68.192 |
| `strcpy_4096` | host glibc | `[44.685 ns 45.067 ns 45.512 ns]` | 45.151 | 48.151 |
| `memcmp_256` | FrankenLibC | `[4.8427 ns 4.8731 ns 4.9086 ns]` | 4.896 | 6.448 |
| `memcmp_256` | host glibc | `[3.4332 ns 3.4602 ns 3.5017 ns]` | 3.448 | 4.470 |
| `strncmp_256_equal` | FrankenLibC | `[5.0299 ns 5.0627 ns 5.0971 ns]` | 5.035 | 6.658 |
| `strncmp_256_equal` | host glibc | `[4.2559 ns 4.2864 ns 4.3373 ns]` | 4.272 | 5.031 |
| `exp10` | FrankenLibC | `[511.21 ns 514.87 ns 518.92 ns]` | 512.321 | 527.978 |
| `exp10` | host glibc | `[402.39 ns 406.91 ns 413.61 ns]` | 404.132 | 413.553 |
| `exp10f` | FrankenLibC | `[386.83 ns 387.98 ns 388.90 ns]` | 383.722 | 396.048 |
| `exp10f` | host glibc | `[311.77 ns 317.29 ns 323.38 ns]` | 333.992 | 336.679 |
| `lgamma` | FrankenLibC | `[651.91 ns 721.14 ns 779.44 ns]` | 773.446 | 731.517 |
| `lgamma` | host glibc | `[469.96 ns 485.70 ns 508.89 ns]` | 501.210 | 613.275 |

Closed or lower-priority rows:

- `strlen_4096`: FrankenLibC p50/mean `16.438/21.829 ns`; host
  `32.079/35.603 ns`.
- `strcmp_256_equal`, `memcmp_16`, `scanf_hex_long`, `strtol`, `strtoul`,
  `malloc_free_64`, `malloc_cache_pressure_256`, `malloc_free_large`,
  `printf_*`, `qsort`, `strspn`, `strpbrk`, `strrchr_absent`,
  `memmem_absent`, `strstr_absent`, `strcasestr_absent`, `wcsstr_absent`,
  `fnmatch_*`, `mbsrtowcs_ascii`, and `wcsrtombs_ascii` were faster than host.
- `memcpy_4096`, `memset_4096`, `memcmp_4096`, `strchr_absent`,
  `strncasecmp_256_equal`, and `memmove_4096` were small or noisy enough to
  need focused confirmation before any source edit.
- `exp_wide` includes both the shipped `frankenlibc_core` row and the
  benchmark-only `frankenlibc_old_libm` row; the visible residual in this run
  was the old-libm comparison, so it is not first route evidence for production
  source without a focused production-label gate.

## Routing

`memchr_absent` is the first focused route because it is the largest clean
string residual on this broad run. It also has prior same-worker broad-to-focus
collapses and exhausted micro-lever families, so this pass does not authorize a
source edit by itself.

Admissible next step: focused same-worker `ovh-a` baseline for
`glibc_baseline_memchr_absent`. If that gate reproduces a material p50 and mean
gap, only a genuinely different generated-code or backend-dispatch primitive is
allowed. Panel width changes, wider folded blocks, indexed folded scans, SWAR
word-group scans, resolver retuning, exact-4096 dispatch shuffling, and slice
`contains` certificates remain no-retry families.

No source code changed in this pass.
