# bd-2g7oyh.439 current-head broad profile

Date: 2026-06-16
Agent: BoldFalcon
Status: routing evidence

## Target

Reprofile current pushed head `be42845b1` after the `bd-2g7oyh.438`
`memcmp_256` rejection and the peer `strlen_4096` keep.

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass143-broad-target-20260616T0417
CRITERION_HOME=/data/tmp/frankenlibc-pass143-broad-criterion-20260616T0417
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_ --noplot --sample-size 40 --warm-up-time 0.5
--measurement-time 2
```

RCH selected worker `vmi1227854`; the run completed remote-only in about
715 seconds.

## Residuals

| row | impl | Criterion interval | p50 ns | mean ns |
| --- | --- | --- | ---: | ---: |
| `strcpy_4096` | FrankenLibC | `[57.441 ns 59.418 ns 62.728 ns]` | 58.182 | 60.678 |
| `strcpy_4096` | host glibc | `[29.197 ns 29.797 ns 30.443 ns]` | 32.950 | 34.366 |
| `malloc_free_64` | FrankenLibC | `[6.9307 ns 7.3447 ns 7.8457 ns]` | 7.413 | 10.338 |
| `malloc_free_64` | host glibc | `[4.1545 ns 4.4710 ns 4.8702 ns]` | 4.727 | 7.210 |
| `malloc_free_256` | FrankenLibC | `[6.3909 ns 6.5975 ns 6.8448 ns]` | 6.245 | 7.805 |
| `malloc_free_256` | host glibc | `[4.1336 ns 4.4544 ns 4.9137 ns]` | 4.400 | 6.342 |
| `strncasecmp_256_equal` | FrankenLibC | `[11.128 ns 11.356 ns 11.573 ns]` | 11.365 | 12.802 |
| `strncasecmp_256_equal` | host glibc | `[7.4231 ns 7.8770 ns 8.3243 ns]` | 8.055 | 9.516 |
| `memchr_absent` | FrankenLibC | `[24.468 ns 26.472 ns 28.670 ns]` | 24.835 | 27.516 |
| `memchr_absent` | host glibc | `[19.546 ns 20.011 ns 20.495 ns]` | 20.773 | 22.833 |
| `lgamma` | FrankenLibC | broad row | 543.703 | 562.540 |
| `lgamma` | host glibc | broad row | 450.516 | 466.460 |

Closed or lower-priority rows:

- `strlen_4096`: FrankenLibC `[19.182 ns 19.437 ns 19.740 ns]`,
  p50/mean `19.778/28.219 ns`; host `[20.893 ns 21.683 ns 22.390 ns]`,
  p50/mean `19.979/22.199 ns`.
- `memmove_4096`: FrankenLibC p50/mean `30.643/33.892 ns`; host
  `29.673/33.945 ns`.
- `memcmp_4096`: FrankenLibC p50/mean `44.621/47.325 ns`; host
  `42.511/47.582 ns`.
- `memset_4096`, `strcmp_256_equal`, `memcmp_16`, stdlib/scanf, and most
  wide/printf rows were faster than host or not material first targets.

## Routing

`strcpy_4096` was screened first because it was the largest string residual.
The current codegen already contains the kept terminal-bulk-copy path and the
remaining obvious edits repeat documented no-retry families, so the next route
is `strncasecmp_256_equal` after the allocator hot-cycle screen.

No source code changed in this pass.

