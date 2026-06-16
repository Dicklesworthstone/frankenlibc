# bd-2g7oyh.437 - current-head broad routing profile

Date: 2026-06-16
Agent: BoldFalcon
Worker: `vmi1227854`
Target: current pushed head after `bd-2g7oyh.436`
Verdict: ROUTING ONLY

## Command

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass140-broad-target-20260616T0330 CRITERION_HOME=/data/tmp/frankenlibc-pass140-broad-criterion-20260616T0330 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_ --noplot --sample-size 40 --warm-up-time 0.5 --measurement-time 2
```

RCH completed successfully on `vmi1227854` in about 662 seconds.

## Residual Rows

Rows below are routing evidence only. Each source edit still requires a focused
same-worker baseline on the exact target before implementation.

| Row | FrankenLibC | Host | Notes |
| --- | --- | --- | --- |
| `memcpy_4096` | p50/mean `32.047/39.879 ns` | p50/mean `27.184/29.091 ns` | Modest residual; prior exact full-slice and SIMD tiled copy families rejected or collapsed. |
| `memcmp_256` | Criterion `[4.5776 ns 4.5945 ns 4.6145 ns]`, p50/mean `4.571/6.011 ns` | Criterion `[3.0406 ns 3.1271 ns 3.2120 ns]`, p50/mean `3.170/4.320 ns` | Selected for the next focused gate. |
| `memcmp_4096` | p50/mean `44.517/47.129 ns` | p50/mean `41.815/42.788 ns` | Small residual. |
| `memmove_4096` | p50/mean `28.784/31.833 ns` | p50/mean `25.540/26.793 ns` | Small to moderate residual; prior exact/full-slice/chunk families rejected or collapsed. |
| `strcpy_4096` | Criterion `[56.040 ns 58.253 ns 59.932 ns]`, p50/mean `52.919/56.780 ns` | Criterion `[28.110 ns 29.347 ns 30.572 ns]`, p50/mean `29.932/31.729 ns` | Strong residual, but prior repeated micro-families are exhausted. Needs generated/backend-dispatch terminal/no-overlap primitive. |
| `memchr_absent` | Criterion `[28.194 ns 28.448 ns 28.667 ns]`, p50/mean `28.149/29.522 ns` | Criterion `[20.782 ns 21.474 ns 22.097 ns]`, p50/mean `20.353/22.033 ns` | Strong residual, but exact dispatch, contains, wider, and tiered scans are no-retry. Needs generated/vector primitive. |
| `exp10` | p50/mean `377.672/386.922 ns` | p50/mean `347.516/367.427 ns` | Small residual; surface variants rejected. Needs generated `exp2` if revisited. |

Most math rows were faster than host on this pass, including `exp`, `sin`,
`cos`, `log`, `log2`, `exp2`, `pow`, `powf`, and the f32 rows. Many string
scan, substring, `fnmatch`, and wide-character rows were also faster than host.

## Route

Next focused target: `bd-2g7oyh.438` / `glibc_baseline_memcmp_256`.

The chosen route was still profile-backed, but the allowed primitive family was
narrow: avoid retrying the prior slice-lexicographic, foldback/two-128, wrapper
inline, and safe native-word panel families. The next candidate must prove its
emitted load/test sequence before it can be retained.
