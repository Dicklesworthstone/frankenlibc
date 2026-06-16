# bd-2g7oyh.441 - pass159 current-head broad routing profile

Date: 2026-06-16
Agent: BoldFalcon
Worker: vmi1227854
Head: 7b6aae8508a03a5ccf2ec6192b841fa60e778a46

## Command

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 RCH_BUILD_SLOTS=1 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass159-broad-target-vmi1227854 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass159-broad-criterion-vmi1227854 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_ --noplot --sample-size 40 --warm-up-time 0.5 --measurement-time 2 \
  2>&1 | tee /data/tmp/frankenlibc-pass159-broad-vmi1227854.log
```

RCH completed successfully:

```text
[RCH] remote vmi1227854 (658.7s)
```

Log SHA-256:

```text
dc1f58ca6b8cd18f838d626ab71f788360fe246fd433adcccb6aa20af462a88d  /data/tmp/frankenlibc-pass159-broad-vmi1227854.log
```

## Slower rows

Rows are p50/mean nanoseconds, FrankenLibC versus host glibc.

| Benchmark | Family | FrankenLibC | Host | Ratio p50/mean |
| --- | --- | ---: | ---: | ---: |
| glibc_baseline_math/powf_irrational | math/powf | 480.267 / 494.673 | 423.121 / 439.768 | 1.135 / 1.125 |
| glibc_baseline_strcpy_4096/strcpy_4096 | string/strcpy | 62.253 / 66.420 | 46.275 / 49.940 | 1.345 / 1.330 |
| glibc_baseline_memcmp_4096/memcmp | string/memcmp | 46.463 / 55.022 | 40.940 / 42.206 | 1.135 / 1.304 |
| glibc_baseline_math/log | math/log | 350.562 / 366.397 | 349.381 / 359.584 | 1.003 / 1.019 |
| glibc_baseline_math/exp10 | math/exp10 | 345.274 / 353.814 | 338.866 / 349.997 | 1.019 / 1.011 |
| glibc_baseline_memcmp_256/memcmp | string/memcmp | 4.803 / 8.280 | 3.422 / 4.761 | 1.404 / 1.739 |
| glibc_baseline_malloc_free_256/malloc_free_256 | malloc/malloc/free | 7.052 / 8.524 | 4.998 / 6.763 | 1.411 / 1.260 |
| glibc_baseline_memset_4096/memset_4096 | string/memset | 21.370 / 23.631 | 20.683 / 22.073 | 1.033 / 1.071 |
| glibc_baseline_strlen_4096/strlen_4096 | string/strlen | 20.058 / 24.650 | 21.197 / 23.314 | 0.946 / 1.057 |
| glibc_baseline_strncmp_256_equal/strncmp_256_equal | string/strncmp | 4.375 / 7.971 | 5.817 / 6.936 | 0.752 / 1.149 |
| glibc_baseline_memcpy_4096/memcpy_4096 | string/memcpy | 30.524 / 32.594 | 29.048 / 31.649 | 1.051 / 1.030 |
| glibc_baseline_malloc_free_64/malloc_free_64 | malloc/malloc/free | 5.240 / 7.614 | 4.661 / 6.672 | 1.124 / 1.141 |
| glibc_baseline_memchr_absent/memchr_absent | string/memchr | 25.079 / 25.773 | 22.786 / 25.954 | 1.101 / 0.993 |
| glibc_baseline_memcmp_16/memcmp | string/memcmp | 2.212 / 3.333 | 2.046 / 3.628 | 1.081 / 0.919 |
| glibc_baseline_memmove_4096/memmove_4096 | string/memmove | 35.688 / 37.878 | 34.591 / 39.956 | 1.032 / 0.948 |
| glibc_baseline_math/erfc | math/erfc | 823.734 / 812.131 | 784.144 / 872.914 | 1.050 / 0.930 |

Faster rows counted by parser: 56.

## Routing decision

Verdict: ROUTING ONLY. Score: 0.0.

No implementation source changed. Behavior is unchanged by identity: ordering, tie-breaking, floating-point behavior, RNG state, allocation behavior, errno, locale, and existing golden outputs are not touched by this pass.

The next focused gate is `glibc_baseline_math/powf_irrational`. It is the top current absolute residual on the same worker after pass158 resolved `printf_g_6`.

No-repeat constraints for nearby rows:

- `strcpy_4096` is a recent no-code/codegen-blocked lane; do not retry copy-shape, scan-certificate, public-wrapper inline, terminal-split, or NUL-certificate families without a genuinely new generated/backend primitive.
- `memcmp_4096` and `memcmp_256` require generated/codegen-backed load/test evidence rather than another surface foldback or panel-width edit.
- `powf_irrational` must receive its own focused same-worker RCH baseline before source inspection or edit. If it reproduces, use a deeper generated underlying `log2f`/`exp2f` or proof-carrying range-split primitive, not coefficient retuning.
