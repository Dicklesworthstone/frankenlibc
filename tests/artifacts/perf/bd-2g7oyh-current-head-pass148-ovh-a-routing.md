# bd-2g7oyh.430 / Pass 148 current-head broad routing profile

Date: 2026-06-16
Agent: BoldFalcon
Worker: ovh-a
Head: 6aa651000f7a9564552ad46b0e0e25b76943bf55
Status: routing-only, no source change

## Command

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1 \
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=2400 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass148-broad-target-20260616T1955 \
CRITERION_HOME=/data/tmp/frankenlibc-pass148-broad-criterion-20260616T1955 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_ --noplot --sample-size 40 --warm-up-time 0.5 --measurement-time 2
```

RCH completed remotely on `ovh-a` in about 612 seconds.

## Evidence Caveat

The shared checkout was dirty with unrelated `Cargo.toml`, iconv, and scratch/probe-test changes. Treat this table as routing evidence only. Any source optimization requires a clean detached worktree at `origin/main`, a same-worker focused RCH baseline, behavior proof, and a same-worker post benchmark before keep/reject.

The current bead id `bd-2g7oyh.430` also collides with older historical perf notes in the progress file. This artifact is therefore named by pass/current-head instead of by bead id.

## Material Residuals

| Row | FrankenLibC p50/mean | Host p50/mean | Route |
| --- | ---: | ---: | --- |
| `strlen_4096` | `24.870 / 27.625 ns` | `18.289 / 23.390 ns` | Focus only if clean same-worker gate reproduces; prior public-inline keep and AVX2-width rejection constrain repeat levers. |
| `memmove_4096` | `36.408 / 38.155 ns` | `30.445 / 32.822 ns` | Material but prior copy-panel/exact-4096 families require generated/disassembly-backed primitive before source work. |
| `memcpy_4096` | `43.510 / 46.645 ns` | `32.888 / 36.085 ns` | Prior focused gates on ovh-a/vmi collapsed below edit threshold; screen only after stronger clean evidence. |
| `exp10` | `504.262 / 535.975 ns` | `403.961 / 416.626 ns` | Prior focused collapses/rejections mean only generated underlying `exp2`/range-reduction primitive is admissible. |
| `exp10f` | `381.091 / 382.223 ns` | `332.390 / 334.713 ns` | Same constraint as `exp10`; avoid surface table/profile-band repeats. |
| `erfc` | `1124.625 / 1027.994 ns` | `686.272 / 698.632 ns` | Prior focused `erfc` gate collapsed; rerun focused only before a new minimax/rational primitive. |
| `memchr_absent` | `19.771 / 21.665 ns` | `17.620 / 19.376 ns` | Smaller gap; many prior no-repeat scan families. |
| `strcpy_4096` | `56.476 / 57.064 ns` | `46.134 / 53.101 ns` | Mean is weak and prior codegen screen found current terminal path already lowers to `llvm.memcpy`. |
| `strncmp_256_equal` | `5.430 / 6.480 ns` | `4.883 / 6.073 ns` | Small gap after prior exact-window keep; not first target. |

## Closed/Not First Targets

- Allocator rows are faster or tied on this worker: `malloc_free_64` p50 is essentially equal and mean favors FrankenLibC.
- `strchr_absent`, `strrchr_absent`, `strcmp_256_equal`, `memcmp_16`, qsort, scanf/strtol, substring, fnmatch, and most printf/wide rows are faster than host.
- `strncasecmp_256_equal` is watch-only: broad center/p50 favored host, but the prior focused pass showed FrankenLibC faster.
- Most math rows are faster than host; the current durable math residual family is still `exp10`/`exp10f`, not `pow`, `exp`, `log2`, or `exp2`.

## Next Route

Use a clean detached worktree and run a same-worker focused baseline on `strlen_4096` first because it is a no-gaps string-scan row with the strongest current broad p50 residual. If it collapses, close no-code and switch to `exp10f`/`exp10` only through a generated underlying-kernel primitive; do not repeat prior surface table, profile-band, or lane-reshaping families.

Behavior proof for this pass is identity: no source changed, so ordering, tie-breaking, floating-point behavior, RNG behavior, allocation behavior, and golden outputs are unchanged by construction.
