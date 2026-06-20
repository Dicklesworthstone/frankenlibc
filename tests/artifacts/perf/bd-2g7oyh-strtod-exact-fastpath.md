# bd-2g7oyh strtod exact-integer fast path

## Lever

Add a deployed `strtod` fast path for decimal tokens that normalize to an
exactly representable integer within the `f64` 53-bit mantissa range. The path
fuses whitespace/sign scan, decimal significand scan, optional exponent
normalization, and `endptr` consumption. Fractional, rounded, hex, NaN/Inf,
overflow, and extreme exponent cases fall back to the existing core parser.

This targets the measured deployed losses:

- `strtod_int` (`"12345"`)
- `strtod_sci` (`"1.234567e10"`)

The existing `strtod_simple` fractional row already beat glibc and remains on
the full parser.

## Baseline

Command:

`AGENT_NAME=cod-a FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 RCH_BUILD_SLOTS=1 RCH_VISIBILITY=summary rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- --noplot --sample-size 10 --warm-up-time 1 --measurement-time 2`

Worker: `vmi1152480`

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 7.31 ns | 8.00 ns | 0.91x | WIN |
| `strtol_dec_long` | 20.48 ns | 17.02 ns | 1.20x | LOSS |
| `strtol_hex` | 19.25 ns | 16.54 ns | 1.16x | LOSS |
| `atoi_short` | 3.25 ns | 9.85 ns | 0.33x | WIN |
| `atoi_long` | 8.83 ns | 17.40 ns | 0.51x | WIN |
| `atol_short` | 3.10 ns | 8.45 ns | 0.37x | WIN |
| `atol_long` | 8.86 ns | 16.05 ns | 0.55x | WIN |
| `atoll_short` | 3.13 ns | 9.13 ns | 0.34x | WIN |
| `atoll_long` | 8.90 ns | 16.49 ns | 0.54x | WIN |
| `strtod_int` | 38.73 ns | 35.21 ns | 1.10x | LOSS |
| `strtod_simple` | 53.14 ns | 69.35 ns | 0.77x | WIN |
| `strtod_sci` | 68.09 ns | 49.20 ns | 1.38x | LOSS |
| `rand` | 3.49 ns | 5.92 ns | 0.59x | WIN |
| `getenv_hit` | 39.93 ns | 20.69 ns | 1.93x | LOSS |
| `getenv_miss` | 60.13 ns | 26.16 ns | 2.30x | LOSS |
| `clock_gettime` | 35.56 ns | 25.63 ns | 1.39x | LOSS |
| `time` | 4.44 ns | 2.45 ns | 1.81x | LOSS |
| `pthread_self` | 2.38 ns | 1.88 ns | 1.27x | LOSS |

## Candidate

Same bench command. RCH selected `hz1`; treat old/new nanoseconds as
cross-worker, but the ratio-vs-glibc rows are still head-to-head on the same
machine for each function.

| Workload | FrankenLibC | glibc | Ratio | Verdict | Action |
|---|---:|---:|---:|---|---|
| `strtol_dec_short` | 9.66 ns | 10.81 ns | 0.89x | WIN | Sentinel; unchanged source family. |
| `strtol_dec_long` | 27.76 ns | 18.52 ns | 1.50x | LOSS | Existing residual; not touched. |
| `strtol_hex` | 20.13 ns | 18.52 ns | 1.09x | LOSS | Existing residual; not touched. |
| `atoi_short` | 4.03 ns | 9.88 ns | 0.41x | WIN | Sentinel; unchanged source family. |
| `atoi_long` | 11.43 ns | 19.44 ns | 0.59x | WIN | Sentinel; unchanged source family. |
| `atol_short` | 3.72 ns | 8.96 ns | 0.41x | WIN | Sentinel; unchanged source family. |
| `atol_long` | 11.42 ns | 18.82 ns | 0.61x | WIN | Sentinel; unchanged source family. |
| `atoll_short` | 3.72 ns | 8.65 ns | 0.43x | WIN | Sentinel; unchanged source family. |
| `atoll_long` | 11.42 ns | 18.52 ns | 0.62x | WIN | Sentinel; unchanged source family. |
| `strtod_int` | 11.73 ns | 34.89 ns | 0.34x | WIN | Keep exact-integer fast path. |
| `strtod_simple` | 55.85 ns | 65.76 ns | 0.85x | WIN | Fallthrough stays winning. |
| `strtod_sci` | 20.09 ns | 45.58 ns | 0.44x | WIN | Keep exact-integer fast path. |
| `rand` | 3.15 ns | 6.38 ns | 0.49x | WIN | Sentinel; unchanged source family. |
| `getenv_hit` | 47.49 ns | 20.56 ns | 2.31x | LOSS | Existing residual; not touched. |
| `getenv_miss` | 74.01 ns | 29.20 ns | 2.54x | LOSS | Existing residual; not touched. |
| `clock_gettime` | 35.78 ns | 30.54 ns | 1.17x | LOSS | Existing residual; not touched. |
| `time` | 4.94 ns | 3.10 ns | 1.60x | LOSS | Existing residual; not touched. |
| `pthread_self` | 2.17 ns | 2.47 ns | 0.88x | WIN | Sentinel; unchanged source family. |

## Correctness

`AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -j 1 -p frankenlibc-abi --test strtod_strtof_live_differential_probe strtod_strtof_live_vs_glibc -- --nocapture --test-threads=1`

RCH selected `vmi1227854`. Result: `strtod/strtof: 8071 inputs, 0 divergences vs host glibc`.

The live battery now includes exact-integer fast-path cases (`12345`,
`1.234567e10`, `-0e10`) and malformed exponent consumption (`1e+`), comparing
value bits, `endptr` offset, and `ERANGE` behavior against host glibc.

## Verdict

Keep. The targeted `strtod_int` row moved from a measured loss (1.10x vs glibc)
to a 0.34x win, and `strtod_sci` moved from a 1.38x loss to a 0.44x win. The
fractional row remained a win through the existing full parser.

The remaining red rows in this bench are not caused by this lever: long/hex
`strtol`, `getenv`, `clock_gettime`, and `time` still need separate work.
