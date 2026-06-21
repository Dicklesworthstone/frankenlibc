# bd-2g7oyh.500 strtod short fixed-decimal fast path

Date: 2026-06-21
Agent: cod-a / BlackThrush
Bead: bd-2g7oyh.500

## Target

Current-head routing bench on `vmi1227854` exposed the remaining stdlib parse loss:

```text
strtod_simple: fl=61.30ns glibc=37.47ns fl/glibc=1.64
clock_gettime: fl=30.51ns glibc=25.84ns fl/glibc=1.18
time: fl=4.40ns glibc=2.51ns fl/glibc=1.75
```

The integer-valued `strtod` cases already used the deployed ABI transducer and won:

```text
strtod_int: fl=6.92ns glibc=17.63ns fl/glibc=0.39
strtod_sci: fl=17.12ns glibc=26.52ns fl/glibc=0.65
```

## Lever

Extend the private deployed `strtod` C-string transducer from exact integer-valued decimals to a bounded short fixed-decimal subset. The final kept version scans the C string once, recognizes short no-exponent decimals such as `3.14159`, then passes only the already-scanned token to Rust's correctly-rounded `f64` parser. Hex, NaN/Inf, overflow, exponent-rewind, and large rounded cases stay on the full parser.

Rejected subvariants:

- Reciprocal multiply (`acc as f64 * 1e-k`) was faster-shaped but failed conformance by 1 ULP on `3.14159`, `3.14159xyz`, `0.3`, and `1.005`.
- Divide-by-pow10 was conformance-clean but still measured as `strtod_simple` 68.47 ns vs glibc 62.95 ns, ratio 1.09x LOSS, on `vmi1227854`.

## Conformance

Command:

```bash
AGENT_NAME=cod-a BR_AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test strtod_strtof_live_differential_probe -- --nocapture --test-threads=1
```

Final safe variant result:

```text
strtod/strtof: 8073 inputs, 0 divergences vs host glibc
test result: ok. 1 passed; 0 failed
```

## Benchmark

Command:

```bash
AGENT_NAME=cod-a BR_AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1 RCH_WORKER=ovh-a \
  RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot --sample-size 10 \
  --warm-up-time 1 --measurement-time 2
```

Final same-run rows:

```text
strtol_dec_short: fl=3.03ns glibc=6.02ns fl/glibc=0.50
strtol_dec_long: fl=8.37ns glibc=17.07ns fl/glibc=0.49
strtol_hex: fl=9.91ns glibc=12.94ns fl/glibc=0.77
atoi_short: fl=3.04ns glibc=7.16ns fl/glibc=0.42
atoi_long: fl=10.93ns glibc=14.15ns fl/glibc=0.77
atol_short: fl=2.83ns glibc=6.29ns fl/glibc=0.45
atol_long: fl=11.46ns glibc=13.23ns fl/glibc=0.87
atoll_short: fl=2.61ns glibc=6.29ns fl/glibc=0.41
atoll_long: fl=10.71ns glibc=13.02ns fl/glibc=0.82
strtod_int: fl=9.24ns glibc=23.73ns fl/glibc=0.39
strtod_simple: fl=20.29ns glibc=43.94ns fl/glibc=0.46
strtod_sci: fl=15.12ns glibc=31.18ns fl/glibc=0.48
rand: fl=1.95ns glibc=4.46ns fl/glibc=0.44
getenv_hit: fl=8.64ns glibc=14.30ns fl/glibc=0.60
getenv_miss: fl=15.47ns glibc=29.29ns fl/glibc=0.53
clock_gettime: fl=24.50ns glibc=19.60ns fl/glibc=1.25
time: fl=3.42ns glibc=1.91ns fl/glibc=1.79
pthread_self: fl=1.70ns glibc=1.70ns fl/glibc=1.00
```

Scorecard: 15 WIN / 1 NEUTRAL / 2 LOSS.

## Decision

Keep. The target `strtod_simple` gap is closed in the final same-run head-to-head (`0.46x` vs glibc) while exact integer/scientific paths remain wins. The residual losses are unrelated `clock_gettime`/`time`; do not retry the prior vDSO pointer-cache family without a different primitive.
