# bd-2g7oyh: strtol 0x-prefixed hex fast path

Date: 2026-06-21
Agent: cod-a / BlackThrush

## Lever

`strtol("0xdeadbeef", endptr, 16)` was the only numeric parser row that still
showed a loss in the fresh `hz2` scorecard: 16.08 ns vs glibc 13.38 ns
(1.20x). The deployed parser already had a positive base-16 fast path, but the
0x-prefixed case still entered the generic positive-hex parser and paid the
prefix branch plus `Option` digit decoding in the hot loop.

The kept change adds a monomorphic positive `0x`/`0X` branch:

- prove the prefix and at least one following hex digit before dispatch;
- start parsing at `ptr + 2`;
- use a sentinel byte digit decoder (`0xff` invalid) in the hot loop;
- keep the exact existing overflow, endptr, and fallback behavior.

## Validation

```text
rustfmt --edition 2024 --check crates/frankenlibc-abi/src/stdlib_abi.rs
git diff --check -- crates/frankenlibc-abi/src/stdlib_abi.rs
```

Both passed.

```text
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test conformance_strtol_family --test strtol_family_differential_fuzz \
  -- --nocapture --test-threads=1
```

Remote `ovh-a`: `conformance_strtol_family` passed; differential fuzz compared
1,000,000 cases against host glibc with 0 divergences.

## Benchmark

Acceptance command:

```text
AGENT_NAME=cod-a RCH_WORKER=hz2 RCH_REQUIRE_REMOTE=1 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench --profile release -- --noplot \
  --sample-size 20 --warm-up-time 0.5 --measurement-time 1
```

`rch` selected `ovh-a` despite the `hz2` hint, so old-vs-new should not be read
against the earlier `hz2` baseline. The same-run host-glibc ratio is the keep
proof.

| Workload | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `strtol_dec_short` | 3.19 ns | 5.98 ns | 0.53x | WIN |
| `strtol_dec_long` | 6.65 ns | 12.87 ns | 0.52x | WIN |
| `strtol_hex` | 8.81 ns | 12.93 ns | 0.68x | WIN |
| `atoi_short` | 3.46 ns | 7.12 ns | 0.49x | WIN |
| `atoi_long` | 8.63 ns | 13.80 ns | 0.63x | WIN |
| `atol_short` | 3.23 ns | 6.26 ns | 0.52x | WIN |
| `atol_long` | 8.42 ns | 13.15 ns | 0.64x | WIN |
| `atoll_short` | 3.00 ns | 6.26 ns | 0.48x | WIN |
| `atoll_long` | 8.19 ns | 13.08 ns | 0.63x | WIN |
| `strtod_int` | 8.61 ns | 23.76 ns | 0.36x | WIN |
| `strtod_simple` | 20.07 ns | 44.40 ns | 0.45x | WIN |
| `strtod_sci` | 14.77 ns | 31.48 ns | 0.47x | WIN |
| `rand` | 3.05 ns | 4.45 ns | 0.69x | WIN |
| `getenv_hit` | 10.26 ns | 14.50 ns | 0.71x | WIN |
| `getenv_miss` | 13.75 ns | 29.11 ns | 0.47x | WIN |
| `clock_gettime` | 19.80 ns | 18.98 ns | 1.04x | NEUTRAL |
| `time` | 3.42 ns | 2.13 ns | 1.60x | LOSS |
| `pthread_self` | 1.70 ns | 1.70 ns | 1.00x | NEUTRAL |

Scorecard: 15 WIN / 2 NEUTRAL / 1 LOSS.

Residual route: `time(NULL)` remains a real loss, but adjacent vDSO readiness,
direct-pointer cache, and timing fast-path split families were already rejected
with conformance-green reversions. Do not retry those micro-families.
