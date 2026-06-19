# bd-fused-f64-pow-exp-log-kernels — fused f64 kernels — exp2 DONE (WIN)

Extending the proven f32 fused-kernel recipe to the double-precision family.

## exp2 (f64) — MEASURED WIN

fl's f64 `exp2` was a pure `libm::exp2` passthrough (no fast path). Ported the
ARM optimized-routines `exp2.c` table kernel (glibc `__ieee754_exp2`, 0.507 ULP)
into `crates/frankenlibc-core/src/math/exp.rs` as `exp2_kernel` + the 256-u64
`__exp_data.tab` (N=128) + `exp2_poly` + `exp2_shift = 0x1.8p+52/128`,
embedded as exact IEEE bit patterns. Routed for the normal-result interior
(`MIN_POSITIVE <= |x| < 1022`); denormal-tiny / overflow / underflow / inf / nan
defer to `libm::exp2` for exact FE/errno.

### Results (dedicated p50 ns/op, batch of 64 f64 inputs in [-10, 10))

Command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
rch exec -- cargo bench -p frankenlibc-bench --bench exp2_f64_glibc_bench -- \
  --sample-size 60 --measurement-time 2 --warm-up-time 1 --noplot
```

| impl | p50 | mean |
|------|----:|-----:|
| fl (fused) | 2.4008 | 2.5758 |
| fl_old (libm) | 3.0104 | 3.3109 |
| glibc | 4.8920 | 7.7200 |

- fl/glibc = **0.491x p50** / **0.334x mean**.
- fl/libm = **0.798x p50** / **0.778x mean**.
- Verdict: **WIN** vs both. (Same `math::` inlining caveat as the f32 kernels; the robust result
  is the libm win + glibc-identical algorithm.)

### Standard repo harness check

Command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench glibc_baseline_bench -- \
  'glibc_baseline_math/(exp2|log2|pow_irrational)|glibc_baseline_math_abi/exp2_abi' \
  --sample-size 60 --measurement-time 2 --warm-up-time 1 --noplot
```

| row | FrankenLibC p50 / mean | glibc p50 / mean | ratio p50 / mean | verdict |
|---|---:|---:|---:|---|
| `glibc_baseline_math/exp2` core | 163.950 / 162.282 ns | 621.670 / 651.402 ns | 0.264x / 0.249x | WIN |
| `glibc_baseline_math_abi/exp2_abi` deployed ABI | 610.605 / 656.530 ns | 662.209 / 657.528 ns | 0.922x / 0.998x | WIN p50 / NEUTRAL mean |
| `glibc_baseline_math/log2` route guard | 157.811 / 175.384 ns | 566.407 / 597.321 ns | 0.279x / 0.294x | WIN |
| `glibc_baseline_math/pow_irrational` route guard | 320.143 / 325.648 ns | 900.884 / 876.537 ns | 0.355x / 0.372x | WIN |

The exp2 port does not change `pow_medium_log2_exp2_fast_path`; that path still
uses `libm::exp2(exponent * libm::log2(base))` by design because prior inline
log2+external-exp2 experiments regressed the real pow row. The current subtask
therefore closes f64 `exp2`; full f64 `pow` remains the larger fused log+exp port.

### Conformance (host glibc 2.42)

`conformance_diff_exp2_f64_general`: ≤4 ULP over 221 546 interior inputs,
**worst = 1 ULP** at exp2(-1020.88) (a near-subnormal result; the 1 ULP is
FMA-vs-non-FMA — glibc's exp2 is built with FMA, the Rust kernel uses separate
mul/add — not a transcription error). Boundary/special inputs exact.

Validation:

- `cargo test -p frankenlibc-abi --test conformance_diff_exp2_f64_general -- --nocapture`: 1 passed.
- The two `rch` benchmarks above both completed successfully on `vmi1227854`.
- After the final clippy cleanup of the range guard, a dedicated final-source
  sanity run on `ovh-a` confirmed the same shape: fused core 2.1742 ns p50 /
  2.3905 ns mean, old libm 2.6395 / 2.7566, host glibc 4.4255 / 6.7257.
- Known unrelated warning debt remains in core iconv/regex and ABI math/poll/signal/erf tables.

## Remaining

`exp` (f64, general tail = libm; common case already wins via the medium fast
path) and `pow` (f64, general/irrational = `libm::pow`; the high-value but
largest port — needs `__pow_log_data` 128-entry double-double log table). The
`__exp_data` table is now in-tree and reusable for the f64 `exp` port.
