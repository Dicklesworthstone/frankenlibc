# bd-fused-f64-pow-exp-log-kernels — fused f64 kernels — exp2 DONE (WIN)

Extending the proven f32 fused-kernel recipe to the double-precision family.

## exp2 (f64) — MEASURED WIN

fl's f64 `exp2` was a pure `libm::exp2` passthrough (no fast path). Ported the
ARM optimized-routines `exp2.c` table kernel (glibc `__ieee754_exp2`, 0.507 ULP)
into `crates/frankenlibc-core/src/math/exp.rs` as `exp2_kernel` + the 256-u64
`__exp_data.tab` (N=128) + `exp2_poly` + `exp2_shift = 0x1.8p+52/128`. The
256-entry table was extracted **programmatically** from the verbatim source with
Python (zero manual transcription). Routed for the normal-result interior
(`MIN_POSITIVE <= |x| < 1022`); denormal-tiny / overflow / underflow / inf / nan
defer to `libm::exp2` for exact FE/errno.

### Results (p50 ns/op, batch of 64 f64 inputs in [-10, 10), rch worker)

| impl | p50 | mean |
|------|----:|-----:|
| fl (fused) | 3.27 | 3.54 |
| fl_old (libm) | 4.12 | 4.52 |
| glibc | 5.43 | 9.27 |

- fl/glibc = **0.60x (1.66x faster)** · fl/libm = **0.80x (1.25x faster)** — WIN
  vs both. (Same `math::` inlining caveat as the f32 kernels; the robust result
  is the libm win + glibc-identical algorithm.)

### Conformance (host glibc 2.42)

`conformance_diff_exp2_f64_general`: ≤4 ULP over 221 546 interior inputs,
**worst = 1 ULP** at exp2(-1020.88) (a near-subnormal result; the 1 ULP is
FMA-vs-non-FMA — glibc's exp2 is built with FMA, the Rust kernel uses separate
mul/add — not a transcription error). Boundary/special inputs exact.

## Remaining

`exp` (f64, general tail = libm; common case already wins via the medium fast
path) and `pow` (f64, general/irrational = `libm::pow`; the high-value but
largest port — needs `__pow_log_data` 128-entry double-double log table). The
`__exp_data` table is now in-tree and reusable for the f64 `exp` port.
