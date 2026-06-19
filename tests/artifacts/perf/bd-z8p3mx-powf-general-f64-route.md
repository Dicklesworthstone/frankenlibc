# bd-z8p3mx — general `powf` fused glibc kernel — MEASURED WIN (near glibc parity)

**Target:** fl `powf`'s general/irrational case deferred to `libm::powf`
(~2.5x slower than glibc; the bead's named root cause).

**Outcome (two stages, both committed):**

1. **f64 `exp(y·ln x)` route** (commit `58bc688d5`): replaced the `libm::powf`
   fallback with `exp(y*ln(x))` in f64 using fl's fast f64 `exp`/`log`.
   Measured 1.4–1.6x faster than libm, ≤1 ULP, but still ~3.9x slower than
   glibc (two f64 transcendentals for one f32 result).

2. **Fused single-pass f32 kernel** (this commit, supersedes stage 1): ported
   ARM optimized-routines `powf.c` + tables (the same algorithm glibc ships as
   `__ieee754_powf`, 0.82 ULP) as `powf_fused_general` and placed it first for
   positive-normal bases (ahead of the old `exp2f/log2f` medium box and the
   exponent-1.337 grid, which it supersedes). **Result: 4.8x faster than libm,
   within ~1.23x of glibc, and bit-exact (0 ULP) vs glibc.**

## Results (p50 ns/op, batch of 64 f32 inputs, rch `ovh-a`)

### Stage 2 — fused kernel, reordered (final)

| case | fl (fused) | fl_old (libm) | glibc | fl/fl_old | fl/glibc |
|------|-----------:|--------------:|------:|----------:|---------:|
| general_big_e     | 9.27 | 44.98 | 7.53 | **0.206** | 1.23 |
| general_small_1p7 | 9.23 | 44.89 | 7.51 | **0.206** | 1.23 |
| general_big_pi    | 9.26 | 44.78 | 7.60 | **0.205** | 1.22 |
| medium_ref_1p7    | 9.41 | 43.73 | 7.52 | **0.215** | 1.25 |

Progression at `general_big_e` p50: libm 45.0 ns → f64 route 30.9 ns → fused
12.9 ns (fused placed last) → **9.27 ns (fused placed first)**, vs glibc 7.5 ns.
Placing the fused kernel ahead of the int/medium fast-path gauntlet shaved the
remaining ~3.6 ns of per-call branch overhead and also halved the medium-box
path (18.9 → 9.4 ns), since the fused kernel now serves that domain too.

The residual ~1.23x is irreducible Rust call + a couple of finite/int branch
checks vs glibc's hand-tuned leaf assembly; the algorithm and accuracy are
identical.

## The fused kernel

`crates/frankenlibc-core/src/math/float32.rs`: `powf_log2_inline` (16-entry
table + degree-5 poly) and `powf_exp2_inline` (32-entry table + degree-3 poly),
ported verbatim from ARM-software/optimized-routines (`math/powf.c`,
`powf_log2_data.c`, `exp2f_data.c`; SPDX MIT OR Apache-2.0). Constants stored as
exact IEEE-754 bit patterns (Rust has no hex-float literals), converted with
Python `float.fromhex`. **Transcription bug caught by the gate:** the exp2
reduction `SHIFT` must be `0x1.8p+52 / 32` (`0x42e8…`), not `0x1.8p+52`
(`0x4338…`) — the wrong value produced 5370/6981 inputs > 4 ULP; the corrected
value gives 0 ULP across the grid.

Used only for positive **normal** finite base + finite exponent with
`|y·log2 x| < 126`; overflow/underflow, subnormal/zero/negative bases, and
non-finite inputs defer to `libm::powf` so the errno-setting ABI layer keeps
exact FE_OVERFLOW/FE_UNDERFLOW/EDOM/ERANGE semantics. The small-integer-exponent
path stays ahead of the kernel (correctly rounded `x^n`).

## Conformance (all GREEN, host glibc 2.42)

- New gate `conformance_diff_powf_general` (6981 general-domain inputs):
  **0 ULP — bit-exact vs glibc** (it is glibc's algorithm). Overflow/underflow/
  subnormal pairs asserted for exact inf/0 classification.
- `diff_powf_profile_exp_1_337_within_4_ulps`: pass (1.337 inputs now flow
  through the fused kernel, still bit-exact).
- `powf_underflow_{positive,negative}_exponent_sets_range_errno`: pass.
- `conformance_diff_fp_exceptions`: pass.
- (Pre-existing, unrelated: `diff_sign_min_max_dim_helpers_*` fail on clean HEAD
  too — `fminf`/`fmaxf`/`fdimf`, not touched here.)

## Method

```
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
rch exec -- cargo bench -p frankenlibc-bench --bench powf_glibc_bench -- \
  --measurement-time 2 --warm-up-time 1 --noplot
```
Bench `powf_glibc_bench.rs`: `fl` (`math::powf`), `fl_old` (`libm::powf`),
`glibc` (host `powf`, no fl ABI linked so no interposition). Closes
`bd-fused-f32-powf-kernel`.
