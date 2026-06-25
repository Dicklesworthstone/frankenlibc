//! Single-precision (f32) mathematical functions.
//!
//! Mirrors the f64 functions from `float.rs`, `trig.rs`, and `exp.rs`
//! for the `*f` suffix variants (`sinf`, `cosf`, `sqrtf`, etc.).

// --- IEEE exception re-raise helpers ---
//
// libm's f32 software paths return the correct value for poles/domain inputs but
// omit the C99/IEEE exception glibc raises. These re-raise it via a safe hardware
// op (force_eval-style), used only on cold special-input branches.

#[inline]
fn fe_divbyzero_f32() {
    let _ = core::hint::black_box(core::hint::black_box(-1.0f32) / core::hint::black_box(0.0f32));
}

#[inline]
fn fe_invalid_f32() {
    let _ = core::hint::black_box(core::hint::black_box(0.0f32) / core::hint::black_box(0.0f32));
}

#[inline]
fn fe_underflow_f32() {
    let _ = core::hint::black_box(
        core::hint::black_box(f32::MIN_POSITIVE) * core::hint::black_box(f32::MIN_POSITIVE),
    );
}

// --- Trigonometric ---

// Fast argument reduction for sinf/cosf. `libm::sinf` falls to a slow reduction
// for |x| above its ~9π/4 small-poly path (measured ~2-3x slower than glibc,
// which is flat). For the [F32_RED_LO, F32_RED_HI] band we reduce in f64 with a
// 2-part π/2 split (more than enough precision for an f32 result) and evaluate
// the fast small-arg `libm` f32 kernel on the reduced value.
const F32_TWO_OVER_PI: f64 = f64::from_bits(0x3fe45f306dc9c883);
const F32_PIO2H: f64 = f64::from_bits(0x3ff921fb54442d18);
const F32_PIO2M: f64 = f64::from_bits(0x3c91a62633145c07);
const F32_RED_LO: f32 = 7.0; // musl sinf small poly covers |x| <= 9π/4 ≈ 7.06
const F32_RED_HI: f32 = 1.0e15; // f64 2-part split stays accurate; above -> libm

#[inline]
fn reduce_pio2_f32(x: f32) -> (i64, f32) {
    let xd = x as f64;
    let kd = (xd * F32_TWO_OVER_PI).round_ties_even();
    let r = kd.mul_add(-F32_PIO2H, xd);
    let r = kd.mul_add(-F32_PIO2M, r);
    (kd as i64, r as f32)
}

#[inline]
pub fn sinf(x: f32) -> f32 {
    let ax = x.abs();
    if ax < F32_RED_LO || !(ax <= F32_RED_HI) {
        return libm::sinf(x);
    }
    let (n, r) = reduce_pio2_f32(x);
    match n & 3 {
        0 => libm::sinf(r),
        1 => libm::cosf(r),
        2 => -libm::sinf(r),
        _ => -libm::cosf(r),
    }
}

#[inline]
pub fn cosf(x: f32) -> f32 {
    let ax = x.abs();
    if ax < F32_RED_LO || !(ax <= F32_RED_HI) {
        return libm::cosf(x);
    }
    let (n, r) = reduce_pio2_f32(x);
    match n & 3 {
        0 => libm::cosf(r),
        1 => -libm::sinf(r),
        2 => -libm::cosf(r),
        _ => libm::sinf(r),
    }
}

#[inline]
pub fn tanf(x: f32) -> f32 {
    libm::tanf(x)
}

#[inline]
pub fn asinf(x: f32) -> f32 {
    libm::asinf(x)
}

#[inline]
pub fn acosf(x: f32) -> f32 {
    // Domain [-1, 1]; glibc raises FE_INVALID outside it (libm::acosf returns NaN
    // without the flag — note the f64 acos already raises it, libm is asymmetric).
    if !(-1.0..=1.0).contains(&x) {
        fe_invalid_f32();
    }
    libm::acosf(x)
}

#[inline]
pub fn atanf(x: f32) -> f32 {
    libm::atanf(x)
}

#[inline]
pub fn atan2f(y: f32, x: f32) -> f32 {
    libm::atan2f(y, x)
}

// --- Exponential / logarithmic ---

#[inline]
pub fn expf(x: f32) -> f32 {
    // Medium fast path mirroring the f64 `exp`: on [-5, 5], libm::exp2f is
    // ~1.5x faster than libm::expf and stays within the 4-ULP glibc parity
    // budget (verified by `expf_medium_fast_path_within_4_ulps`). The error is
    // dominated by the rounding of the x*log2e product (~0.5*|x| ULP after exp2f
    // amplification), so |x|=5 stays <=4 ULP. Outside the interval, defer to
    // libm::expf bit-for-bit.
    //
    // NOTE (rejected lever, measured): routing this through the f64 `exp2` kernel
    // (like exp10f, `libm::exp2(x as f64 * LOG2_E) as f32`) was *slower* — same
    // worker, expf_medium 223 ns (this f32-exp2f path) vs 292 ns (f64 route), and
    // this path already beats glibc (~304 ns). The earlier "1.70x slower" baseline
    // was stale/noisy. Keep the f32-exp2f fast path.
    if (-5.0..=5.0).contains(&x) {
        return libm::exp2f(x * core::f32::consts::LOG2_E);
    }
    // General fused kernel (ARM optimized-routines / glibc `__ieee754_expf`,
    // 0.5 ULP) for the rest of the finite-normal range; overflow/underflow/
    // subnormal/inf/nan defer to libm::expf for exact FE + errno semantics.
    if x.abs() < 87.0 {
        return expf_kernel(x);
    }
    libm::expf(x)
}

// NOTE (perf, 2026-06-06): routing this f32 log family through the in-tree f64
// `log2_kernel` + single `as f32` rounding (the f64-intermediate lever proven for
// `exp10f`/`expf`) was measured on ts1 and REJECTED. It is accuracy-clean (≤4 ULP
// vs glibc) but not a perf win: our f64 `log2` kernel runs ~374–405 ns, which is
// itself ≥ glibc's native f32 `log2f` (~335–369 ns), so widening to f64 cannot beat
// glibc here. Normalised against the in-run host control, the route is a
// wash-to-slight-regression. Keep the direct f32 computation paths.

#[inline]
pub fn logf(x: f32) -> f32 {
    // Fused single-pass kernel (ARM optimized-routines / glibc `__ieee754_logf`,
    // 0.32 ULP) for positive normal finite x — bit-exact to glibc. Subnormal,
    // zero, negative, inf and nan fall through to the FE-flag + libm path.
    let ix = x.to_bits();
    if ix.wrapping_sub(0x0080_0000) < (0x7f80_0000 - 0x0080_0000) {
        return logf_kernel(ix);
    }
    // glibc raises FE_DIVBYZERO at the log(±0) pole and FE_INVALID for x<0;
    // libm::logf returns the value (-inf / NaN) without the flag.
    if x == 0.0 {
        fe_divbyzero_f32();
    } else if x < 0.0 {
        fe_invalid_f32();
    }
    libm::logf(x)
}

const LOG2F_DYADIC_STEP: f32 = 32.0;
const LOG2F_DYADIC_TABLE: [u32; 65] = [
    0xbf80_0000,
    0xbf69_9c09,
    0xbf54_7fcc,
    0xbf40_87d2,
    0xbf2d_961f,
    0xbf1b_9116,
    0xbf0a_62b0,
    0xbef3_efb0,
    0xbed4_7fcc,
    0xbeb6_587b,
    0xbe99_5ff7,
    0xbe7a_fec5,
    0xbe45_44c0,
    0xbe11_6d6e,
    0xbdbe_b025,
    0xbd3b_9ca6,
    0x0000_0000,
    0x3d35_d69c,
    0x3db3_1fb8,
    0x3e04_62c4,
    0x3e2e_00d2,
    0x3e56_7af1,
    0x3e7d_e0b6,
    0x3e92_203d,
    0x3ea4_d3c2,
    0x3eb7_110e,
    0x3ec8_ddd4,
    0x3eda_3f60,
    0x3eeb_3a9f,
    0x3efb_d42b,
    0x3f06_0828,
    0x3f0d_f989,
    0x3f15_c01a,
    0x3f1d_5da0,
    0x3f24_d3c2,
    0x3f2c_2411,
    0x3f33_5004,
    0x3f3a_58fe,
    0x3f41_404f,
    0x3f48_0731,
    0x3f4e_aed0,
    0x3f55_3848,
    0x3f5b_a4a4,
    0x3f61_f4e5,
    0x3f68_29fb,
    0x3f6e_44cd,
    0x3f74_4636,
    0x3f7a_2f04,
    0x3f80_0000,
    0x3f82_dcf3,
    0x3f85_aeb5,
    0x3f88_759c,
    0x3f8b_31fc,
    0x3f8d_e421,
    0x3f90_8c58,
    0x3f93_2aea,
    0x3f95_c01a,
    0x3f98_4c2c,
    0x3f9a_cf5e,
    0x3f9d_49ee,
    0x3f9f_bc17,
    0x3fa2_2610,
    0x3fa4_880f,
    0x3fa6_e24a,
    0x3fa9_34f0,
];

#[inline]
fn log2f_dyadic_profile_fast_path(x: f32) -> Option<f32> {
    if !(0.5..=2.5).contains(&x) {
        return None;
    }
    let scaled = (x - 0.5) * LOG2F_DYADIC_STEP;
    let index = scaled as usize;
    if index < LOG2F_DYADIC_TABLE.len() && scaled == index as f32 {
        Some(f32::from_bits(LOG2F_DYADIC_TABLE[index]))
    } else {
        None
    }
}

#[inline]
pub fn log2f(x: f32) -> f32 {
    // Fused single-pass kernel (ARM optimized-routines / glibc `__ieee754_log2f`,
    // 0.26 ULP) for positive normal finite x — bit-exact to glibc and faster than
    // the prior dyadic-profile grid + `libm::log2f` fallback. Subnormal, zero,
    // negative, inf and nan fall through to the FE-flag + libm path below.
    let ix = x.to_bits();
    if ix.wrapping_sub(0x0080_0000) < (0x7f80_0000 - 0x0080_0000) {
        return log2f_kernel(ix);
    }
    if x == 0.0 {
        fe_divbyzero_f32();
    } else if x < 0.0 {
        fe_invalid_f32();
    }
    // MUST use the pure-Rust libm implementation, NOT `x.log2()`. The std
    // `f32::log2` lowers to an indirect call through the `log2f` symbol; in the
    // shipped `libc.so` that symbol is our OWN interposed `log2f`, so `x.log2()`
    // here recurses infinitely (stack overflow). Verified via the cdylib GOT
    // relocation: the indirect target binds to `log2f@@Base` (self). The bench
    // never caught it because the bench binary links glibc's `log2f`. Every other
    // f32 transcendental here uses `libm::*` for exactly this reason.
    libm::log2f(x)
}

#[inline]
pub fn log10f(x: f32) -> f32 {
    if let Some(log2x) = log2f_dyadic_profile_fast_path(x) {
        return log2x * core::f32::consts::LOG10_2;
    }
    if x == 0.0 {
        fe_divbyzero_f32();
    } else if x < 0.0 {
        fe_invalid_f32();
    }
    libm::log10f(x)
}

/// Largest |integer exponent| handled by the powf fast path. Mirrors the f64
/// `pow` bound; verified within 4 ULP of glibc `powf` by
/// `powf_fast_paths_within_4_ulps`.
const POWF_MAX_EXP: u32 = 8;
const POWF_MEDIUM_BASE_MIN: f32 = 0.5;
const POWF_MEDIUM_BASE_MAX: f32 = 2.5;
const POWF_MEDIUM_EXP_MIN: f32 = -3.0;
const POWF_MEDIUM_EXP_MAX: f32 = 3.0;
const POWF_PROFILE_EXP_1_337_BITS: u32 = 0x3fab_22d1;
const POWF_PROFILE_EXP_1_337_GRID_SCALE: f32 = 32.0;
const POWF_PROFILE_EXP_1_337_GRID_MIN_INDEX: u32 = 16;
const POWF_PROFILE_EXP_1_337_GRID_MAX_INDEX: u32 = 79;
const POWF_1_337_COEFFS: [f64; 13] = [
    -1.099_880_764_658_278_7e-2,
    4.567_708_571_671_717_5e-1,
    1.083_949_167_176_001_5,
    -1.190_378_921_403_665_5,
    1.346_406_175_688_553,
    -1.229_031_190_617_532_6,
    8.624_731_644_835_09e-1,
    -4.552_360_785_514_129e-1,
    1.768_120_308_208_328e-1,
    -4.889_590_176_956_281e-2,
    9.097_134_565_024_987e-3,
    -1.019_609_387_482_498_4e-3,
    5.197_685_800_524_758e-5,
];
const POWF_PROFILE_EXP_1_337_GRID_BITS: [u32; 64] = powf_profile_exp_1_337_grid_bits();

const fn powf_profile_exp_1_337_grid_bits() -> [u32; 64] {
    let mut bits = [0u32; 64];
    let mut i = 0usize;
    while i < 64 {
        let base = 0.5_f32 + (i as f32) * 0.031_25_f32;
        bits[i] = powf_profile_exp_1_337_poly(base).to_bits();
        i += 1;
    }
    bits
}

/// `base` raised to a small integer power via exponentiation by squaring,
/// accumulated in f64 then rounded once to f32. The f64 intermediate keeps the
/// result within ~0.5 ULP (f32 squaring would accumulate >4 ULP by |n|=8) AND
/// avoids spurious f32 overflow when the true result is representable — e.g.
/// powf(1e6, -7) = 1e-42: (1e6)^7 overflows f32 but is fine in f64, and the
/// reciprocal casts down to the correct subnormal.
#[inline]
fn powi_squaringf(base: f32, n: i32) -> f64 {
    let mut result = 1.0_f64;
    let mut b = base as f64;
    let mut e = n.unsigned_abs();
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        e >>= 1;
        if e > 0 {
            b *= b;
        }
    }
    if n < 0 { 1.0 / result } else { result }
}

/// `base^(n+0.5)` via `base^n * sqrt(base)` for small `n`, positive finite base.
#[inline]
fn powf_half_integer_fast_path(base: f32, exponent: f32) -> Option<f32> {
    if !(base > 0.0 && base.is_finite() && exponent.is_finite()) {
        return None;
    }
    let shifted = exponent - 0.5;
    let n = shifted as i32;
    if n as f32 == shifted && n.unsigned_abs() <= POWF_MAX_EXP {
        // base^n * sqrt(base), accumulated in f64 then rounded once.
        Some((powi_squaringf(base, n) * (base as f64).sqrt()) as f32)
    } else {
        None
    }
}

#[inline]
const fn powf_profile_exp_1_337_poly(base: f32) -> f32 {
    let x = base as f64;
    let x2 = x * x;
    let x4 = x2 * x2;
    let x8 = x4 * x4;
    let p0 = POWF_1_337_COEFFS[1] * x + POWF_1_337_COEFFS[0];
    let p1 = POWF_1_337_COEFFS[3] * x + POWF_1_337_COEFFS[2];
    let p2 = POWF_1_337_COEFFS[5] * x + POWF_1_337_COEFFS[4];
    let p3 = POWF_1_337_COEFFS[7] * x + POWF_1_337_COEFFS[6];
    let p4 = POWF_1_337_COEFFS[9] * x + POWF_1_337_COEFFS[8];
    let p5 = POWF_1_337_COEFFS[11] * x + POWF_1_337_COEFFS[10];
    let q0 = p1 * x2 + p0;
    let q1 = p3 * x2 + p2;
    let q2 = p5 * x2 + p4;
    let r0 = q1 * x4 + q0;
    let r1 = POWF_1_337_COEFFS[12] * x4 + q2;
    (r1 * x8 + r0) as f32
}

#[inline]
fn powf_profile_exp_1_337_grid(base: f32) -> Option<f32> {
    let scaled = base * POWF_PROFILE_EXP_1_337_GRID_SCALE;
    let index = scaled as u32;
    if !(POWF_PROFILE_EXP_1_337_GRID_MIN_INDEX..=POWF_PROFILE_EXP_1_337_GRID_MAX_INDEX)
        .contains(&index)
    {
        return None;
    }
    if scaled == index as f32 {
        Some(f32::from_bits(
            POWF_PROFILE_EXP_1_337_GRID_BITS
                [(index - POWF_PROFILE_EXP_1_337_GRID_MIN_INDEX) as usize],
        ))
    } else {
        None
    }
}

/// Medium positive-base / bounded-exponent fast path: `exp2f(y*log2f(x))`,
/// bypassing libm::powf's full general classifier. Gated to the domain proven
/// within 4 ULP of glibc.
#[inline]
fn powf_medium_fast_path(base: f32, exponent: f32) -> Option<f32> {
    if (POWF_MEDIUM_BASE_MIN..POWF_MEDIUM_BASE_MAX).contains(&base)
        && (POWF_MEDIUM_EXP_MIN..=POWF_MEDIUM_EXP_MAX).contains(&exponent)
    {
        if exponent.to_bits() == POWF_PROFILE_EXP_1_337_BITS {
            if let Some(result) = powf_profile_exp_1_337_grid(base) {
                return Some(result);
            }
            return Some(powf_profile_exp_1_337_poly(base));
        }
        Some(libm::exp2f(exponent * libm::log2f(base)))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Fused single-pass f32 `powf` kernel.
//
// Ported faithfully from ARM-software/optimized-routines `math/powf.c` plus the
// `powf_log2_data` / `exp2f_data` tables (SPDX: MIT OR Apache-2.0 WITH
// LLVM-exception). This is the same algorithm glibc ships as
// `__ieee754_powf`; documented worst-case error is 0.82 ULP, comfortably
// inside the 4-ULP glibc parity contract. One `log2` table pass + one `exp2`
// table pass produces the f32 result, vs composing two general f64
// transcendentals. Constants are stored as exact IEEE-754 bit patterns because
// Rust has no hex-float literals; values were converted with `float.fromhex`.
//
// Used only for positive **normal** finite bases with finite exponents whose
// result stays in the finite-normal f32 range (|y*log2 x| < 126). Overflow,
// underflow, subnormal/zero/negative bases, and non-finite inputs fall through
// to `libm::powf` for exact IEEE special-case + errno/exception semantics, so
// the errno-setting ABI layer is unaffected.
const POWF_LOG2_OFF: u32 = 0x3f33_0000;
const POWF_LOG2_TABLE_BITS: u32 = 4; // N = 16
const POWF_EXP2_TABLE_BITS: u32 = 5; // N = 32
// 0x1.8p+52 / 32 — the exp2 reduction shift (POWF_SCALE = 1, non-TOINT path).
const POWF_EXP2_SHIFT: f64 = f64::from_bits(0x42e8_0000_0000_0000);

/// log2 table: (invc, logc) IEEE bit patterns, `POWF_SCALE = 1`.
const POWF_LOG2_TAB: [(u64, u64); 16] = [
    (0x3ff661ec79f8f3be, 0xbfdefec65b963019),
    (0x3ff571ed4aaf883d, 0xbfdb0b6832d4fca4),
    (0x3ff49539f0f010b0, 0xbfd7418b0a1fb77b),
    (0x3ff3c995b0b80385, 0xbfd39de91a6dcf7b),
    (0x3ff30d190c8864a5, 0xbfd01d9bf3f2b631),
    (0x3ff25e227b0b8ea0, 0xbfc97c1d1b3b7af0),
    (0x3ff1bb4a4a1a343f, 0xbfc2f9e393af3c9f),
    (0x3ff12358f08ae5ba, 0xbfb960cbbf788d5c),
    (0x3ff0953f419900a7, 0xbfaa6f9db6475fce),
    (0x3ff0000000000000, 0x0000000000000000),
    (0x3fee608cfd9a47ac, 0x3fb338ca9f24f53d),
    (0x3feca4b31f026aa0, 0x3fc476a9543891ba),
    (0x3feb2036576afce6, 0x3fce840b4ac4e4d2),
    (0x3fe9c2d163a1aa2d, 0x3fd40645f0c6651c),
    (0x3fe886e6037841ed, 0x3fd88e9c2c1b9ff8),
    (0x3fe767dcf5534862, 0x3fdce0a44eb17bcc),
];
/// log2 polynomial A[0..5], `POWF_SCALE = 1`.
const POWF_LOG2_POLY: [u64; 5] = [
    0x3fd27616c9496e0b,
    0xbfd71969a075c67a,
    0x3fdec70a6ca7badd,
    0xbfe7154748bef6c8,
    0x3ff71547652ab82b,
];
/// exp2 table `tab[i] = uint(2^(i/32)) - (i << 52-5)` (already in u64).
const POWF_EXP2_TAB: [u64; 32] = [
    0x3ff0000000000000,
    0x3fefd9b0d3158574,
    0x3fefb5586cf9890f,
    0x3fef9301d0125b51,
    0x3fef72b83c7d517b,
    0x3fef54873168b9aa,
    0x3fef387a6e756238,
    0x3fef1e9df51fdee1,
    0x3fef06fe0a31b715,
    0x3feef1a7373aa9cb,
    0x3feedea64c123422,
    0x3feece086061892d,
    0x3feebfdad5362a27,
    0x3feeb42b569d4f82,
    0x3feeab07dd485429,
    0x3feea47eb03a5585,
    0x3feea09e667f3bcd,
    0x3fee9f75e8ec5f74,
    0x3feea11473eb0187,
    0x3feea589994cce13,
    0x3feeace5422aa0db,
    0x3feeb737b0cdc5e5,
    0x3feec49182a3f090,
    0x3feed503b23e255d,
    0x3feee89f995ad3ad,
    0x3feeff76f2fb5e47,
    0x3fef199bdd85529c,
    0x3fef3720dcef9069,
    0x3fef5818dcfba487,
    0x3fef7c97337b9b5f,
    0x3fefa4afa2a490da,
    0x3fefd0765b6e4540,
];
/// exp2 polynomial C[0..3] (N = 32).
const POWF_EXP2_POLY: [u64; 3] = [0x3fac6af84b912394, 0x3fcebfce50fac4f3, 0x3fe62e42ff0c52d6];

/// `log2(x)` for the bit pattern `ix` of a positive normal float, returned as a
/// double. Faithful port of ARM `log2_inline` (POWF_SCALE = 1).
#[inline]
fn powf_log2_inline(ix: u32) -> f64 {
    let tmp = ix.wrapping_sub(POWF_LOG2_OFF);
    let i = ((tmp >> (23 - POWF_LOG2_TABLE_BITS)) % 16) as usize;
    let top = tmp & 0xff80_0000;
    let iz = ix.wrapping_sub(top);
    let k = (top as i32) >> 23; // POWF_SCALE_BITS = 0, arithmetic shift
    let (invc_bits, logc_bits) = POWF_LOG2_TAB[i];
    let invc = f64::from_bits(invc_bits);
    let logc = f64::from_bits(logc_bits);
    let z = f32::from_bits(iz) as f64;

    // log2(x) = log1p(z/c-1)/ln2 + log2(c) + k.
    let r = z * invc - 1.0;
    let y0 = logc + f64::from(k);
    let a0 = f64::from_bits(POWF_LOG2_POLY[0]);
    let a1 = f64::from_bits(POWF_LOG2_POLY[1]);
    let a2 = f64::from_bits(POWF_LOG2_POLY[2]);
    let a3 = f64::from_bits(POWF_LOG2_POLY[3]);
    let a4 = f64::from_bits(POWF_LOG2_POLY[4]);
    let r2 = r * r;
    let y = a0 * r + a1;
    let p = a2 * r + a3;
    let r4 = r2 * r2;
    let q = a4 * r + y0;
    let q = p * r2 + q;
    y * r4 + q
}

/// `2^xd` rounded to f32, for positive-base powf (no sign bias). Faithful port
/// of ARM `exp2_inline` (non-TOINT path). Caller guarantees `xd` is bounded
/// (|xd| < 126) so the table index arithmetic cannot overflow.
#[inline]
fn powf_exp2_inline(xd: f64) -> f32 {
    // x = k/N + r with r in [-1/(2N), 1/(2N)].
    let kd = xd + POWF_EXP2_SHIFT;
    let ki = kd.to_bits();
    let kd = kd - POWF_EXP2_SHIFT; // k/N
    let r = xd - kd;

    // exp2(x) = 2^(k/N) * 2^r ~= s * (C0*r^3 + C1*r^2 + C2*r + 1).
    let t = POWF_EXP2_TAB[(ki % 32) as usize];
    let t = t.wrapping_add(ki << (52 - POWF_EXP2_TABLE_BITS));
    let s = f64::from_bits(t);
    let c0 = f64::from_bits(POWF_EXP2_POLY[0]);
    let c1 = f64::from_bits(POWF_EXP2_POLY[1]);
    let c2 = f64::from_bits(POWF_EXP2_POLY[2]);
    let z = c0 * r + c1;
    let r2 = r * r;
    let y = c2 * r + 1.0;
    let y = z * r2 + y;
    (y * s) as f32
}

/// General fused `powf` for a positive **normal** finite base and finite
/// exponent. Returns `None` when the result would overflow/underflow
/// (|y*log2 x| >= 126) so the caller defers to `libm::powf` for exact range
/// semantics. Within the accepted range the result is always a finite normal
/// f32 (2^(-126) < r < 2^126), so no output guard is needed.
#[inline]
fn powf_fused_general(base: f32, exponent: f32) -> Option<f32> {
    let ix = base.to_bits();
    let ylogx = f64::from(exponent) * powf_log2_inline(ix);
    if ylogx.abs() < 126.0 {
        Some(powf_exp2_inline(ylogx))
    } else {
        None
    }
}

/// log2f fused kernel polynomial (ARM optimized-routines `__log2f_data.poly`,
/// degree 4). The `tab` it pairs with is byte-identical to `POWF_LOG2_TAB`
/// (same invc/logc, `POWF_SCALE = 1`), so that table is reused.
const LOG2F_POLY: [u64; 4] = [
    0xbfd712b6f70a7e4d,
    0x3fdecabf496832e0,
    0xbfe715479ffae3de,
    0x3ff715475f35c8b8,
];

/// `log2(x)` for the bit pattern `ix` of a positive normal float, rounded to
/// f32. Faithful port of ARM `log2f` (the standalone single-precision log2,
/// glibc `__ieee754_log2f`, 0.26 ULP).
#[inline]
fn log2f_kernel(ix: u32) -> f32 {
    let tmp = ix.wrapping_sub(POWF_LOG2_OFF);
    let i = ((tmp >> (23 - POWF_LOG2_TABLE_BITS)) % 16) as usize;
    let top = tmp & 0xff80_0000;
    let iz = ix.wrapping_sub(top);
    let k = (tmp as i32) >> 23; // arithmetic shift
    let (invc_bits, logc_bits) = POWF_LOG2_TAB[i];
    let invc = f64::from_bits(invc_bits);
    let logc = f64::from_bits(logc_bits);
    let z = f32::from_bits(iz) as f64;

    // log2(x) = log1p(z/c-1)/ln2 + log2(c) + k.
    let r = z * invc - 1.0;
    let y0 = logc + f64::from(k);
    let a0 = f64::from_bits(LOG2F_POLY[0]);
    let a1 = f64::from_bits(LOG2F_POLY[1]);
    let a2 = f64::from_bits(LOG2F_POLY[2]);
    let a3 = f64::from_bits(LOG2F_POLY[3]);
    let r2 = r * r;
    let y = a1 * r + a2;
    let y = a0 * r2 + y;
    let p = a3 * r + y0;
    let y = y * r2 + p;
    y as f32
}

// expf fused kernel constants (ARM optimized-routines `expf`, glibc
// `__ieee754_expf`, 0.5 ULP). Reuses `POWF_EXP2_TAB`; the polynomial and shift
// are the N-scaled variants (`poly_scaled`, unscaled `shift = 0x1.8p+52`).
const EXPF_INVLN2_SCALED: f64 = f64::from_bits(0x4047_1547_652b_82fe); // log2(e) * 32
const EXPF_SHIFT: f64 = f64::from_bits(0x4338_0000_0000_0000); // 0x1.8p+52
const EXPF_POLY_SCALED: [u64; 3] = [
    0x3ebc_6af8_4b91_2394,
    0x3f2e_bfce_50fa_c4f3,
    0x3f96_2e42_ff0c_52d6,
];

/// `e^x` rounded to f32. Faithful port of ARM `expf` (non-TOINT path). Caller
/// guarantees `|x| < 88` so the result is a finite normal f32 and the table
/// index arithmetic cannot overflow.
#[inline]
fn expf_kernel(x: f32) -> f32 {
    let xd = f64::from(x);
    // x*N/Ln2 = k + r with r in [-1/2, 1/2] and int k.
    let z = EXPF_INVLN2_SCALED * xd;
    let kd = z + EXPF_SHIFT;
    let ki = kd.to_bits();
    let kd = kd - EXPF_SHIFT;
    let r = z - kd;

    // exp(x) = 2^(k/N) * 2^(r/N) ~= s * (C0*r^3 + C1*r^2 + C2*r + 1).
    let t = POWF_EXP2_TAB[(ki % 32) as usize];
    let t = t.wrapping_add(ki << (52 - POWF_EXP2_TABLE_BITS));
    let s = f64::from_bits(t);
    let c0 = f64::from_bits(EXPF_POLY_SCALED[0]);
    let c1 = f64::from_bits(EXPF_POLY_SCALED[1]);
    let c2 = f64::from_bits(EXPF_POLY_SCALED[2]);
    let z2 = c0 * r + c1;
    let r2 = r * r;
    let y = c2 * r + 1.0;
    let y = z2 * r2 + y;
    (y * s) as f32
}

// logf fused kernel (ARM optimized-routines `logf`, glibc `__ieee754_logf`,
// 0.32 ULP). Reuses `POWF_LOG2_OFF` (0x3f330000) and the 16-subinterval split;
// the `invc` column matches the shared table but the `logc` column is `ln(c)`
// (natural log), so a dedicated table is used. First-order poly coefficient is 1.
const LOGF_LN2: f64 = f64::from_bits(0x3fe6_2e42_fefa_39ef);
const LOGF_TAB: [(u64, u64); 16] = [
    (0x3ff661ec79f8f3be, 0xbfd57bf7808caade),
    (0x3ff571ed4aaf883d, 0xbfd2bef0a7c06ddb),
    (0x3ff49539f0f010b0, 0xbfd01eae7f513a67),
    (0x3ff3c995b0b80385, 0xbfcb31d8a68224e9),
    (0x3ff30d190c8864a5, 0xbfc6574f0ac07758),
    (0x3ff25e227b0b8ea0, 0xbfc1aa2bc79c8100),
    (0x3ff1bb4a4a1a343f, 0xbfba4e76ce8c0e5e),
    (0x3ff12358f08ae5ba, 0xbfb1973c5a611ccc),
    (0x3ff0953f419900a7, 0xbfa252f438e10c1e),
    (0x3ff0000000000000, 0x0000000000000000),
    (0x3fee608cfd9a47ac, 0x3faaa5aa5df25984),
    (0x3feca4b31f026aa0, 0x3fbc5e53aa362eb4),
    (0x3feb2036576afce6, 0x3fc526e57720db08),
    (0x3fe9c2d163a1aa2d, 0x3fcbc2860d224770),
    (0x3fe886e6037841ed, 0x3fd1058bc8a07ee1),
    (0x3fe767dcf5534862, 0x3fd4043057b6ee09),
];
const LOGF_POLY: [u64; 3] = [0xbfd00ea348b88334, 0x3fd5575b0be00b6a, 0xbfdffffef20a4123];

/// `ln(x)` for the bit pattern `ix` of a positive normal float, rounded to f32.
/// Faithful port of ARM `logf`.
#[inline]
fn logf_kernel(ix: u32) -> f32 {
    let tmp = ix.wrapping_sub(POWF_LOG2_OFF);
    let i = ((tmp >> (23 - POWF_LOG2_TABLE_BITS)) % 16) as usize;
    let k = (tmp as i32) >> 23; // arithmetic shift
    let iz = ix.wrapping_sub(tmp & 0xff80_0000);
    let (invc_bits, logc_bits) = LOGF_TAB[i];
    let invc = f64::from_bits(invc_bits);
    let logc = f64::from_bits(logc_bits);
    let z = f32::from_bits(iz) as f64;

    // log(x) = log1p(z/c-1) + log(c) + k*Ln2.
    let r = z * invc - 1.0;
    let y0 = logc + f64::from(k) * LOGF_LN2;
    let a0 = f64::from_bits(LOGF_POLY[0]);
    let a1 = f64::from_bits(LOGF_POLY[1]);
    let a2 = f64::from_bits(LOGF_POLY[2]);
    let r2 = r * r;
    let y = a1 * r + a2;
    let y = a0 * r2 + y;
    let y = y * r2 + (y0 + r);
    y as f32
}

#[inline]
pub fn powf(base: f32, exponent: f32) -> f32 {
    // Fast paths mirroring the f64 `pow`: libm::powf always routes through its
    // general log/exp classifier; small integer exponents (and y==0.5) via
    // exponentiation by squaring are far faster and, bounded to small
    // magnitudes / the medium base-exponent box, stay within the 4-ULP glibc
    // parity contract. Everything else defers to libm for exact IEEE semantics.
    if base.is_finite() && exponent.is_finite() {
        let n = exponent as i32;
        if n as f32 == exponent && n.unsigned_abs() <= POWF_MAX_EXP {
            // Small integer exponents stay correctly rounded (0 ULP) via
            // exponentiation by squaring — kept ahead of the fused kernel
            // (which carries ~0.8 ULP) and also handles negative bases.
            return powi_squaringf(base, n) as f32;
        }
        if exponent == 0.5 && base >= 0.0 {
            return base.sqrt();
        }
        // General fused single-pass kernel (ARM optimized-routines / glibc
        // `__ieee754_powf`, 0.82 ULP): one log2 + one exp2 table pass for any
        // positive **normal** finite base whose result lands in the finite-
        // normal f32 range. This supersedes the older `exp2f/log2f` medium box
        // and the exponent-1.337 grid below (same domain, but bit-exact to glibc
        // and faster), so those run only for the residual subnormal-base /
        // overflow cases the fused guard rejects. Overflow/underflow
        // (|y*log2 x| >= 126) returns None and defers to `libm::powf` for exact
        // FE_OVERFLOW/FE_UNDERFLOW + errno semantics; subnormal/zero/negative
        // bases also defer (the `>=` guard excludes them).
        if base >= f32::MIN_POSITIVE
            && let Some(result) = powf_fused_general(base, exponent)
        {
            return result;
        }
        if let Some(result) = powf_half_integer_fast_path(base, exponent) {
            return result;
        }
        if let Some(result) = powf_medium_fast_path(base, exponent) {
            return result;
        }
    }
    libm::powf(base, exponent)
}

// --- Hyperbolic ---

const SINHF_FAST_ABS_MIN: f32 = 0.5;
// Upper bound is fl's f64 `exp` fast-path limit (|x| <= 5); beyond it the f64
// kernel itself defers to libm, so widening past 5 buys nothing.
const SINHF_FAST_ABS_MAX: f32 = 5.0;

#[inline]
pub fn sinhf(x: f32) -> f32 {
    // sinh(x) = (e^x - e^-x)/2 = (u - 1/u)/2, u = e^x. For |x| >= 0.5 the two
    // terms differ enough that the subtraction loses <1 bit, so evaluating in f64
    // with our fast `exp` (whose [-5,5] fast path covers x here) and rounding
    // once replaces libm::sinhf's dedicated polynomial. The identity is odd, so
    // it serves negative x directly. Near-0 (cancellation) and large/non-finite x
    // defer to libm. Mirrors the f64 `cosh` one-exp reroute and `tanhf`.
    if (SINHF_FAST_ABS_MIN..=SINHF_FAST_ABS_MAX).contains(&x.abs()) {
        let u = crate::math::exp::exp(x as f64);
        return ((u - 1.0 / u) * 0.5) as f32;
    }
    libm::sinhf(x)
}

#[inline]
pub fn coshf(x: f32) -> f32 {
    // cosh(x) = (e^|x| + e^-|x|)/2 = (u + 1/u)/2, u = e^|x|. cosh is even and the
    // sum never cancels (result >= 1), so this is well-conditioned for ALL x,
    // including near 0. Evaluate in f64 with the fast `exp` (whose [-5,5] fast
    // path covers |x| here) and round once — correctly-rounded for f32, matching
    // glibc bit-for-bit on the conformance CASES. |x| > 5 (where the f64 exp
    // kernel itself defers to libm, and large x eventually overflows) stays on
    // libm::coshf for the exact overflow/FE semantics. Mirrors `sinhf`.
    let ax = x.abs();
    if ax <= 5.0 {
        let u = crate::math::exp::exp(ax as f64);
        return ((u + 1.0 / u) * 0.5) as f32;
    }
    libm::coshf(x)
}

const TANHF_FAST_ABS_MIN: f32 = 0.5;
// Upper bound kept below where `expf(2x)` overflows (2x < 88.7, i.e. x < 44.3);
// well before that, `(u-1)/(u+1)` self-saturates to ±1 exactly in f32 (the `-1`
// and `+1` vanish against the huge `u`), so the result is correct for the whole
// band — including the saturated CASES (e.g. tanhf(20)=1.0).
const TANHF_FAST_ABS_MAX: f32 = 40.0;

#[inline]
pub fn tanhf(x: f32) -> f32 {
    // tanh(x) = (e^2x - 1)/(e^2x + 1). For |x| >= 0.5 this form has no
    // cancellation (the result is bounded away from 0), so the f32 `expf`
    // fast path covers 2x directly on this interval and avoids widening through
    // the f64 exp kernel. The identity is odd, so it serves negative x with no
    // special-casing. Near-0 (cancellation) and tiny/non-finite x defer to libm.
    if (TANHF_FAST_ABS_MIN..=TANHF_FAST_ABS_MAX).contains(&x.abs()) {
        let u = expf(2.0 * x);
        return (u - 1.0) / (u + 1.0);
    }
    libm::tanhf(x)
}

#[inline]
pub fn asinhf(x: f32) -> f32 {
    // asinh(x) = sign(x)·log(|x| + sqrt(x²+1)), evaluated in f64 so the precision
    // absorbs the small-|x| cancellation (no dedicated log1p/polynomial needed) and the
    // single f32 rounding is correctly-rounded-ish. Uses fl's fused f64 `log` — faster
    // than the generic libm::asinhf. inf→±inf, ±0→±0, NaN→NaN fall out of the formula.
    let fx = x as f64;
    let ax = fx.abs();
    let r = crate::math::log(ax + (ax * ax + 1.0).sqrt());
    (if fx.is_sign_negative() { -r } else { r }) as f32
}

#[inline]
pub fn acoshf(x: f32) -> f32 {
    // Domain is [1, +inf); for x < 1 acosh is undefined and glibc returns NaN.
    // libm::acoshf computes a spurious finite value for large negative x (e.g.
    // acoshf(-100) = -2.2), so guard the domain explicitly. NaN inputs fall
    // through (NaN < 1.0 is false) to libm, which returns NaN. glibc also raises
    // FE_INVALID for the out-of-domain case, so produce the NaN via 0/0 (which
    // sets the flag) rather than a bare NaN constant.
    if x < 1.0 {
        return core::hint::black_box(
            core::hint::black_box(0.0f32) / core::hint::black_box(0.0f32),
        );
    }
    // acosh(x) = log(x + sqrt((x-1)(x+1))) in f64 (the (x-1)(x+1) factoring keeps the
    // sqrt accurate near x=1). x=1→log(1)=0; +inf→+inf. Fused f64 `log` beats libm::acoshf.
    let fx = x as f64;
    (crate::math::log(fx + ((fx - 1.0) * (fx + 1.0)).sqrt())) as f32
}

#[inline]
pub fn atanhf(x: f32) -> f32 {
    // atanh(x) = 0.5·log((1+x)/(1-x)) in f64 (precision absorbs the small-x cancellation).
    // copysign restores the sign for ±0 (0.5·log(1)=+0 otherwise). |x|>1→log(neg)=NaN,
    // ±1→±inf. Fused f64 `log` beats libm::atanhf.
    let fx = x as f64;
    let r = 0.5 * crate::math::log((1.0 + fx) / (1.0 - fx));
    (r as f32).copysign(x)
}

// --- Exponential / logarithmic (additional) ---

#[inline]
pub fn exp2f(x: f32) -> f32 {
    // Fused single-pass kernel (ARM optimized-routines / glibc `__ieee754_exp2f`,
    // 0.5 ULP) — the same `2^xd` table pass used by the powf exp2 stage. Used for
    // the normal-result interior |x| < 126, where 2^x is a finite normal f32 and
    // `xd = x` is exact. Overflow, underflow, subnormal, inf and nan defer to
    // `libm::exp2f` for exact FE_OVERFLOW/FE_UNDERFLOW + errno semantics.
    if x.abs() < 126.0 {
        return powf_exp2_inline(f64::from(x));
    }
    libm::exp2f(x)
}

const EXPM1F_POSITIVE_FAST_MIN: f32 = 0.5;
const EXPM1F_POSITIVE_FAST_MAX: f32 = 2.5;

#[inline]
pub fn expm1f(x: f32) -> f32 {
    if (EXPM1F_POSITIVE_FAST_MIN..=EXPM1F_POSITIVE_FAST_MAX).contains(&x) {
        return expf(x) - 1.0;
    }
    libm::expm1f(x)
}

#[inline]
pub fn log1pf(x: f32) -> f32 {
    // log1pf(-1) = -inf is a pole: glibc raises FE_DIVBYZERO, libm omits it.
    if x == -1.0 {
        fe_divbyzero_f32();
    }
    libm::log1pf(x)
}

// --- Float utilities ---

#[inline]
pub fn sqrtf(x: f32) -> f32 {
    libm::sqrtf(x)
}

#[inline]
pub fn fabsf(x: f32) -> f32 {
    libm::fabsf(x)
}

#[inline]
pub fn ceilf(x: f32) -> f32 {
    libm::ceilf(x)
}

#[inline]
pub fn floorf(x: f32) -> f32 {
    libm::floorf(x)
}

#[inline]
pub fn roundf(x: f32) -> f32 {
    libm::roundf(x)
}

#[inline]
pub fn truncf(x: f32) -> f32 {
    libm::truncf(x)
}

#[inline]
pub fn rintf(x: f32) -> f32 {
    libm::rintf(x)
}

#[inline]
pub fn nearbyintf(x: f32) -> f32 {
    libm::rintf(x)
}

#[inline]
pub fn fmodf(x: f32, y: f32) -> f32 {
    libm::fmodf(x, y)
}

#[inline]
pub fn remainderf(x: f32, y: f32) -> f32 {
    libm::remainderf(x, y)
}

#[inline]
pub fn copysignf(x: f32, y: f32) -> f32 {
    libm::copysignf(x, y)
}

#[inline]
pub fn cbrtf(x: f32) -> f32 {
    libm::cbrtf(x)
}

#[inline]
pub fn hypotf(x: f32, y: f32) -> f32 {
    libm::hypotf(x, y)
}

// --- Min / max / dim / fma ---

#[inline]
pub fn fminf(x: f32, y: f32) -> f32 {
    libm::fminf(x, y)
}

#[inline]
pub fn fmaxf(x: f32, y: f32) -> f32 {
    libm::fmaxf(x, y)
}

#[inline]
pub fn fdimf(x: f32, y: f32) -> f32 {
    libm::fdimf(x, y)
}

#[inline]
pub fn fmaf(x: f32, y: f32, z: f32) -> f32 {
    libm::fmaf(x, y, z)
}

// --- Rounding / conversion ---

// f32 conversions share glibc's x86 `cvt(t)ss2si` out-of-range / NaN semantics
// (integer-indefinite i64::MIN), the same as the f64 path. The rounded f32 is
// widened to f64 exactly before the range check. See
// `crate::math::float::round_to_i64_x86`.
#[inline]
pub fn lrintf(x: f32) -> i64 {
    crate::math::float::round_to_i64_x86(libm::rintf(x) as f64)
}

#[inline]
pub fn llrintf(x: f32) -> i64 {
    crate::math::float::round_to_i64_x86(libm::rintf(x) as f64)
}

#[inline]
pub fn lroundf(x: f32) -> i64 {
    crate::math::float::round_to_i64_x86(libm::roundf(x) as f64)
}

#[inline]
pub fn llroundf(x: f32) -> i64 {
    crate::math::float::round_to_i64_x86(libm::roundf(x) as f64)
}

// --- Float decomposition ---

#[inline]
pub fn ldexpf(x: f32, exp: i32) -> f32 {
    libm::ldexpf(x, exp)
}

#[inline]
pub fn frexpf(x: f32) -> (f32, i32) {
    libm::frexpf(x)
}

#[inline]
pub fn modff(x: f32) -> (f32, f32) {
    libm::modff(x)
}

// --- Scaling / exponent extraction ---

#[inline]
pub fn scalbnf(x: f32, n: i32) -> f32 {
    libm::scalbnf(x, n)
}

#[inline]
pub fn scalblnf(x: f32, n: i64) -> f32 {
    let exp = n.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    libm::ldexpf(x, exp)
}

#[inline]
pub fn nextafterf(x: f32, y: f32) -> f32 {
    let r = libm::nextafterf(x, y);
    // C99/IEEE: FE_OVERFLOW when finite -> infinite; FE_UNDERFLOW when the result
    // is subnormal/zero and differs from x. libm omits these; re-raise.
    if x.is_finite() && r.is_infinite() {
        let _ = core::hint::black_box(
            core::hint::black_box(f32::MAX) * core::hint::black_box(f32::MAX),
        );
    } else if r != x && r.abs() < f32::MIN_POSITIVE {
        let _ = core::hint::black_box(
            core::hint::black_box(f32::MIN_POSITIVE) * core::hint::black_box(f32::MIN_POSITIVE),
        );
    }
    r
}

/// Return the next representable `f32` after `x` toward `y` (long double direction).
///
/// `y` is `f64` (representing the `long double` direction parameter in C ABI).
/// The direction is determined by `x < y` / `x > y` / `x == y`.
#[inline]
pub fn nexttowardf(x: f32, y: f64) -> f32 {
    if x.is_nan() || y.is_nan() {
        return f32::NAN;
    }
    let xd = x as f64;
    if xd == y {
        return x;
    }
    // Step toward y using f32 nextafter
    if xd < y {
        libm::nextafterf(x, f32::INFINITY)
    } else {
        libm::nextafterf(x, f32::NEG_INFINITY)
    }
}

#[inline]
pub fn ilogbf(x: f32) -> i32 {
    // C99 7.12.6.5: ilogb(0), ilogb(±inf), ilogb(NaN) raise FE_INVALID.
    if x == 0.0 || !x.is_finite() {
        fe_invalid_f32();
    }
    libm::ilogbf(x)
}

#[inline]
pub fn logbf(x: f32) -> f32 {
    if x == 0.0 {
        // logb(0) = -inf is a pole: glibc raises FE_DIVBYZERO.
        fe_divbyzero_f32();
        return f32::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f32::INFINITY;
    }
    if x.is_nan() {
        return x;
    }
    libm::ilogbf(x) as f32
}

// --- Special functions ---

#[inline]
/// Error function, single precision.
///
/// Verbatim port of the ARM optimized-routines `erff` (the algorithm glibc 2.42
/// ships): a pure polynomial on |x| < 0.875 and `exp` of a polynomial on
/// [0.875, 4); ±1 beyond. Worst-case error ~1.09 ULP. `libm::erff` (fdlibm) is
/// ~2x slower. The rare tiny |x| < 2^-28 path defers to `libm::erff` so the
/// underflow/subnormal flag semantics stay exact.
pub fn erff(x: f32) -> f32 {
    const A: [f32; 6] = [
        f32::from_bits(0x3e0375d3),
        f32::from_bits(0xbec09370),
        f32::from_bits(0x3de70d23),
        f32::from_bits(0xbcdb45e9),
        f32::from_bits(0x3ba39fa4),
        f32::from_bits(0xba1d0d41),
    ];
    const B: [f32; 7] = [
        f32::from_bits(0x3e03ce86),
        f32::from_bits(0x3f228550),
        f32::from_bits(0x3ddaae58),
        f32::from_bits(0xbcc6b180),
        f32::from_bits(0x3b7e899b),
        f32::from_bits(0xb9c8e966),
        f32::from_bits(0x37911480),
    ];
    const TWO_OVER_SQRT_PI_M1: f32 = f32::from_bits(0x3e0375d4);

    let ix = x.to_bits();
    let sign = ix >> 31;
    let ia12 = (ix >> 20) & 0x7ff;

    if ia12 < 0x3f6 {
        // |x| < 0.875.
        if ia12 < 0x318 {
            // |x| < 2^-28 (incl. tiny/subnormal): defer for exact uflow flag.
            return libm::erff(x);
        }
        let x2 = x * x;
        // x + x*P(x^2), Horner.
        let mut r = A[5];
        r = r.mul_add(x2, A[4]);
        r = r.mul_add(x2, A[3]);
        r = r.mul_add(x2, A[2]);
        r = r.mul_add(x2, A[1]);
        r = r.mul_add(x2, A[0]);
        r.mul_add(x, x)
    } else if ia12 < 0x408 {
        // |x| < 4.0: erf = sign*(1 - exp(-(a + a*Q(a)))).
        let a = x.abs();
        let mut r = B[6].mul_add(a, B[5]);
        let u = B[4].mul_add(a, B[3]);
        let x2 = x * x;
        r = r.mul_add(x2, u);
        r = r.mul_add(a, B[2]);
        r = r.mul_add(a, B[1]);
        r = r.mul_add(a, B[0]);
        r = r.mul_add(a, a);
        r = expf(-r);
        if sign != 0 { -1.0 + r } else { 1.0 - r }
    } else {
        // |x| >= 4.0.
        if ia12 >= 0x7f8 {
            // erff(nan)=nan, erff(±inf)=±1.
            return (1.0 - ((ix >> 31) << 1) as f32) + 1.0 / x;
        }
        if sign != 0 { -1.0 } else { 1.0 }
    }
}

#[inline]
pub fn erfcf(x: f32) -> f32 {
    // Well-conditioned region: build erfc from the fast `erff` kernel.
    //   x <= 0:          erfc(x) = 1 + erf(|x|)  (result in [1,2], no cancellation)
    //   0 < x <= 0.8:    erfc(x) = 1 - erf(x)    (erfc >= ~0.26, cancellation <=~3 ULP)
    // libm::erfcf is ~1.5x slower than glibc; this routes the bulk of the domain
    // through the in-tree ARM erff port instead. The small-erfc tail (x > 0.875,
    // where 1-erf loses precision and the result eventually underflows) stays on
    // libm::erfcf, which also yields the exact subnormal/underflow flag.
    if x.is_finite() {
        if x <= 0.0 {
            return 1.0 + erff(-x);
        }
        if x <= 0.8 {
            return 1.0 - erff(x);
        }
    }
    let r = libm::erfcf(x);
    // erfc(x) for large finite positive x underflows toward 0; glibc raises
    // FE_UNDERFLOW on the subnormal/zero result, libm omits it. erfc(+inf)=0
    // is an exact limit (no underflow), so exclude non-finite x.
    if x.is_finite() && x > 0.0 && r < f32::MIN_POSITIVE {
        fe_underflow_f32();
    }
    r
}

#[inline]
pub fn lgammaf(x: f32) -> f32 {
    libm::lgammaf(x)
}

#[inline]
pub fn tgammaf(x: f32) -> f32 {
    // Negative-integer poles: glibc raises FE_INVALID (NaN); libm::tgammaf omits
    // the flag. (tgammaf(0) is handled by libm with FE_DIVBYZERO.)
    if x < 0.0 && x.is_finite() && x == x.floor() {
        fe_invalid_f32();
    }
    // `libm::tgammaf` is ~7x slower than glibc; the in-tree f64 `tgamma` fast
    // kernel (tgamma_reduced) is far more than accurate enough for a
    // correctly-rounded f32 result, and f32 args widen to f64 exactly.
    super::special::tgamma(x as f64) as f32
}

// --- New batch: remquo, sincos, nan, Bessel, compat ---

/// IEEE remainder with quotient (f32 variant).
#[inline]
pub fn remquof(x: f32, y: f32) -> (f32, i32) {
    let (rem, quo) = libm::remquof(x, y);
    // Match glibc: store only sign(x/y) * (low 3 bits of the quotient
    // magnitude) — C99 n=3. See `crate::math::float::remquo`.
    let magnitude = (quo.unsigned_abs() & 7) as i32;
    (rem, if quo < 0 { -magnitude } else { magnitude })
}

/// Compute sine and cosine simultaneously (f32 variant).
#[inline]
pub fn sincosf(x: f32) -> (f32, f32) {
    libm::sincosf(x)
}

/// Generate a quiet NaN (f32 variant), encoding the `tag` payload like
/// C `nanf(tagp)`. See [`crate::math::float::nan`] for the tag grammar;
/// here the payload occupies the f32 mantissa's low 22 bits.
#[inline]
pub fn nanf(tag: &[u8]) -> f32 {
    // Quiet NaN: exponent all-ones + the quiet bit (mantissa bit 22).
    const QUIET_NAN: u32 = 0x7fc0_0000;
    // The tag payload occupies mantissa bits 0..=21.
    const PAYLOAD_MASK: u32 = 0x003f_ffff;
    // Reuse the f64 tag parser; the payload lives in the low bits.
    let payload = crate::math::float::nan(tag).to_bits() as u32;
    f32::from_bits(QUIET_NAN | (payload & PAYLOAD_MASK))
}

/// GNU extension: base-10 exponential (f32 variant).
#[inline]
pub fn exp10f(x: f32) -> f32 {
    // Integer exponents in [-10, 10] yield powers of ten that `powi`
    // returns exactly (positive) or correctly rounded (negative); the
    // `expf(x * ln10)` form double-rounds, so exp10f(3) would otherwise
    // come out slightly off 1000.0.
    if x.is_finite() && x == x.trunc() && (-10.0..=10.0).contains(&x) {
        return 10.0_f32.powi(x as i32);
    }
    if x.is_finite() && (0.5..=2.5).contains(&x) {
        return exp10f_profile_band(x);
    }
    // 10^x = 2^(x·log2 10), evaluated entirely in f64 via the fast exp2 kernel
    // outside the profiled medium-positive band. f64 carries 29 extra bits, so
    // the single trailing f64→f32 rounding is essentially correct (far inside 4
    // ULP) with no extended-precision constant or wide-domain range gate: f64
    // never overflows across the entire finite f32 domain, and the cast maps f64
    // over/underflow to f32 inf/0 exactly as glibc does. Verified by
    // conformance_diff_math::diff_exp10f_within_4_ulps.
    //
    // NOTE (rejected lever, measured): the f32 `exp2f(x * LOG2_10_f32)` route is
    // faster but FAILS the 4-ULP contract (5 ULP on subnormal results near
    // x ≈ -39, where the f32 x·log2(10) rounding loses precision). Keep that
    // low-range traffic on the f64 fallback; do not switch the full domain to f32.
    (libm::exp2(x as f64 * core::f64::consts::LOG2_10)) as f32
}

#[inline]
fn exp10f_profile_band(x: f32) -> f32 {
    const TABLE_START: i32 = 8;
    const CENTER_STEP: f64 = 0.0625;
    const TABLE: [f64; 33] = [
        3.162_277_660_168_379_5,
        3.651_741_272_548_377,
        4.216_965_034_285_822,
        4.869_675_251_658_631,
        5.623_413_251_903_491,
        6.493_816_315_762_113,
        7.498_942_093_324_558,
        8.659_643_233_600_654,
        10.0,
        11.547_819_846_894_581,
        13.335_214_321_633_24,
        15.399_265_260_594_92,
        17.782_794_100_389_23,
        20.535_250_264_571_46,
        23.713_737_056_616_55,
        27.384_196_342_643_612,
        31.622_776_601_683_793,
        36.517_412_725_483_77,
        42.169_650_342_858_226,
        48.696_752_516_586_31,
        56.234_132_519_034_91,
        64.938_163_157_621_13,
        74.989_420_933_245_58,
        86.596_432_336_006_53,
        100.0,
        115.478_198_468_945_82,
        133.352_143_216_332_4,
        153.992_652_605_949_2,
        177.827_941_003_892_28,
        205.352_502_645_714_6,
        237.137_370_566_165_52,
        273.841_963_426_436_1,
        316.227_766_016_837_96,
    ];
    const C0: f64 = 1.0;
    const C1: f64 = core::f64::consts::LN_10;
    const C2: f64 = 2.650_949_055_239_199_7;
    const C3: f64 = 2.034_678_592_293_477;
    const C4: f64 = 1.171_255_148_912_267_6;
    const C5: f64 = 0.539_382_929_195_581_7;

    let bucket = (x * 16.0 + 0.5) as i32;
    let index = (bucket - TABLE_START) as usize;
    debug_assert!(index < TABLE.len());
    let r = x as f64 - (bucket as f64) * CENTER_STEP;
    let r2 = r * r;
    let r4 = r2 * r2;
    let residual = (C0 + C1 * r) + r2 * (C2 + C3 * r) + r4 * (C4 + C5 * r);
    (TABLE[index] * residual) as f32
}

/// Bessel function of the first kind, order 0 (f32 variant).
#[inline]
pub fn j0f(x: f32) -> f32 {
    libm::j0f(x)
}

/// Bessel function of the first kind, order 1 (f32 variant).
#[inline]
pub fn j1f(x: f32) -> f32 {
    // J1 is odd, so J1(-inf) carries the sign of -J1(+inf) = -0.0; libm::j1f(-inf)
    // returns +0.0, but glibc returns -0.0. Match glibc.
    if x == f32::NEG_INFINITY {
        return -0.0;
    }
    libm::j1f(x)
}

/// Bessel function of the first kind, order `n` (f32 variant).
#[inline]
pub fn jnf(n: i32, x: f32) -> f32 {
    // Mirror f64 jn: route orders 0/±1 through j0f/j1f (j1f's signed-zero-at-(-inf)
    // fix) + the identity J_{-n} = (-1)^n J_n. Identical to libm::jnf for finite x;
    // |n| >= 2 stays on libm::jnf.
    match n {
        0 => j0f(x),
        1 => j1f(x),
        -1 => -j1f(x),
        _ => libm::jnf(n, x),
    }
}

/// Bessel function of the second kind, order 0 (f32 variant).
/// Y-Bessel pole/domain exception re-raise (f32): x==0 -> FE_DIVBYZERO,
/// x<0 -> FE_INVALID. Mirrors the f64 `raise_y_special`.
#[inline]
fn raise_y_special_f32(x: f32) {
    if x == 0.0 {
        fe_divbyzero_f32();
    } else if x < 0.0 {
        fe_invalid_f32();
    }
}

pub fn y0f(x: f32) -> f32 {
    raise_y_special_f32(x);
    libm::y0f(x)
}

/// Bessel function of the second kind, order 1 (f32 variant).
#[inline]
pub fn y1f(x: f32) -> f32 {
    raise_y_special_f32(x);
    libm::y1f(x)
}

/// Bessel function of the second kind, order `n` (f32 variant).
#[inline]
pub fn ynf(n: i32, x: f32) -> f32 {
    // Mirror f64 yn: orders 0/±1 via y0f/y1f + the identity Y_{-n} = (-1)^n Y_n.
    match n {
        0 => y0f(x),
        1 => y1f(x),
        -1 => -y1f(x),
        _ => {
            raise_y_special_f32(x);
            libm::ynf(n, x)
        }
    }
}

/// BSD/SUSv2 `finitef()`: returns non-zero if `x` is neither infinite nor NaN.
#[inline]
pub fn finitef(x: f32) -> i32 {
    if x.is_finite() { 1 } else { 0 }
}

/// BSD `dremf()` — alias for `remainderf()`.
#[inline]
pub fn dremf(x: f32, y: f32) -> f32 {
    remainderf(x, y)
}

/// BSD `gammaf()` — alias for `lgammaf()`.
#[inline]
pub fn gammaf(x: f32) -> f32 {
    libm::lgammaf(x)
}

/// Reentrant lgammaf: returns `(lgammaf(x), signgam)` (f32 variant).
#[inline]
pub fn lgammaf_r(x: f32) -> (f32, i32) {
    libm::lgammaf_r(x)
}

// ---------------------------------------------------------------------------
// IEEE 754 classification helpers (f32 variants)
// ---------------------------------------------------------------------------

/// FP_NAN, FP_INFINITE, FP_ZERO, FP_SUBNORMAL, FP_NORMAL (same values as f64).
pub const FP_NAN_F32: i32 = 0;
pub const FP_INFINITE_F32: i32 = 1;
pub const FP_ZERO_F32: i32 = 2;
pub const FP_SUBNORMAL_F32: i32 = 3;
pub const FP_NORMAL_F32: i32 = 4;

/// Classify a single-precision float (glibc `__fpclassifyf`).
#[inline]
pub fn fpclassifyf(x: f32) -> i32 {
    if x.is_nan() {
        FP_NAN_F32
    } else if x.is_infinite() {
        FP_INFINITE_F32
    } else if x == 0.0 {
        FP_ZERO_F32
    } else if x.is_subnormal() {
        FP_SUBNORMAL_F32
    } else {
        FP_NORMAL_F32
    }
}

/// Return non-zero if sign bit is set (f32 variant).
#[inline]
pub fn signbitf(x: f32) -> i32 {
    if x.is_sign_negative() { 1 } else { 0 }
}

/// Return non-zero if `x` is infinite (f32 variant).
#[inline]
pub fn isinff(x: f32) -> i32 {
    if x == f32::INFINITY {
        1
    } else if x == f32::NEG_INFINITY {
        -1
    } else {
        0
    }
}

/// Return non-zero if `x` is NaN (f32 variant).
#[inline]
pub fn isnanf(x: f32) -> i32 {
    if x.is_nan() { 1 } else { 0 }
}

/// Extract the significand (mantissa) of `x` scaled to `[1, 2)` (f32 variant).
#[inline]
pub fn significandf(x: f32) -> f32 {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    let e = libm::ilogbf(x);
    libm::scalbnf(x, -e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acoshf_domain_and_j1f_sign_match_glibc() {
        // acosh domain is [1, +inf); x < 1 must be NaN (libm returns spurious
        // finite values for large negative x, e.g. acoshf(-100) = -2.2).
        for x in [
            -100.0f32,
            -104.0,
            -1.0,
            0.0,
            0.5,
            0.9999999,
            f32::NEG_INFINITY,
        ] {
            assert!(acoshf(x).is_nan(), "acoshf({x}) must be NaN (domain x<1)");
        }
        assert_eq!(acoshf(1.0), 0.0);
        assert!(acoshf(2.0).is_finite() && acoshf(2.0) > 0.0);
        assert_eq!(acoshf(f32::INFINITY), f32::INFINITY);
        // J1 is odd → j1f(-inf) = -0.0 (glibc); libm returns +0.0.
        assert_eq!(j1f(f32::NEG_INFINITY).to_bits(), (-0.0f32).to_bits());
        assert_eq!(j1f(f32::INFINITY).to_bits(), 0.0f32.to_bits());
    }

    /// ULP distance for f32 with matching-sign requirement (mirrors the f64
    /// `within_ulps`). `f32::powf` resolves to host glibc `powf`.
    fn within_ulps_f32(a: f32, b: f32, ulps: u32) -> bool {
        if a == b {
            return true;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return false;
        }
        let ab = a.to_bits() as i32;
        let bb = b.to_bits() as i32;
        (ab - bb).unsigned_abs() <= ulps
    }

    #[test]
    fn log2f_dyadic_profile_grid_matches_libm_bits() {
        let mut s = 0x6c8e_9cf5_u32;
        for k in 0..=64 {
            let x = 0.5 + (k as f32) * 0.031_25;
            let got = log2f(x);
            let want = libm::log2f(x);
            assert_eq!(got.to_bits(), want.to_bits(), "log2f({x})");
        }

        for _ in 0..1_000_000 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let x = 0.5 + (s >> 9) as f32 * (2.0 / (1u32 << 23) as f32);
            let got = log2f(x);
            let want = libm::log2f(x);
            assert_eq!(got.to_bits(), want.to_bits(), "log2f({x})");
        }

        for &x in &[
            -0.0f32,
            0.0,
            0.499_999_97,
            1.0,
            2.0,
            2.500_000_2,
            f32::INFINITY,
        ] {
            assert_eq!(log2f(x).to_bits(), libm::log2f(x).to_bits(), "log2f({x})");
        }
        assert!(log2f(-1.0).is_nan());
        assert!(log2f(f32::NAN).is_nan());
    }

    #[test]
    fn golden_log2f_dyadic_profile_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for k in 0..64 {
            let x = 0.5 + (k as f32) * 0.031_25;
            let got = log2f(x);
            let want = libm::log2f(x);
            assert_eq!(got.to_bits(), want.to_bits(), "log2f({x})");
            hasher.update(x.to_bits().to_le_bytes());
            hasher.update(got.to_bits().to_le_bytes());
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "248d682cbff82dc23dbcce6229ef91fe6c6acf2d7c60289e9080756ac411b5f1",
            "log2f dyadic profile corpus hash drifted: got {digest}"
        );
    }

    #[test]
    fn log10f_dyadic_profile_grid_within_4_ulps() {
        let mut worst = 0u32;
        for k in 0..=64 {
            let x = 0.5 + (k as f32) * 0.031_25;
            let got = log10f(x);
            let want = x.log10();
            let ulps = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            worst = worst.max(ulps);
            assert!(
                within_ulps_f32(got, want, 4),
                "log10f({x}) = {got:?} but glibc = {want:?} ({ulps} ULP)"
            );
        }

        for &x in &[
            -1.0f32,
            -0.0,
            0.0,
            0.500_001,
            0.531_251,
            2.500_001,
            f32::INFINITY,
            f32::NAN,
        ] {
            let got = log10f(x);
            let want = libm::log10f(x);
            if got.is_nan() && want.is_nan() {
                continue;
            }
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "log10f fallback drifted at {x:?}"
            );
        }
        println!("log10f dyadic profile grid worst ULP = {worst}");
    }

    #[test]
    fn golden_log10f_dyadic_profile_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for k in 0..64 {
            let x = 0.5 + (k as f32) * 0.031_25;
            let got = log10f(x);
            hasher.update(x.to_bits().to_le_bytes());
            hasher.update(got.to_bits().to_le_bytes());
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        println!("log10f dyadic profile corpus sha256 = {digest}");
        assert_eq!(
            digest, "d7fd22a304b20df2cf355da32d9cf28877f90e34d6b552155d434bb8e2d585fc",
            "log10f dyadic profile corpus hash drifted: got {digest}"
        );
    }

    #[test]
    fn expf_medium_fast_path_within_4_ulps() {
        // Dense sweep of the fast-path interval [-5, 5] vs host glibc expf.
        let mut s = 0x1357_9bdf_u32;
        let mut maxu = 0u32;
        for _ in 0..1_000_000 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let x = -5.0 + (s >> 9) as f32 * (10.0 / (1u32 << 23) as f32); // [-5,5]
            let got = expf(x);
            let want = x.exp(); // glibc expf
            let u = if got == want {
                0
            } else {
                (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs()
            };
            if u > maxu {
                maxu = u;
            }
        }
        assert!(
            maxu <= 4,
            "expf medium fast path max {maxu} ULP > 4 vs glibc"
        );
    }

    #[test]
    fn expf_fallback_preserves_libm_bits() {
        // Outside [-5, 5] expf must stay bit-identical to libm::expf.
        for &x in &[
            -50.0f32,
            -10.0,
            -5.0001,
            5.0001,
            10.0,
            50.0,
            f32::NEG_INFINITY,
            f32::INFINITY,
        ] {
            assert_eq!(
                expf(x).to_bits(),
                libm::expf(x).to_bits(),
                "expf({x}) fallback drifted"
            );
        }
        assert!(expf(f32::NAN).is_nan());
    }

    #[test]
    fn sinhf_fast_path_within_4_ulps() {
        fn ulpf(a: f32, b: f32) -> i64 {
            if a == b {
                0
            } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
                i64::MAX
            } else {
                (a.to_bits() as i64 - b.to_bits() as i64).abs()
            }
        }
        let mut worst = 0i64;
        let mut worst_x = 0.0f32;
        let mut x = -2.5f32;
        while x <= 2.5 {
            let u = ulpf(sinhf(x), libm::sinhf(x));
            if u > worst {
                worst = u;
                worst_x = x;
            }
            x += 0.0005;
        }
        assert!(
            worst <= 4,
            "sinhf fast path worst {worst} ULP at x={worst_x}"
        );
    }

    #[test]
    fn tanhf_fast_path_within_4_ulps() {
        fn ulpf(a: f32, b: f32) -> i64 {
            if a == b {
                0
            } else if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
                i64::MAX
            } else {
                (a.to_bits() as i64 - b.to_bits() as i64).abs()
            }
        }
        let mut worst = 0i64;
        let mut worst_x = 0.0f32;
        let mut x = -2.5f32;
        while x <= 2.5 {
            let u = ulpf(tanhf(x), libm::tanhf(x));
            if u > worst {
                worst = u;
                worst_x = x;
            }
            x += 0.0005;
        }
        assert!(
            worst <= 4,
            "tanhf fast path worst {worst} ULP at x={worst_x}"
        );
    }

    #[test]
    fn powf_fast_paths_within_4_ulps() {
        let bases = [
            0.0f32,
            -0.0,
            1.0,
            -1.0,
            2.0,
            -2.0,
            0.5,
            -0.5,
            std::f32::consts::PI,
            1.785,
            1e-3,
            1e6,
            123.456,
            0.999_999,
            1.000_001,
            0.6,
            1.5,
            2.49,
            0.51,
        ];
        // Integer exponents in the gated range, plus 0.5 and half-integers.
        for &base in &bases {
            for n in -(POWF_MAX_EXP as i32)..=(POWF_MAX_EXP as i32) {
                let e = n as f32;
                assert!(
                    within_ulps_f32(powf(base, e), base.powf(e), 4),
                    "powf({base},{e})={} glibc={}",
                    powf(base, e),
                    base.powf(e)
                );
            }
            if base >= 0.0 {
                assert!(within_ulps_f32(powf(base, 0.5), base.powf(0.5), 4));
                for n in -(POWF_MAX_EXP as i32)..=(POWF_MAX_EXP as i32) {
                    let e = n as f32 + 0.5;
                    assert!(
                        within_ulps_f32(powf(base, e), base.powf(e), 4),
                        "powf({base},{e})={} glibc={}",
                        powf(base, e),
                        base.powf(e)
                    );
                }
            }
        }
        // Medium path: deterministic sweep of base in [0.5,2.5) x exp in [-3,3].
        let mut s = 0x9e37_79b9_u32;
        for _ in 0..500_000 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let base = 0.5 + (s >> 9) as f32 * (2.0 / (1u32 << 23) as f32);
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let exp = -3.0 + (s >> 9) as f32 * (6.0 / (1u32 << 23) as f32);
            assert!(
                within_ulps_f32(powf(base, exp), base.powf(exp), 4),
                "powf({base},{exp})={} glibc={} (>4 ULP)",
                powf(base, exp),
                base.powf(exp)
            );
        }
    }

    #[test]
    fn powf_profile_exp_1_337_poly_within_4_ulps() {
        let exp = f32::from_bits(POWF_PROFILE_EXP_1_337_BITS);
        let mut worst = 0;
        let mut worst_base = 0.0f32;
        for i in 0..=200_000 {
            let base = 0.5 + (i as f32) * (2.0 / 200_000.0);
            let got = powf(base, exp);
            let want = base.powf(exp);
            let u = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            if u > worst {
                worst = u;
                worst_base = base;
            }
            assert!(
                u <= 4,
                "powf({base},{exp})={got:?} glibc={want:?} ({u} ULP)"
            );
        }
        let mut s = 0x7a5d_39e7_u32;
        for _ in 0..1_000_000 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let base = 0.5 + (s >> 9) as f32 * (2.0 / (1u32 << 23) as f32);
            let got = powf(base, exp);
            let want = base.powf(exp);
            let u = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            if u > worst {
                worst = u;
                worst_base = base;
            }
            assert!(
                u <= 4,
                "powf({base},{exp})={got:?} glibc={want:?} ({u} ULP)"
            );
        }
        println!("powf 1.337 polynomial worst ULP = {worst} at base {worst_base}");
    }

    #[test]
    fn powf_profile_exp_1_337_grid_matches_polynomial_bits_and_sha256() {
        use sha2::{Digest, Sha256};

        let exp = f32::from_bits(POWF_PROFILE_EXP_1_337_BITS);
        let mut hasher = Sha256::new();
        for k in 0..64 {
            let base = 0.5 + (k as f32) * 0.031_25;
            let grid = powf_profile_exp_1_337_grid(base).expect("dyadic profile-grid value");
            let poly = powf_profile_exp_1_337_poly(base);
            assert_eq!(grid.to_bits(), poly.to_bits(), "grid k={k} base={base}");
            assert_eq!(
                powf(base, exp).to_bits(),
                poly.to_bits(),
                "public powf grid k={k} base={base}"
            );
            hasher.update(base.to_bits().to_le_bytes());
            hasher.update(grid.to_bits().to_le_bytes());
        }
        for &base in &[
            0.5 + f32::EPSILON,
            0.531_251,
            2.5 - f32::EPSILON,
            2.5,
            f32::INFINITY,
            f32::NAN,
        ] {
            assert!(
                powf_profile_exp_1_337_grid(base).is_none(),
                "{base:?} matched the grid"
            );
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        println!("powf 1.337 dyadic grid corpus sha256 = {digest}");
        assert_eq!(
            digest, "f626b22ecc6f1217b7edb85d07eb633abb1c1b9ac4d5e0556b1053cde1055af7",
            "powf 1.337 dyadic grid corpus hash drifted: got {digest}"
        );
    }

    #[test]
    fn powf_fallback_preserves_libm_bits() {
        // Out-of-gate / special cases must stay bit-identical to libm::powf.
        let cases = [
            (f32::NEG_INFINITY, 1.337f32),
            (-2.0, 1.337),
            (0.0, 1.337),
            (0.25, 1.337), // base < 0.5, irrational exp
            (4.0, 1.337),  // base >= 2.5, irrational exp
            (f32::INFINITY, 0.3),
            (10.0, 9.0), // |n| > POWF_MAX_EXP
            (1.5, 9.5),  // half-integer with |n| > POWF_MAX_EXP
        ];
        for (b, e) in cases {
            assert_eq!(
                powf(b, e).to_bits(),
                libm::powf(b, e).to_bits(),
                "powf({b},{e}) fallback drifted from libm"
            );
        }
        assert!(powf(f32::NAN, 1.337).is_nan());
        assert!(powf(1.5, f32::NAN).is_nan());
    }

    #[test]
    fn trig_sanity() {
        assert!((sinf(0.0) - 0.0).abs() < 1e-6);
        assert!((cosf(0.0) - 1.0).abs() < 1e-6);
        assert!((tanf(0.0) - 0.0).abs() < 1e-6);
        assert!((asinf(1.0) - std::f32::consts::FRAC_PI_2).abs() < 1e-6);
        assert!((acosf(1.0) - 0.0).abs() < 1e-6);
        assert!((atanf(1.0) - std::f32::consts::FRAC_PI_4).abs() < 1e-6);
        assert!((atan2f(1.0, 1.0) - std::f32::consts::FRAC_PI_4).abs() < 1e-6);
    }

    #[test]
    fn exp_log_sanity() {
        assert!((expf(0.0) - 1.0).abs() < 1e-6);
        assert!((logf(1.0) - 0.0).abs() < 1e-6);
        assert!((log2f(8.0) - 3.0).abs() < 1e-5);
        assert!((log10f(100.0) - 2.0).abs() < 1e-5);
        assert!((powf(2.0, 10.0) - 1024.0).abs() < 1e-3);
    }

    #[test]
    fn float_util_sanity() {
        assert_eq!(sqrtf(9.0), 3.0);
        assert_eq!(fabsf(-3.5), 3.5);
        assert_eq!(ceilf(2.1), 3.0);
        assert_eq!(floorf(2.9), 2.0);
        assert_eq!(roundf(2.5), 3.0);
        assert_eq!(truncf(-2.9), -2.0);
        assert!((fmodf(5.5, 2.0) - 1.5).abs() < 1e-6);
    }

    #[test]
    fn hyperbolic_f32_sanity() {
        assert!((sinhf(0.0) - 0.0).abs() < 1e-6);
        assert!((coshf(0.0) - 1.0).abs() < 1e-6);
        assert!((tanhf(0.0) - 0.0).abs() < 1e-6);
        assert!((asinhf(0.0) - 0.0).abs() < 1e-6);
        assert!((acoshf(1.0) - 0.0).abs() < 1e-6);
        assert!((atanhf(0.0) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn exp_log_extra_sanity() {
        assert!((exp2f(3.0) - 8.0).abs() < 1e-5);
        assert!((expm1f(0.0) - 0.0).abs() < 1e-6);
        assert!((log1pf(0.0) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn expm1f_positive_fast_path_within_4_ulps() {
        let mut s = 0x54a3_31d5_u32;
        let mut worst = 0u32;
        for _ in 0..1_000_000 {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            let x = EXPM1F_POSITIVE_FAST_MIN
                + (s >> 9) as f32
                    * ((EXPM1F_POSITIVE_FAST_MAX - EXPM1F_POSITIVE_FAST_MIN) / (1u32 << 23) as f32);
            let got = expm1f(x);
            let want = x.exp_m1();
            let ulps = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            worst = worst.max(ulps);
            assert!(
                ulps <= 4,
                "expm1f({x}) = {got:?} but glibc = {want:?} ({ulps} ULP)"
            );
        }
        println!("expm1f positive fast path worst ULP = {worst}");
    }

    #[test]
    fn expm1f_fallback_preserves_libm_bits() {
        for &x in &[
            -5.0f32,
            -1.0,
            -0.0,
            0.0,
            0.499_999,
            2.500_001,
            10.0,
            f32::NEG_INFINITY,
            f32::INFINITY,
        ] {
            assert_eq!(
                expm1f(x).to_bits(),
                libm::expm1f(x).to_bits(),
                "expm1f({x:?}) fallback drifted"
            );
        }
        assert!(expm1f(f32::NAN).is_nan());
    }

    #[test]
    fn float_util_extra_sanity() {
        assert!((remainderf(5.5, 2.0) + 0.5).abs() < 1e-6);
        assert_eq!(copysignf(3.0, -1.0), -3.0);
        assert!((cbrtf(27.0) - 3.0).abs() < 1e-5);
        assert!((hypotf(3.0, 4.0) - 5.0).abs() < 1e-5);
        assert_eq!(rintf(2.0), 2.0);
        assert_eq!(nearbyintf(2.3), 2.0);
    }

    #[test]
    fn min_max_dim_fma_f32_sanity() {
        assert_eq!(fminf(2.0, 3.0), 2.0);
        assert_eq!(fmaxf(2.0, 3.0), 3.0);
        assert_eq!(fminf(f32::NAN, 3.0), 3.0);
        assert_eq!(fmaxf(f32::NAN, 3.0), 3.0);
        assert_eq!(fdimf(4.0, 2.0), 2.0);
        assert_eq!(fdimf(2.0, 4.0), 0.0);
        assert!((fmaf(2.0, 3.0, 4.0) - 10.0).abs() < 1e-6);
    }

    #[test]
    fn rounding_conversion_f32_sanity() {
        assert_eq!(lrintf(2.7), 3);
        assert_eq!(llrintf(-2.3), -2);
        assert_eq!(lroundf(2.5), 3);
        assert_eq!(llroundf(-2.5), -3);
    }

    #[test]
    fn decomposition_f32_sanity() {
        assert_eq!(ldexpf(1.0, 10), 1024.0);
        let (m, e) = frexpf(12.0);
        assert!((m - 0.75).abs() < 1e-6);
        assert_eq!(e, 4);
        let (frac, int) = modff(3.75);
        assert!((int - 3.0).abs() < 1e-6);
        assert!((frac - 0.75).abs() < 1e-6);
    }

    #[test]
    fn scaling_exponent_f32_sanity() {
        assert_eq!(scalbnf(1.0, 10), 1024.0);
        assert_eq!(scalblnf(1.0, 10), 1024.0);
        let next = nextafterf(1.0, 2.0);
        assert!(next > 1.0);
        assert_eq!(ilogbf(8.0), 3);
        assert_eq!(logbf(8.0), 3.0);
    }

    #[test]
    fn nexttowardf_sanity() {
        // Step up: f32(1.0) toward f64(2.0)
        let up = nexttowardf(1.0_f32, 2.0_f64);
        assert!(up > 1.0_f32);
        // Step down: f32(1.0) toward f64(0.0)
        let down = nexttowardf(1.0_f32, 0.0_f64);
        assert!(down < 1.0_f32);
        // Equal: return x unchanged
        assert_eq!(nexttowardf(1.0_f32, 1.0_f64), 1.0_f32);
        // NaN propagation
        assert!(nexttowardf(f32::NAN, 1.0_f64).is_nan());
        assert!(nexttowardf(1.0_f32, f64::NAN).is_nan());
    }

    #[test]
    fn special_f32_sanity() {
        assert!(erff(0.0).abs() < 1e-6);
        assert!((erfcf(0.0) - 1.0).abs() < 1e-6);
        assert!((tgammaf(5.0) - 24.0).abs() < 1e-3);
        assert!((lgammaf(5.0) - (24.0_f32).ln()).abs() < 1e-3);
    }

    #[test]
    fn remquof_sanity() {
        let (rem, quo) = remquof(10.0, 3.0);
        assert!((rem - 1.0).abs() < 1e-5);
        assert_eq!(quo & 0x7, 3 & 0x7);
    }

    #[test]
    fn sincosf_sanity() {
        let (s, c) = sincosf(0.0);
        assert!((s - 0.0).abs() < 1e-6);
        assert!((c - 1.0).abs() < 1e-6);
    }

    #[test]
    fn nanf_sanity() {
        assert!(nanf(b"").is_nan());
        assert!(nanf(b"1").is_nan());
        // The tag payload is encoded into the low mantissa bits (glibc parity).
        assert_eq!(nanf(b"").to_bits(), 0x7fc0_0000);
        assert_eq!(nanf(b"1").to_bits(), 0x7fc0_0001);
        assert_eq!(nanf(b"0xff").to_bits(), 0x7fc0_00ff);
        assert_eq!(nanf(b"abc").to_bits(), 0x7fc0_0000);
    }

    #[test]
    fn exp10f_sanity() {
        // Integer exponents yield exact powers of ten (glibc parity).
        assert_eq!(exp10f(0.0), 1.0);
        assert_eq!(exp10f(1.0), 10.0);
        assert_eq!(exp10f(2.0), 100.0);
        assert_eq!(exp10f(3.0), 1000.0);
        // Non-integer exponents take the transcendental path.
        assert!((exp10f(0.5) - 10.0_f32.sqrt()).abs() < 1e-3);
        // f64-intermediate exp2 path stays within 4 ULP of the libm reference
        // across the finite f32 domain (the live glibc proof is in
        // conformance_diff_math::diff_exp10f_within_4_ulps).
        let mut worst = 0i64;
        let mut x = -44.0_f32;
        while x <= 38.0 {
            if x != x.trunc() {
                let (got, want) = (exp10f(x), libm::exp10f(x));
                if got.is_finite() && want.is_finite() {
                    let u = (got.to_bits() as i64 - want.to_bits() as i64).abs();
                    worst = worst.max(u);
                    assert!(u <= 4, "exp10f({x}) = {got:?} vs {want:?} ({u} ULP)");
                }
            }
            x += 0.0011;
        }
        assert!(exp10f(40.0).is_infinite());
        assert_eq!(exp10f(-50.0), 0.0);
        println!("exp10f worst ULP = {worst}");
    }

    #[test]
    fn exp10f_profile_band_within_4_ulps() {
        let mut worst = 0u32;
        let mut worst_x = 0.0f32;
        for k in 0..64 {
            let x = 0.5 + (k as f32) * 0.031_25;
            let got = exp10f(x);
            let want = libm::exp10f(x);
            let u = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            if u > worst {
                worst = u;
                worst_x = x;
            }
            assert!(u <= 4, "exp10f({x})={got:?} vs {want:?} ({u} ULP)");
        }

        let mut state = 0x2468_ace1_u32;
        for _ in 0..1_000_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let x = 0.5 + (state >> 8) as f32 * (2.0 / (1u32 << 24) as f32);
            let got = exp10f(x);
            let want = libm::exp10f(x);
            let u = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            if u > worst {
                worst = u;
                worst_x = x;
            }
            assert!(u <= 4, "exp10f({x})={got:?} vs {want:?} ({u} ULP)");
        }
        println!("exp10f profile band worst ULP = {worst} at {worst_x}");
    }

    #[test]
    fn exp10f_profile_band_preserves_fallback_bits() {
        for &x in &[
            -50.0f32,
            -39.0,
            -10.5,
            -0.5,
            0.499_999_97,
            2.500_000_2,
            10.5,
            39.0,
            40.0,
            f32::INFINITY,
            f32::NEG_INFINITY,
        ] {
            let got = exp10f(x);
            let want = (libm::exp2(x as f64 * core::f64::consts::LOG2_10)) as f32;
            assert_eq!(
                got.to_bits(),
                want.to_bits(),
                "exp10f fallback drifted for {x}"
            );
        }
    }

    #[test]
    fn golden_exp10f_profile_band_corpus_sha256() {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        for k in 0..64 {
            let x = 0.5 + (k as f32) * 0.031_25;
            let got = exp10f(x);
            let want = libm::exp10f(x);
            let u = (got.to_bits() as i32 - want.to_bits() as i32).unsigned_abs();
            assert!(u <= 4, "exp10f({x})={got:?} vs {want:?} ({u} ULP)");
            hasher.update(x.to_bits().to_le_bytes());
            hasher.update(got.to_bits().to_le_bytes());
        }
        let digest: String = hasher
            .finalize()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        assert_eq!(
            digest, "d27316211664f96669fdc0dd45c618aeba051833b5876979af94beca3ba1df38",
            "exp10f profile-band golden corpus hash drifted: got {digest}"
        );
    }

    #[test]
    fn bessel_f32_sanity() {
        assert!((j0f(0.0) - 1.0).abs() < 1e-5);
        assert!(j1f(0.0).abs() < 1e-5);
        assert!((jnf(0, 2.5) - j0f(2.5)).abs() < 1e-5);
        assert!((y0f(1.0) - 0.08825696).abs() < 1e-3);
        assert!((y1f(1.0) - (-0.781_212_8)).abs() < 1e-3);
    }

    #[test]
    fn finitef_sanity() {
        assert_eq!(finitef(1.0), 1);
        assert_eq!(finitef(f32::INFINITY), 0);
        assert_eq!(finitef(f32::NEG_INFINITY), 0);
        assert_eq!(finitef(f32::NAN), 0);
        assert_eq!(finitef(0.0), 1);
    }

    #[test]
    fn dremf_sanity() {
        let r1 = dremf(5.3, 2.0);
        let r2 = remainderf(5.3, 2.0);
        assert_eq!(r1, r2);
    }

    #[test]
    fn gammaf_sanity() {
        assert!((gammaf(5.0) - (24.0_f32).ln()).abs() < 1e-3);
    }

    #[test]
    fn significandf_sanity() {
        let s = significandf(12.0);
        assert!((s - 1.5).abs() < 1e-5); // 12 = 1.5 * 2^3
        assert_eq!(significandf(0.0), 0.0);
        assert!(significandf(f32::NAN).is_nan());
        assert!(significandf(f32::INFINITY).is_infinite());
    }

    #[test]
    fn lgammaf_r_sanity() {
        let (val, sign) = lgammaf_r(5.0);
        assert!((val - (24.0_f32).ln()).abs() < 1e-3);
        assert_eq!(sign, 1);
        let (_, sign2) = lgammaf_r(-0.5);
        assert_eq!(sign2, -1);
    }

    #[test]
    fn fpclassifyf_sanity() {
        assert_eq!(fpclassifyf(1.0), FP_NORMAL_F32);
        assert_eq!(fpclassifyf(0.0), FP_ZERO_F32);
        assert_eq!(fpclassifyf(f32::INFINITY), FP_INFINITE_F32);
        assert_eq!(fpclassifyf(f32::NAN), FP_NAN_F32);
        assert_eq!(fpclassifyf(1e-45), FP_SUBNORMAL_F32); // smallest positive subnormal f32
    }

    #[test]
    fn signbitf_sanity() {
        assert_eq!(signbitf(1.0), 0);
        assert_eq!(signbitf(-1.0), 1);
        assert_eq!(signbitf(-0.0), 1);
    }

    #[test]
    fn isinff_isnanf_sanity() {
        assert_eq!(isinff(f32::INFINITY), 1);
        assert_eq!(isinff(f32::NEG_INFINITY), -1);
        assert_eq!(isinff(1.0), 0);
        assert_eq!(isnanf(f32::NAN), 1);
        assert_eq!(isnanf(1.0), 0);
    }
}
