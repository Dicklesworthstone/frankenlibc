//! Single-precision (f32) mathematical functions.
//!
//! Mirrors the f64 functions from `float.rs`, `trig.rs`, and `exp.rs`
//! for the `*f` suffix variants (`sinf`, `cosf`, `sqrtf`, etc.).

// --- Trigonometric ---

#[inline]
pub fn sinf(x: f32) -> f32 {
    libm::sinf(x)
}

#[inline]
pub fn cosf(x: f32) -> f32 {
    libm::cosf(x)
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
    libm::expf(x)
}

#[inline]
pub fn logf(x: f32) -> f32 {
    libm::logf(x)
}

#[inline]
pub fn log2f(x: f32) -> f32 {
    libm::log2f(x)
}

#[inline]
pub fn log10f(x: f32) -> f32 {
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

/// Medium positive-base / bounded-exponent fast path: `exp2f(y*log2f(x))`,
/// bypassing libm::powf's full general classifier. Gated to the domain proven
/// within 4 ULP of glibc.
#[inline]
fn powf_medium_fast_path(base: f32, exponent: f32) -> Option<f32> {
    if (POWF_MEDIUM_BASE_MIN..POWF_MEDIUM_BASE_MAX).contains(&base)
        && (POWF_MEDIUM_EXP_MIN..=POWF_MEDIUM_EXP_MAX).contains(&exponent)
    {
        Some(libm::exp2f(exponent * libm::log2f(base)))
    } else {
        None
    }
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
            return powi_squaringf(base, n) as f32;
        }
        if exponent == 0.5 && base >= 0.0 {
            return base.sqrt();
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

#[inline]
pub fn sinhf(x: f32) -> f32 {
    libm::sinhf(x)
}

#[inline]
pub fn coshf(x: f32) -> f32 {
    libm::coshf(x)
}

#[inline]
pub fn tanhf(x: f32) -> f32 {
    libm::tanhf(x)
}

#[inline]
pub fn asinhf(x: f32) -> f32 {
    libm::asinhf(x)
}

#[inline]
pub fn acoshf(x: f32) -> f32 {
    libm::acoshf(x)
}

#[inline]
pub fn atanhf(x: f32) -> f32 {
    libm::atanhf(x)
}

// --- Exponential / logarithmic (additional) ---

#[inline]
pub fn exp2f(x: f32) -> f32 {
    libm::exp2f(x)
}

#[inline]
pub fn expm1f(x: f32) -> f32 {
    libm::expm1f(x)
}

#[inline]
pub fn log1pf(x: f32) -> f32 {
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
    libm::nextafterf(x, y)
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
    libm::ilogbf(x)
}

#[inline]
pub fn logbf(x: f32) -> f32 {
    if x == 0.0 {
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
pub fn erff(x: f32) -> f32 {
    libm::erff(x)
}

#[inline]
pub fn erfcf(x: f32) -> f32 {
    libm::erfcf(x)
}

#[inline]
pub fn lgammaf(x: f32) -> f32 {
    libm::lgammaf(x)
}

#[inline]
pub fn tgammaf(x: f32) -> f32 {
    libm::tgammaf(x)
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
    libm::expf(x * core::f32::consts::LN_10)
}

/// Bessel function of the first kind, order 0 (f32 variant).
#[inline]
pub fn j0f(x: f32) -> f32 {
    libm::j0f(x)
}

/// Bessel function of the first kind, order 1 (f32 variant).
#[inline]
pub fn j1f(x: f32) -> f32 {
    libm::j1f(x)
}

/// Bessel function of the first kind, order `n` (f32 variant).
#[inline]
pub fn jnf(n: i32, x: f32) -> f32 {
    libm::jnf(n, x)
}

/// Bessel function of the second kind, order 0 (f32 variant).
#[inline]
pub fn y0f(x: f32) -> f32 {
    libm::y0f(x)
}

/// Bessel function of the second kind, order 1 (f32 variant).
#[inline]
pub fn y1f(x: f32) -> f32 {
    libm::y1f(x)
}

/// Bessel function of the second kind, order `n` (f32 variant).
#[inline]
pub fn ynf(n: i32, x: f32) -> f32 {
    libm::ynf(n, x)
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
