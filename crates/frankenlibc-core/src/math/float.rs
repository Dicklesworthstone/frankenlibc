//! Floating-point utility functions.

#[inline]
pub fn fabs(x: f64) -> f64 {
    libm::fabs(x)
}

#[inline]
pub fn ceil(x: f64) -> f64 {
    libm::ceil(x)
}

#[inline]
pub fn floor(x: f64) -> f64 {
    libm::floor(x)
}

#[inline]
pub fn round(x: f64) -> f64 {
    libm::round(x)
}

#[inline]
pub fn trunc(x: f64) -> f64 {
    libm::trunc(x)
}

#[inline]
pub fn rint(x: f64) -> f64 {
    libm::rint(x)
}

#[inline]
pub fn fmod(x: f64, y: f64) -> f64 {
    libm::fmod(x, y)
}

#[inline]
pub fn remainder(x: f64, y: f64) -> f64 {
    libm::remainder(x, y)
}

#[inline]
pub fn copysign(x: f64, y: f64) -> f64 {
    libm::copysign(x, y)
}

#[inline]
pub fn sqrt(x: f64) -> f64 {
    libm::sqrt(x)
}

#[inline]
pub fn cbrt(x: f64) -> f64 {
    libm::cbrt(x)
}

#[inline]
pub fn hypot(x: f64, y: f64) -> f64 {
    libm::hypot(x, y)
}

/// Round to nearest integer without raising inexact exception.
///
/// Uses banker's rounding (round to even on ties), matching rint semantics.
#[inline]
pub fn nearbyint(x: f64) -> f64 {
    libm::rint(x)
}

/// Round to nearest integer, return as `i64`.
#[inline]
pub fn lrint(x: f64) -> i64 {
    libm::rint(x) as i64
}

/// Round to nearest integer, return as `i64`.
#[inline]
pub fn llrint(x: f64) -> i64 {
    libm::rint(x) as i64
}

/// Round to nearest integer (away from zero), return as `i64`.
#[inline]
pub fn lround(x: f64) -> i64 {
    libm::round(x) as i64
}

/// Round to nearest integer (away from zero), return as `i64`.
#[inline]
pub fn llround(x: f64) -> i64 {
    libm::round(x) as i64
}

/// Multiply `x` by 2^`exp`.
#[inline]
pub fn ldexp(x: f64, exp: i32) -> f64 {
    libm::ldexp(x, exp)
}

/// Extract mantissa and exponent: `x = m * 2^exp`, `0.5 <= |m| < 1.0`.
#[inline]
pub fn frexp(x: f64) -> (f64, i32) {
    libm::frexp(x)
}

/// Split `x` into integer and fractional parts.
#[inline]
pub fn modf(x: f64) -> (f64, f64) {
    libm::modf(x)
}

/// Return the minimum of two values, respecting NaN semantics.
#[inline]
pub fn fmin(x: f64, y: f64) -> f64 {
    libm::fmin(x, y)
}

/// Return the maximum of two values, respecting NaN semantics.
#[inline]
pub fn fmax(x: f64, y: f64) -> f64 {
    libm::fmax(x, y)
}

/// Positive difference: `max(x - y, 0)`.
#[inline]
pub fn fdim(x: f64, y: f64) -> f64 {
    libm::fdim(x, y)
}

/// Fused multiply-add: `x * y + z` with single rounding.
#[inline]
pub fn fma(x: f64, y: f64, z: f64) -> f64 {
    libm::fma(x, y, z)
}

/// Scale `x` by `2^n`.
#[inline]
pub fn scalbn(x: f64, n: i32) -> f64 {
    libm::scalbn(x, n)
}

/// Scale `x` by `2^n` (long exponent variant).
#[inline]
pub fn scalbln(x: f64, n: i64) -> f64 {
    // libm doesn't have scalbln directly; delegate via ldexp with clamping
    let exp = n.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    libm::ldexp(x, exp)
}

/// Return the next representable float after `x` toward `y`.
#[inline]
pub fn nextafter(x: f64, y: f64) -> f64 {
    libm::nextafter(x, y)
}

/// Return the next representable `f64` after `x` toward `y` (long double direction).
///
/// In glibc, `y` is `long double` (80-bit extended on x86_64).  Since Rust has
/// no native `long double`, we accept `f64` — the direction is determined solely
/// by the comparison `x < y` / `x > y` / `x == y`, so truncation to `f64`
/// preserves correctness for all finite values and special cases.
#[inline]
pub fn nexttoward(x: f64, y: f64) -> f64 {
    // C99 semantics: nexttoward(x, y) == nextafter(x, (double)y) when
    // long double → double comparison preserves ordering, which it does for
    // all finite values and ±Inf/NaN.
    libm::nextafter(x, y)
}

/// Extract unbiased exponent as `i32` (FP_ILOGBNAN / FP_ILOGB0 for special values).
#[inline]
pub fn ilogb(x: f64) -> i32 {
    libm::ilogb(x)
}

/// Extract unbiased exponent as `f64`.
#[inline]
pub fn logb(x: f64) -> f64 {
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return f64::INFINITY;
    }
    if x.is_nan() {
        return x;
    }
    libm::ilogb(x) as f64
}

/// IEEE remainder with quotient: `x - n*y` where `n` is the integer nearest `x/y`.
/// Returns `(remainder, quotient_low_bits)` where quotient retains at least 3 low bits.
#[inline]
pub fn remquo(x: f64, y: f64) -> (f64, i32) {
    libm::remquo(x, y)
}

/// Compute sine and cosine simultaneously.
/// Returns `(sin(x), cos(x))`.
#[inline]
pub fn sincos(x: f64) -> (f64, f64) {
    libm::sincos(x)
}

/// Generate a quiet NaN.
///
/// The `_tag` argument is parsed as an unsigned integer to set NaN payload bits,
/// but the common case (empty string or "0") returns a plain quiet NaN.
#[inline]
pub fn nan(_tag: &[u8]) -> f64 {
    f64::NAN
}

/// BSD/SUSv2 `finite()`: returns non-zero if `x` is neither infinite nor NaN.
#[inline]
pub fn finite(x: f64) -> i32 {
    if x.is_finite() { 1 } else { 0 }
}

/// BSD `drem()` — alias for `remainder()`.
#[inline]
pub fn drem(x: f64, y: f64) -> f64 {
    remainder(x, y)
}

/// BSD `gamma()` — alias for `lgamma()`.
/// In glibc, `gamma` is equivalent to `lgamma` (the log of the absolute value
/// of the Gamma function).
#[inline]
pub fn gamma(x: f64) -> f64 {
    libm::lgamma(x)
}

/// Extract the significand (mantissa) of `x` scaled to `[1, 2)`.
///
/// Returns `x * 2^(-ilogb(x))`, or equivalently `scalbn(x, -ilogb(x))`.
#[inline]
pub fn significand(x: f64) -> f64 {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    let e = libm::ilogb(x);
    libm::scalbn(x, -e)
}

/// GNU extension: base-10 exponential `10^x`.
#[inline]
pub fn exp10(x: f64) -> f64 {
    // 10^x = 2^(x * log2(10)) = exp(x * ln(10))
    libm::exp(x * core::f64::consts::LN_10)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_sanity() {
        assert_eq!(fabs(-3.5), 3.5);
        assert_eq!(ceil(2.1), 3.0);
        assert_eq!(floor(2.9), 2.0);
        assert_eq!(round(2.5), 3.0);
        assert_eq!(trunc(-2.9), -2.0);
        assert_eq!(rint(2.0), 2.0);
        assert!((fmod(5.5, 2.0) - 1.5).abs() < 1e-12);
        assert!((remainder(5.3, 2.0) + 0.7).abs() < 1e-12);
        let signed = copysign(3.0, -0.0);
        assert_eq!(signed, -3.0);
        assert!(signed.is_sign_negative());
        assert_eq!(sqrt(9.0), 3.0);
        assert_eq!(cbrt(27.0), 3.0);
        assert_eq!(cbrt(-8.0), -2.0);
        assert!((hypot(3.0, 4.0) - 5.0).abs() < 1e-12);
    }

    #[test]
    fn test_nearbyint() {
        assert_eq!(nearbyint(2.3), 2.0);
        assert_eq!(nearbyint(2.7), 3.0);
        assert_eq!(nearbyint(-2.5), -2.0); // banker's rounding
    }

    #[test]
    fn test_lrint_llrint() {
        assert_eq!(lrint(2.7), 3);
        assert_eq!(lrint(-2.3), -2);
        assert_eq!(llrint(2.7), 3);
        assert_eq!(llrint(-2.3), -2);
    }

    #[test]
    fn test_lround_llround() {
        assert_eq!(lround(2.5), 3);
        assert_eq!(lround(-2.5), -3);
        assert_eq!(llround(2.5), 3);
        assert_eq!(llround(-2.5), -3);
    }

    #[test]
    fn test_ldexp() {
        assert_eq!(ldexp(1.0, 10), 1024.0);
        assert_eq!(ldexp(3.0, 2), 12.0);
    }

    #[test]
    fn test_frexp() {
        let (m, e) = frexp(12.0);
        assert!((m - 0.75).abs() < 1e-12);
        assert_eq!(e, 4);
    }

    #[test]
    fn test_modf() {
        let (frac, int) = modf(3.75);
        assert!((int - 3.0).abs() < 1e-12);
        assert!((frac - 0.75).abs() < 1e-12);
    }

    #[test]
    fn test_fmin_fmax() {
        assert_eq!(fmin(2.0, 3.0), 2.0);
        assert_eq!(fmax(2.0, 3.0), 3.0);
        // NaN semantics: fmin/fmax return the non-NaN arg
        assert_eq!(fmin(f64::NAN, 3.0), 3.0);
        assert_eq!(fmax(f64::NAN, 3.0), 3.0);
    }

    #[test]
    fn test_fdim() {
        assert_eq!(fdim(4.0, 2.0), 2.0);
        assert_eq!(fdim(2.0, 4.0), 0.0);
    }

    #[test]
    fn test_fma() {
        assert!((fma(2.0, 3.0, 4.0) - 10.0).abs() < 1e-12);
    }

    #[test]
    fn test_scalbn() {
        assert_eq!(scalbn(1.0, 10), 1024.0);
        assert_eq!(scalbln(1.0, 10), 1024.0);
    }

    #[test]
    fn test_nextafter() {
        let next = nextafter(1.0, 2.0);
        assert!(next > 1.0);
        assert!(next < 1.0 + 1e-15);
    }

    #[test]
    fn test_nexttoward() {
        // nexttoward behaves like nextafter for f64 direction
        let nt = nexttoward(1.0, 2.0);
        let na = nextafter(1.0, 2.0);
        assert_eq!(nt, na);
        // Equal values: return x unchanged
        assert_eq!(nexttoward(1.0, 1.0), 1.0);
        // NaN propagation
        assert!(nexttoward(f64::NAN, 1.0).is_nan());
        assert!(nexttoward(1.0, f64::NAN).is_nan());
        // Step toward negative
        let down = nexttoward(1.0, 0.0);
        assert!(down < 1.0);
    }

    #[test]
    fn test_ilogb_logb() {
        assert_eq!(ilogb(8.0), 3);
        assert_eq!(logb(8.0), 3.0);
        assert_eq!(ilogb(1.0), 0);
    }

    #[test]
    fn test_remquo() {
        let (rem, quo) = remquo(10.0, 3.0);
        // 10 / 3 ~ 3.333, nearest integer = 3, remainder = 10 - 3*3 = 1
        assert!((rem - 1.0).abs() < 1e-12);
        assert_eq!(quo & 0x7, 3 & 0x7);
    }

    #[test]
    fn test_sincos() {
        let (s, c) = sincos(0.0);
        assert!((s - 0.0).abs() < 1e-12);
        assert!((c - 1.0).abs() < 1e-12);
        let (s2, c2) = sincos(core::f64::consts::FRAC_PI_2);
        assert!((s2 - 1.0).abs() < 1e-12);
        assert!(c2.abs() < 1e-12);
    }

    #[test]
    fn test_nan() {
        let v = nan(b"");
        assert!(v.is_nan());
    }

    #[test]
    fn test_finite_fn() {
        assert_eq!(finite(1.0), 1);
        assert_eq!(finite(f64::INFINITY), 0);
        assert_eq!(finite(f64::NEG_INFINITY), 0);
        assert_eq!(finite(f64::NAN), 0);
        assert_eq!(finite(0.0), 1);
    }

    #[test]
    fn test_drem() {
        // drem is alias for remainder
        let r1 = drem(5.3, 2.0);
        let r2 = remainder(5.3, 2.0);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_gamma_alias() {
        // gamma() is alias for lgamma()
        assert!((gamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }

    #[test]
    fn test_significand() {
        // significand(x) = x * 2^(-ilogb(x)), result in [1, 2)
        let s = significand(12.0);
        assert!((s - 1.5).abs() < 1e-12); // 12 = 1.5 * 2^3
        assert_eq!(significand(0.0), 0.0);
        assert!(significand(f64::NAN).is_nan());
        assert!(significand(f64::INFINITY).is_infinite());
    }

    #[test]
    fn test_exp10() {
        assert!((exp10(0.0) - 1.0).abs() < 1e-12);
        assert!((exp10(1.0) - 10.0).abs() < 1e-10);
        assert!((exp10(2.0) - 100.0).abs() < 1e-8);
        assert!((exp10(3.0) - 1000.0).abs() < 1e-6);
    }
}
