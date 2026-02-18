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
    fn test_ilogb_logb() {
        assert_eq!(ilogb(8.0), 3);
        assert_eq!(logb(8.0), 3.0);
        assert_eq!(ilogb(1.0), 0);
    }
}
