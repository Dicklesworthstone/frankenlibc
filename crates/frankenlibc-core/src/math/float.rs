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
}
