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

#[inline]
pub fn powf(base: f32, exponent: f32) -> f32 {
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

#[inline]
pub fn lrintf(x: f32) -> i64 {
    libm::rintf(x) as i64
}

#[inline]
pub fn llrintf(x: f32) -> i64 {
    libm::rintf(x) as i64
}

#[inline]
pub fn lroundf(x: f32) -> i64 {
    libm::roundf(x) as i64
}

#[inline]
pub fn llroundf(x: f32) -> i64 {
    libm::roundf(x) as i64
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn special_f32_sanity() {
        assert!(erff(0.0).abs() < 1e-6);
        assert!((erfcf(0.0) - 1.0).abs() < 1e-6);
        assert!((tgammaf(5.0) - 24.0).abs() < 1e-3);
        assert!((lgammaf(5.0) - (24.0_f32).ln()).abs() < 1e-3);
    }
}
