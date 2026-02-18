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
pub fn fmodf(x: f32, y: f32) -> f32 {
    libm::fmodf(x, y)
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
}
