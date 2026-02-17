//! Exponential and logarithmic functions.

#[inline]
pub fn exp(x: f64) -> f64 {
    libm::exp(x)
}

#[inline]
pub fn exp2(x: f64) -> f64 {
    libm::exp2(x)
}

#[inline]
pub fn expm1(x: f64) -> f64 {
    libm::expm1(x)
}

#[inline]
pub fn log(x: f64) -> f64 {
    libm::log(x)
}

#[inline]
pub fn log2(x: f64) -> f64 {
    libm::log2(x)
}

#[inline]
pub fn log10(x: f64) -> f64 {
    libm::log10(x)
}

#[inline]
pub fn log1p(x: f64) -> f64 {
    libm::log1p(x)
}

#[inline]
pub fn pow(base: f64, exponent: f64) -> f64 {
    libm::pow(base, exponent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exp_log_pow_sanity() {
        assert!((exp(1.0) - std::f64::consts::E).abs() < 1e-12);
        assert!((exp2(10.0) - 1024.0).abs() < 1e-12);
        assert!((expm1(1.0) - (std::f64::consts::E - 1.0)).abs() < 1e-12);
        assert!((log(std::f64::consts::E) - 1.0).abs() < 1e-12);
        assert!((log2(8.0) - 3.0).abs() < 1e-12);
        assert!((log10(1000.0) - 3.0).abs() < 1e-12);
        assert!((log1p(0.5) - 1.5_f64.ln()).abs() < 1e-12);
        assert!((pow(9.0, 0.5) - 3.0).abs() < 1e-12);
    }
}
