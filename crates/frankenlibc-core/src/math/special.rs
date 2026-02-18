//! Special mathematical functions.

#[inline]
pub fn erf(x: f64) -> f64 {
    libm::erf(x)
}

#[inline]
pub fn tgamma(x: f64) -> f64 {
    libm::tgamma(x)
}

#[inline]
pub fn lgamma(x: f64) -> f64 {
    libm::lgamma(x)
}

/// Complementary error function: 1 - erf(x).
#[inline]
pub fn erfc(x: f64) -> f64 {
    libm::erfc(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erf_sanity() {
        assert!(erf(0.0).abs() < 1e-12);
        assert!((erf(1.0) - 0.8427).abs() < 5e-4);
    }

    #[test]
    fn gamma_sanity() {
        assert!((tgamma(5.0) - 24.0).abs() < 1e-8);
        assert!((lgamma(5.0) - 24.0_f64.ln()).abs() < 1e-8);
    }

    #[test]
    fn erfc_sanity() {
        // erfc(x) = 1 - erf(x)
        assert!((erfc(0.0) - 1.0).abs() < 1e-12);
        assert!((erfc(1.0) - (1.0 - erf(1.0))).abs() < 1e-12);
    }
}
