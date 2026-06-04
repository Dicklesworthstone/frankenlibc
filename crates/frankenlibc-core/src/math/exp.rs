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

/// `base` raised to a small integer power via exponentiation by squaring.
/// `n.unsigned_abs()` must be small (the caller gates on `<= POWI_MAX_EXP`) so
/// the multiply chain stays well inside the 4-ULP glibc parity budget.
#[inline]
fn powi_squaring(base: f64, n: i64) -> f64 {
    let mut result = 1.0_f64;
    let mut b = base;
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

/// Largest |integer exponent| handled by the fast path. Each squaring/multiply
/// adds at most ~0.5 ULP; capping the magnitude here keeps the result within
/// the 4-ULP-vs-glibc contract (verified by `pow_integer_fast_path_within_4_ulps`).
const POWI_MAX_EXP: u64 = 8;

#[inline]
pub fn pow(base: f64, exponent: f64) -> f64 {
    // Fast path: small integer exponents (and y == 0.5) on a finite base.
    // libm::pow always routes through the general log2/exp2 path (~3.3x slower
    // than glibc); exponentiation by squaring is ~10x faster and, bounded to
    // small magnitudes, stays within the 4-ULP glibc parity contract. Non-finite
    // bases, large/non-integer exponents, etc. defer to libm for exact IEEE
    // special-case semantics.
    if base.is_finite() && exponent.is_finite() {
        let n = exponent as i64;
        if n as f64 == exponent && n.unsigned_abs() <= POWI_MAX_EXP {
            return powi_squaring(base, n);
        }
        if exponent == 0.5 && base >= 0.0 {
            return base.sqrt();
        }
    }
    libm::pow(base, exponent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn approx_eq(lhs: f64, rhs: f64, abs_tol: f64, rel_tol: f64) -> bool {
        let diff = (lhs - rhs).abs();
        diff <= abs_tol.max(rel_tol * lhs.abs().max(rhs.abs()))
    }

    /// 4-ULP comparison (the math conformance contract). `f64::powf` resolves
    /// to the host glibc `pow`, so this pins the fast path against glibc itself.
    fn within_ulps(a: f64, b: f64, ulps: u64) -> bool {
        if a == b {
            return true;
        }
        if a.is_nan() || b.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
            return false;
        }
        let ab = a.to_bits() as i64;
        let bb = b.to_bits() as i64;
        (ab - bb).unsigned_abs() <= ulps
    }

    #[test]
    fn pow_integer_fast_path_within_4_ulps() {
        // Sweep the gated fast-path domain (|n| <= POWI_MAX_EXP, plus 0.5) over a
        // wide spread of finite bases incl. negatives, zeros, sub/huge, and verify
        // every result is within 4 ULP of the host glibc pow (f64::powf).
        let bases = [
            0.0, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.14159, -3.14159, 1.785, 1e-3, -1e-3, 1e6,
            -1e6, 1e150, 1e-150, 123.456, -123.456, 0.999_999, 1.000_001,
        ];
        for &base in &bases {
            for n in -(POWI_MAX_EXP as i64)..=(POWI_MAX_EXP as i64) {
                let exp_f = n as f64;
                let got = pow(base, exp_f);
                let want = base.powf(exp_f);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, {exp_f}) = {got:?} but glibc = {want:?} (>4 ULP)"
                );
            }
            if base >= 0.0 {
                let got = pow(base, 0.5);
                let want = base.powf(0.5);
                assert!(
                    within_ulps(got, want, 4),
                    "pow({base}, 0.5) = {got:?} but glibc = {want:?}"
                );
            }
        }
    }

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

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_exp_turns_addition_into_multiplication(
            x in -20.0f64..20.0f64,
            y in -20.0f64..20.0f64
        ) {
            let lhs = exp(x + y);
            let rhs = exp(x) * exp(y);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log_of_exp_round_trips(x in -20.0f64..20.0f64) {
            let round_trip = log(exp(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_exp_of_log_round_trips(x in 1.0e-12f64..1.0e12f64) {
            let round_trip = exp(log(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log_turns_products_into_sums(
            x in 1.0e-6f64..1.0e6f64,
            y in 1.0e-6f64..1.0e6f64
        ) {
            let lhs = log(x * y);
            let rhs = log(x) + log(y);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_expm1_matches_exp_minus_one(x in -1.0f64..1.0f64) {
            let lhs = expm1(x);
            let rhs = exp(x) - 1.0;
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_log1p_matches_log_of_one_plus_x(x in -0.99f64..10.0f64) {
            let lhs = log1p(x);
            let rhs = log(1.0 + x);
            prop_assert!(approx_eq(lhs, rhs, 1e-12, 1e-11));
        }

        #[test]
        fn prop_pow_turns_added_exponents_into_multiplied_results(
            base in 1.0e-6f64..1.0e6f64,
            x in -5.0f64..5.0f64,
            y in -5.0f64..5.0f64
        ) {
            let lhs = pow(base, x + y);
            let rhs = pow(base, x) * pow(base, y);
            prop_assert!(approx_eq(lhs, rhs, 1e-10, 1e-10));
        }
    }
}
