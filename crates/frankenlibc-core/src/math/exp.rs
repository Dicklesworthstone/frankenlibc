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
