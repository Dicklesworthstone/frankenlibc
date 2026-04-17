//! Trigonometric functions.

#[inline]
pub fn sin(x: f64) -> f64 {
    libm::sin(x)
}

#[inline]
pub fn cos(x: f64) -> f64 {
    libm::cos(x)
}

#[inline]
pub fn tan(x: f64) -> f64 {
    libm::tan(x)
}

#[inline]
pub fn asin(x: f64) -> f64 {
    libm::asin(x)
}

#[inline]
pub fn acos(x: f64) -> f64 {
    libm::acos(x)
}

#[inline]
pub fn atan(x: f64) -> f64 {
    libm::atan(x)
}

#[inline]
pub fn atan2(y: f64, x: f64) -> f64 {
    libm::atan2(y, x)
}

#[inline]
pub fn sinh(x: f64) -> f64 {
    libm::sinh(x)
}

#[inline]
pub fn cosh(x: f64) -> f64 {
    libm::cosh(x)
}

#[inline]
pub fn tanh(x: f64) -> f64 {
    libm::tanh(x)
}

#[inline]
pub fn asinh(x: f64) -> f64 {
    libm::asinh(x)
}

#[inline]
pub fn acosh(x: f64) -> f64 {
    libm::acosh(x)
}

#[inline]
pub fn atanh(x: f64) -> f64 {
    libm::atanh(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::f64::consts::{PI, TAU};
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
    fn trig_sanity() {
        let x = 0.5_f64;
        assert!((sin(x) - x.sin()).abs() < 1e-12);
        assert!((cos(x) - x.cos()).abs() < 1e-12);
        assert!((tan(x) - x.tan()).abs() < 1e-12);
        assert!((asin(x) - x.asin()).abs() < 1e-12);
        assert!((acos(x) - x.acos()).abs() < 1e-12);
        assert!((atan(x) - x.atan()).abs() < 1e-12);
        assert!((atan2(1.0, 2.0) - 1.0_f64.atan2(2.0)).abs() < 1e-12);
        assert!((sinh(x) - x.sinh()).abs() < 1e-12);
        assert!((cosh(x) - x.cosh()).abs() < 1e-12);
        assert!((tanh(x) - x.tanh()).abs() < 1e-12);
        assert!((asinh(x) - x.asinh()).abs() < 1e-12);
        assert!((acosh(1.5) - 1.5_f64.acosh()).abs() < 1e-12);
        assert!((atanh(x) - x.atanh()).abs() < 1e-12);
    }

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_sin_is_odd(x in -1_000.0f64..1_000.0f64) {
            let lhs = sin(-x);
            let rhs = -sin(x);
            prop_assert!((lhs - rhs).abs() <= 1e-11);
        }

        #[test]
        fn prop_cos_is_even(x in -1_000.0f64..1_000.0f64) {
            let lhs = cos(-x);
            let rhs = cos(x);
            prop_assert!((lhs - rhs).abs() <= 1e-11);
        }

        #[test]
        fn prop_sin_asin_round_trip(x in -1.0f64..1.0f64) {
            let round_trip = sin(asin(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_cos_acos_round_trip(x in -1.0f64..1.0f64) {
            let round_trip = cos(acos(x));
            prop_assert!(approx_eq(round_trip, x, 1e-12, 1e-11));
        }

        #[test]
        fn prop_sin_has_tau_periodicity(x in -100.0f64..100.0f64) {
            let shifted = sin(x + TAU);
            let base = sin(x);
            prop_assert!(approx_eq(shifted, base, 1e-12, 1e-11));
        }

        #[test]
        fn prop_cos_has_tau_periodicity(x in -100.0f64..100.0f64) {
            let shifted = cos(x + TAU);
            let base = cos(x);
            prop_assert!(approx_eq(shifted, base, 1e-12, 1e-11));
        }

        #[test]
        fn prop_tan_has_pi_periodicity_away_from_poles(x in -1.25f64..1.25f64) {
            let shifted = tan(x + PI);
            let base = tan(x);
            prop_assert!(approx_eq(shifted, base, 1e-12, 1e-11));
        }

        #[test]
        fn prop_sin_cos_satisfy_pythagorean_identity(x in -100.0f64..100.0f64) {
            let s = sin(x);
            let c = cos(x);
            prop_assert!(approx_eq(s.mul_add(s, c * c), 1.0, 1e-12, 1e-10));
        }

        #[test]
        fn prop_atan2_is_invariant_under_positive_scaling(
            y in -1_000.0f64..1_000.0f64,
            x in -1_000.0f64..1_000.0f64,
            scale in 0.125f64..8.0f64
        ) {
            prop_assume!(x.abs() > 1e-9 || y.abs() > 1e-9);

            let base = atan2(y, x);
            let scaled = atan2(y * scale, x * scale);
            prop_assert!(approx_eq(scaled, base, 1e-12, 1e-11));
        }

        #[test]
        fn prop_sinh_is_odd(x in -100.0f64..100.0f64) {
            let lhs = sinh(-x);
            let rhs = -sinh(x);
            prop_assert!((lhs - rhs).abs() <= 1e-11);
        }

        #[test]
        fn prop_tanh_is_odd(x in -100.0f64..100.0f64) {
            let lhs = tanh(-x);
            let rhs = -tanh(x);
            prop_assert!((lhs - rhs).abs() <= 1e-11);
        }
    }
}
