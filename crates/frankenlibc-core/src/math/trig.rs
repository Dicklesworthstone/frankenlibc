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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

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
    }

    proptest! {
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
            prop_assert!((round_trip - x).abs() <= 1e-11);
        }
    }
}
