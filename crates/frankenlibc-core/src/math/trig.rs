//! Trigonometric functions.

#[inline]
pub fn sin(x: f64) -> f64 {
    // CORE-MATH's correctly rounded sin. glibc's IBM sin is correctly rounded
    // on all but ~0.1% of inputs, so this differs from glibc ~20x less often
    // than libm::sin (3% in [-10, 10]; bd-otip6a).
    crate::math::coremath::sin(x)
}

#[inline]
pub fn cos(x: f64) -> f64 {
    // CORE-MATH's correctly rounded cos; see `sin` (bd-otip6a).
    crate::math::coremath::cos(x)
}

#[inline]
pub fn tan(x: f64) -> f64 {
    // CORE-MATH's correctly rounded tan; see `sin` (bd-otip6a).
    crate::math::coremath::tan(x)
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
    // CORE-MATH's correctly rounded atan. glibc's IBM atan is correctly rounded
    // on all but ~0.02-0.1% of inputs, so this differs from glibc 10-70x less
    // often than fdlibm's libm::atan did (1.4%; bd-otip6a).
    crate::math::coremath::atan(x)
}

#[inline]
pub fn atan2(y: f64, x: f64) -> f64 {
    libm::atan2(y, x)
}

// sinh/cosh/tanh are fdlibm's e_sinh.c / e_cosh.c / s_tanh.c (Sun Microsystems,
// freely redistributable with this notice: "Developed at SunSoft, a Sun
// Microsystems, Inc. business. Permission to use, copy, modify, and distribute
// this software is freely granted, provided that this notice is preserved."),
// the formulas glibc uses. Compiled in C on top of glibc's exp and expm1 they
// reproduce glibc 2.43 bit for bit (0 of 300k differences); fl's exp is
// bit-identical to glibc's, so what remains is fl's expm1 (bd-otip6a).

/// High and low 32-bit words of `x`.
#[inline(always)]
fn hi_lo(x: f64) -> (i32, u32) {
    let u = x.to_bits();
    ((u >> 32) as i32, u as u32)
}

#[inline]
pub fn sinh(x: f64) -> f64 {
    let (jx, lx) = hi_lo(x);
    let ix = jx & 0x7fff_ffff;
    if ix >= 0x7ff0_0000 {
        return x + x; // inf or NaN
    }
    let h = if jx < 0 { -0.5 } else { 0.5 };
    let ax = x.abs();
    if ix < 0x4036_0000 {
        // |x| < 22
        if ix < 0x3e30_0000 {
            return x; // |x| < 2^-28: sinh(x) rounds to x
        }
        let t = crate::math::expm1(ax);
        if ix < 0x3ff0_0000 {
            return h * (2.0 * t - t * t / (t + 1.0));
        }
        return h * (t + t / (t + 1.0));
    }
    if ix < 0x4086_2e42 {
        // |x| in [22, log(DBL_MAX)]
        return h * crate::math::exp(ax);
    }
    if ix < 0x4086_33ce || (ix == 0x4086_33ce && lx <= 0x8fb9_f87d) {
        // |x| in [log(DBL_MAX), overflow threshold]: split the exponential.
        let w = crate::math::exp(0.5 * ax);
        let t = h * w;
        return t * w;
    }
    x * 1.0e307 // overflow
}

#[inline]
pub fn cosh(x: f64) -> f64 {
    let (jx, lx) = hi_lo(x);
    let ix = jx & 0x7fff_ffff;
    if ix >= 0x7ff0_0000 {
        return x * x; // inf or NaN
    }
    let ax = x.abs();
    if ix < 0x3fd6_2e43 {
        // |x| < ln(2)/2: 1 + expm1(|x|)^2 / (2 exp(|x|))
        let t = crate::math::expm1(ax);
        let w = 1.0 + t;
        if ix < 0x3c80_0000 {
            return w; // cosh(tiny) = 1
        }
        return 1.0 + (t * t) / (w + w);
    }
    if ix < 0x4036_0000 {
        // |x| < 22
        let t = crate::math::exp(ax);
        return 0.5 * t + 0.5 / t;
    }
    if ix < 0x4086_2e42 {
        return 0.5 * crate::math::exp(ax);
    }
    if ix < 0x4086_33ce || (ix == 0x4086_33ce && lx <= 0x8fb9_f87d) {
        let w = crate::math::exp(0.5 * ax);
        let t = 0.5 * w;
        return t * w;
    }
    let huge = core::hint::black_box(1.0e300);
    huge * huge // overflow
}

#[inline]
pub fn tanh(x: f64) -> f64 {
    let (jx, _) = hi_lo(x);
    let ix = jx & 0x7fff_ffff;
    if ix >= 0x7ff0_0000 {
        // tanh(±inf) = ±1; NaN propagates.
        return if jx >= 0 {
            1.0 / x + 1.0
        } else {
            1.0 / x - 1.0
        };
    }
    let z = if ix < 0x4036_0000 {
        // |x| < 22
        if ix < 0x3c80_0000 {
            return x * (1.0 + x); // |x| < 2^-55
        }
        if ix >= 0x3ff0_0000 {
            let t = crate::math::expm1(2.0 * x.abs());
            1.0 - 2.0 / (t + 2.0)
        } else {
            let t = crate::math::expm1(-2.0 * x.abs());
            -t / (t + 2.0)
        }
    } else {
        1.0 - core::hint::black_box(1.0e-300) // ±1 with FE_INEXACT
    };
    if jx >= 0 { z } else { -z }
}

#[inline]
pub fn asinh(x: f64) -> f64 {
    // CORE-MATH's correctly rounded asinh, which glibc 2.43 ships: bit-identical
    // to glibc. fdlibm's libm::asinh differed on 6.6% of inputs (bd-otip6a).
    crate::math::coremath::asinh(x)
}

#[inline]
pub fn acosh(x: f64) -> f64 {
    // CORE-MATH's correctly rounded acosh, which glibc 2.43 ships: bit-identical
    // to glibc. fdlibm's libm::acosh differed on 6.4% of inputs (bd-otip6a).
    crate::math::coremath::acosh(x)
}

#[inline]
pub fn atanh(x: f64) -> f64 {
    // CORE-MATH's correctly rounded atanh, which glibc 2.43 ships: bit-identical
    // to glibc. The log1p(2|x|/(1-|x|))/2 shortcut differed on 21.6% of inputs
    // (bd-otip6a).
    crate::math::coremath::atanh(x)
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

    /// 4-ULP comparison against the host glibc (`f64::cosh` lowers to glibc).
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
    fn cosh_fast_path_within_4_ulps() {
        // Sweep densely across the fast-exp window [-5,5] and beyond, plus the
        // overflow edge. `f64::cosh` is the host glibc oracle.
        let mut worst = 0u64;
        let mut x = -30.0_f64;
        while x <= 30.0 {
            let got = cosh(x);
            let want = x.cosh();
            let u = if got == want {
                0
            } else {
                (got.to_bits() as i64 - want.to_bits() as i64).unsigned_abs()
            };
            worst = worst.max(u);
            assert!(
                within_ulps(got, want, 4),
                "cosh({x}) = {got:?} vs glibc {want:?} ({u} ULP)"
            );
            x += 0.0001;
        }
        // Special points: 0 exact, overflow -> inf, even symmetry.
        assert_eq!(cosh(0.0), 1.0);
        assert_eq!(cosh(800.0), f64::INFINITY);
        assert_eq!(cosh(-800.0), f64::INFINITY);
        assert!(within_ulps(cosh(710.4), 710.4_f64.cosh(), 4));
        println!("cosh worst ULP = {worst}");
    }

    #[test]
    fn acosh_large_asymptotic_within_4_ulps() {
        let mut worst = 0u64;
        let mut worst_x = 0.0_f64;
        for i in 0..=262_144 {
            let x = 16.0 + (10_000_000.0 - 16.0) * (i as f64) / 262_144.0;
            let got = acosh(x);
            let want = x.acosh();
            let u = if got == want {
                0
            } else {
                (got.to_bits() as i64 - want.to_bits() as i64).unsigned_abs()
            };
            if u > worst {
                worst = u;
                worst_x = x;
            }
            assert!(
                within_ulps(got, want, 4),
                "acosh({x}) = {got:?} vs glibc {want:?} ({u} ULP)"
            );
        }
        assert_eq!(acosh(f64::INFINITY), f64::INFINITY);
        println!("acosh large asymptotic worst ULP = {worst} at {worst_x}");
    }

    #[test]
    fn asinh_large_asymptotic_within_4_ulps() {
        let mut worst = 0u64;
        let mut worst_x = 0.0_f64;
        for i in 0..=262_144 {
            let ax = 16.0 + (10_000_000.0 - 16.0) * (i as f64) / 262_144.0;
            for x in [ax, -ax] {
                let got = asinh(x);
                let want = x.asinh();
                let u = if got == want {
                    0
                } else {
                    (got.to_bits() as i64 - want.to_bits() as i64).unsigned_abs()
                };
                if u > worst {
                    worst = u;
                    worst_x = x;
                }
                assert!(
                    within_ulps(got, want, 4),
                    "asinh({x}) = {got:?} vs glibc {want:?} ({u} ULP)"
                );
            }
        }
        assert_eq!(asinh(f64::INFINITY), f64::INFINITY);
        assert_eq!(asinh(f64::NEG_INFINITY), f64::NEG_INFINITY);
        println!("asinh large asymptotic worst ULP = {worst} at {worst_x}");
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

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_math_edge.c

    #[test]
    fn glibc_sin_cos_at_zero() {
        assert_eq!(sin(0.0), 0.0);
        assert_eq!(cos(0.0), 1.0);
        assert_eq!(tan(0.0), 0.0);
    }

    #[test]
    fn glibc_sin_at_pi_half() {
        // sin(pi/2) = 1.0
        assert!((sin(PI / 2.0) - 1.0).abs() < 1e-12);
    }

    #[test]
    fn glibc_cos_at_pi() {
        // cos(pi) = -1.0
        assert!((cos(PI) - (-1.0)).abs() < 1e-12);
    }

    #[test]
    fn glibc_asin_domain_error_outside_range() {
        // asin(2.0) is NaN (domain error)
        assert!(asin(2.0).is_nan());
        assert!(asin(-2.0).is_nan());
    }

    #[test]
    fn glibc_asin_acos_at_boundaries() {
        // asin(0) = 0, asin(1) = pi/2
        assert!((asin(0.0) - 0.0).abs() < 1e-12);
        assert!((asin(1.0) - PI / 2.0).abs() < 1e-12);
        // acos(1) = 0
        assert!((acos(1.0) - 0.0).abs() < 1e-12);
    }

    #[test]
    fn glibc_atan_at_one() {
        // atan(1) = pi/4
        assert!((atan(1.0) - PI / 4.0).abs() < 1e-12);
    }

    #[test]
    fn glibc_atan2_quadrant_aware() {
        // atan2(1, 1) = pi/4
        assert!((atan2(1.0, 1.0) - PI / 4.0).abs() < 1e-12);
        // atan2(0, 0) = 0 in glibc
        assert_eq!(atan2(0.0, 0.0), 0.0);
    }
}
