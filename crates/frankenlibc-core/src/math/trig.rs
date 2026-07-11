//! Trigonometric functions.

// Fast extended-range argument reduction for sin/cos/tan.
//
// `libm`'s reduction is fast for |x| < 2^20·π/2 (≈1.6e6), but above that it
// falls to a slow Payne-Hanek path — measured ~7-10x slower than glibc, which
// stays flat (~10 ns) across all ranges. For the common "large but not
// astronomical" range we reduce with an FMA-based 3-part π/2 Cody-Waite (no
// Payne-Hanek table) and evaluate the already-fast small-arg `libm` kernel on
// the reduced value. |x| above the 3-part range (≈1e15, where the quotient `n`
// no longer leaves enough of the 159-bit π/2 split) stays on `libm` so the rare
// astronomical case keeps its full accuracy.

const TWO_OVER_PI: f64 = f64::from_bits(0x3fe45f306dc9c883); // 2/π
const PIO2H: f64 = f64::from_bits(0x3ff921fb54442d18); // π/2, high 53 bits
const PIO2M: f64 = f64::from_bits(0x3c91a62633145c07); // π/2 − PIO2H
const PIO2L: f64 = f64::from_bits(0xb91f1976b7ed8fbc); // π/2 − PIO2H − PIO2M
/// Below this, `libm`'s own reduction is already fast — leave it alone.
const TRIG_FAST_HI: f64 = 1.647e6;
/// Above this, the 3-part split runs out of precision — defer to `libm`.
const TRIG_RED_MAX: f64 = 1.0e15;

/// Reduce `x` to `(n mod 4, r)` with `r ∈ ~[-π/4, π/4]` and `x = n·π/2 + r`,
/// using three FMA steps against a 159-bit split of π/2. Valid for the
/// `[TRIG_FAST_HI, TRIG_RED_MAX]` magnitude band (caller-guarded).
#[inline]
fn reduce_pio2_fma(x: f64) -> (i64, f64) {
    let kd = (x * TWO_OVER_PI).round_ties_even();
    let mut r = kd.mul_add(-PIO2H, x);
    r = kd.mul_add(-PIO2M, r);
    r = kd.mul_add(-PIO2L, r);
    (kd as i64, r)
}

#[inline]
pub fn sin(x: f64) -> f64 {
    let ax = x.abs();
    // Route the reduce-needing band `[π/4, TRIG_RED_MAX]` through the fast FMA Cody-Waite
    // reduction instead of `libm::sin`'s slower internal `rem_pio2` — same mechanism as the
    // landed f64 `tan` lever (glibc 2.42 sped up its dbl-64 trig, exposing libm's medium-range
    // reduction). `|x| < π/4` needs no reduction (stays on libm); the reduction is ≤2 ULP and
    // only more accurate for smaller `x`, within the ≤4-ULP trig contract.
    if ax < core::f64::consts::FRAC_PI_4 || !(ax <= TRIG_RED_MAX) {
        return libm::sin(x);
    }
    let (n, r) = reduce_pio2_fma(x);
    match n & 3 {
        0 => libm::sin(r),
        1 => libm::cos(r),
        2 => -libm::sin(r),
        _ => -libm::cos(r),
    }
}

#[inline]
pub fn cos(x: f64) -> f64 {
    let ax = x.abs();
    // See `sin`: route `[π/4, TRIG_RED_MAX]` through the fast FMA reduction (same mechanism as
    // the landed `tan` lever); `|x| < π/4` stays on libm. ≤2 ULP, within the ≤4-ULP contract.
    if ax < core::f64::consts::FRAC_PI_4 || !(ax <= TRIG_RED_MAX) {
        return libm::cos(x);
    }
    let (n, r) = reduce_pio2_fma(x);
    match n & 3 {
        0 => libm::cos(r),
        1 => -libm::sin(r),
        2 => -libm::cos(r),
        _ => libm::sin(r),
    }
}

/// Fused sin+cos over the fast FMA-reduction band `[TRIG_FAST_HI, TRIG_RED_MAX]`.
/// Returns `Some((sin(x), cos(x)))` computed from a SINGLE `reduce_pio2_fma`
/// instead of `libm::sincos`'s slower Payne–Hanek `rem_pio2`. The result is
/// BIT-IDENTICAL to `(self::sin(x), self::cos(x))` (same reduction, same quadrant
/// map, same `libm::sin/cos` on the reduced arg), so it inherits their already-green
/// ≤1–2 ULP-vs-glibc conformance; outside the band the caller falls back to
/// `libm::sincos` (unchanged behavior).
///
/// NOTE (rejected 2026-07-11, cc-sincos-band): lowering this threshold to `π/4` (mirroring
/// the sin/cos/tan levers) is a MEASURED no-op — `libm::sincos` already shares ONE reduction
/// for both outputs and already BEATS glibc's `sincos` on the common band (fl_cand/libm_orig
/// = 1.001, both 0.74x glibc). The FMA path adds a double reduction (`reduce_pio2_fma` +
/// `libm::sin(r)`/`libm::cos(r)`'s own `rem_pio2` fast-exits) that washes the savings. Do not
/// retry without transcribing the sin/cos KERNELS to avoid the double reduction.
#[inline]
pub(crate) fn sincos_band(x: f64) -> Option<(f64, f64)> {
    let ax = x.abs();
    if ax < TRIG_FAST_HI || !(ax <= TRIG_RED_MAX) {
        return None;
    }
    let (n, r) = reduce_pio2_fma(x);
    let s = libm::sin(r);
    let c = libm::cos(r);
    Some(match n & 3 {
        0 => (s, c),
        1 => (c, -s),
        2 => (-s, -c),
        _ => (-c, s),
    })
}

/// Below π/4 no reduction is needed (`libm::tan` is a direct small-arg kernel eval), so
/// leave it on libm. From π/4 up to `TRIG_RED_MAX` we route through the fast FMA
/// Cody-Waite reduction (`reduce_pio2_fma`, 3 FMAs) + the already-fast small-arg kernel,
/// instead of `libm::tan`'s slower internal `rem_pio2`. glibc 2.42 sped up its dbl-64
/// `tan`, exposing libm's medium-range reduction as the gap (f64 `tan` measured 1.68x
/// slower than glibc 2.42). The reduction is proven ≤2 ULP on the large-arg band and is
/// only MORE accurate for smaller `x` (smaller quotient), so it stays within the ≤4-ULP
/// trig contract (`conformance_diff_trig_special`). Odd by construction: `reduce_pio2_fma`
/// is odd (round-ties-even is odd), so `tan(-x) == -tan(x)` exactly. Above `TRIG_RED_MAX`
/// the 3-part split runs out of precision — defer to libm for the rare astronomical case.
#[inline]
pub fn tan(x: f64) -> f64 {
    let ax = x.abs();
    if ax < core::f64::consts::FRAC_PI_4 || !(ax <= TRIG_RED_MAX) {
        return libm::tan(x);
    }
    let (n, r) = reduce_pio2_fma(x);
    if n & 1 == 0 {
        libm::tan(r)
    } else {
        -1.0 / libm::tan(r)
    }
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
    // |x| <= 3: odd Taylor polynomial (no exp — cheaper than the (t-1/t)/2 reroute on
    //   the hot band, mirrors the `cosh` polynomial). |x| in (3, 700): the two
    //   exponentials are well separated (t >> 1/t), so sign(x)·(t-1/t)/2 with t=exp(|x|)
    //   rides the fast f64 `exp` with no cancellation. |x| >= 700 (overflow) -> libm.
    let ax = x.abs();
    if ax <= 3.0 {
        return sinh_poly_le_3(x);
    }
    if ax < 700.0 {
        let t = crate::math::exp(ax);
        let r = (t - 1.0 / t) * 0.5;
        return if x.is_sign_negative() { -r } else { r };
    }
    libm::sinh(x)
}

#[inline]
fn sinh_poly_le_3(x: f64) -> f64 {
    // Odd Taylor/Horner polynomial through x^27: sinh(x) = x·Σ (x²)^k/(2k+1)!. On
    // |x| <= 3 the first omitted term x^29/29! < 8e-18 is well under the 4-ULP math
    // contract for sinh (sinh(3)=10.02, 4 ULP ~ 9e-15). x carries the sign (odd), so ±0
    // -> ±0 falls out. Mirrors the peer's `cosh_poly_le_3`.
    let z = x * x;
    let mut p: f64 = 9.183_689_863_795_546e-29;
    p = p.mul_add(z, 6.446_950_284_384_474e-26);
    p = p.mul_add(z, 3.868_170_170_630_683_5e-23);
    p = p.mul_add(z, 1.957_294_106_339_126_3e-20);
    p = p.mul_add(z, 8.220_635_246_624_33e-18);
    p = p.mul_add(z, 2.811_457_254_345_520_6e-15);
    p = p.mul_add(z, 7.647_163_731_819_816e-13);
    p = p.mul_add(z, 1.605_904_383_682_161_3e-10);
    p = p.mul_add(z, 2.505_210_838_544_172e-8);
    p = p.mul_add(z, 2.755_731_922_398_589_3e-6);
    p = p.mul_add(z, 1.984_126_984_126_984e-4);
    p = p.mul_add(z, 8.333_333_333_333_333e-3);
    p = p.mul_add(z, 0.166_666_666_666_666_66);
    p = p.mul_add(z, 1.0);
    x * p
}

/// `cosh(x) = (eˣ + e⁻ˣ)/2`, using a small/medium even polynomial before the
/// large-input one-`exp` form.
///
/// Profiling (`glibc_baseline_math/cosh`) showed `libm::cosh` (~13.5 ns) is
/// ~1.4x slower than glibc's `cosh` (~9.6 ns), while our `exp` (exp2-based
/// fast path) is ~0.66x glibc's — so one `exp` + reciprocal reaches parity.
/// A degree-26 even Taylor/Horner polynomial is faster still on the survey's
/// hot `[0.1, 3.0]` band; the first omitted term at `|x| = 3` is below 8e-17.
/// Unlike `sinh`, `cosh` has no catastrophic cancellation: both the polynomial
/// and the one-`exp` form sum positive terms, and the result stays within the
/// 4-ULP-vs-glibc math contract (verified by `cosh_fast_path_within_4_ulps`).
///
/// `|x| >= 700` defers to `libm::cosh`: there `exp(x)` would overflow to `inf`
/// while `cosh(x)` is still finite in the band `(709.78, 710.47]` (cosh
/// overflows later than exp), so the naive form would wrongly return `inf`.
/// 700 sits safely below the `exp` overflow threshold (`exp(700) ≈ 1e304`).
#[inline]
pub fn cosh(x: f64) -> f64 {
    let ax = x.abs();
    if ax <= 3.0 {
        return cosh_poly_le_3(ax);
    }
    if ax < 700.0 {
        let t = crate::math::exp(ax);
        return (t + 1.0 / t) * 0.5;
    }
    libm::cosh(x)
}

#[inline]
fn cosh_poly_le_3(x: f64) -> f64 {
    // Even Taylor/Horner polynomial through x^26. On |x| <= 3 the first omitted
    // term is x^28/28! < 8e-17, well under the 4-ULP math contract for cosh.
    let z = x * x;
    let mut p: f64 = 2.479_596_263_224_797_2e-27;
    p = p.mul_add(z, 1.611_737_571_096_118_4e-24);
    p = p.mul_add(z, 8.896_791_392_450_574e-22);
    p = p.mul_add(z, 4.110_317_623_312_165e-19);
    p = p.mul_add(z, 1.561_920_696_858_622_5e-16);
    p = p.mul_add(z, 4.779_477_332_387_385e-14);
    p = p.mul_add(z, 1.147_074_559_772_972_5e-11);
    p = p.mul_add(z, 2.087_675_698_786_81e-9);
    p = p.mul_add(z, 2.755_731_922_398_589e-7);
    p = p.mul_add(z, 2.480_158_730_158_73e-5);
    p = p.mul_add(z, 1.388_888_888_888_889e-3);
    p = p.mul_add(z, 4.166_666_666_666_666_4e-2);
    p = p.mul_add(z, 0.5);
    p.mul_add(z, 1.0)
}

#[inline]
pub fn tanh(x: f64) -> f64 {
    // For |x| in [0.5, 20): tanh(x) = sign(x)·(u-1)/(u+1) with u = exp(2|x|). Since
    // u >= e (no cancellation in u-1) it rides the now-fast f64 `exp` kernel. |x| >= 20
    // saturates to ±1 in f64 (1 - tanh < half-ULP), which also avoids exp(2x) overflow.
    // Small |x| (< 0.5, where u ~ 1 and u-1 cancels) keeps libm::tanh's exact handling.
    let ax = x.abs();
    if ax >= 0.5 {
        let r = if ax >= 20.0 {
            1.0
        } else {
            let u = crate::math::exp(2.0 * ax);
            (u - 1.0) / (u + 1.0)
        };
        return if x.is_sign_negative() { -r } else { r };
    }
    libm::tanh(x)
}

#[inline]
pub fn asinh(x: f64) -> f64 {
    // Large-|x| asinh is dominated by sign(x)*log(2|x|). The previously rejected
    // rewrite was sqrt-bound; this asymptotic path removes the sqrt on the hot
    // large-input band and corrects log(2|x|) by the exact series in z=1/x^2:
    // asinh(x)-log(2x) = z/4 - 3z^2/32 + 5z^3/96 - 35z^4/1024 + 63z^5/2560 + O(z^6).
    let ax = x.abs();
    if ax >= 16.0 {
        let z = 1.0 / (ax * ax);
        let mut p: f64 = 63.0 / 2560.0;
        p = p.mul_add(z, -35.0 / 1024.0);
        p = p.mul_add(z, 5.0 / 96.0);
        p = p.mul_add(z, -3.0 / 32.0);
        p = p.mul_add(z, 0.25);
        let r = crate::math::log(ax) + core::f64::consts::LN_2 + z * p;
        return if x.is_sign_negative() { -r } else { r };
    }
    if ax >= 1.0 {
        // Midrange [1,16): x+√(x²+1) ≥ 1+√2 — NO cancellation — so the PLAIN log form
        // (one sqrt + fl's fused f64 `log`) is accurate to ≤2 ULP (asinh is gated ≤2 ULP)
        // and beats libm::asinh's heavier internal log+branch path. This is NOT the
        // rejected log1p form (asinh = log1p(|x| + x²/(√(x²+1)+1)), 1.80x — extra divide +
        // non-inlined log1p); the bare log avoids both.
        let r = crate::math::log(ax + (ax * ax + 1.0).sqrt());
        return if x.is_sign_negative() { -r } else { r };
    }
    // |x| < 1: x+√(x²+1) → 1 cancellation needs extra precision — libm::asinh is tighter.
    libm::asinh(x)
}

#[inline]
pub fn acosh(x: f64) -> f64 {
    // Large-x acosh is dominated by log(2x). The previously rejected rewrite was
    // sqrt-bound; this asymptotic path removes the sqrt on the hot large-input band and
    // corrects log(2x) by the exact series in z=1/x^2:
    // acosh(x)-log(2x) = -z/4 - 3z^2/32 - 5z^3/96 - 35z^4/1024 - 63z^5/2560 + O(z^6).
    if x >= 16.0 {
        let z = 1.0 / (x * x);
        let mut p: f64 = -63.0 / 2560.0;
        p = p.mul_add(z, -35.0 / 1024.0);
        p = p.mul_add(z, -5.0 / 96.0);
        p = p.mul_add(z, -3.0 / 32.0);
        p = p.mul_add(z, -0.25);
        return crate::math::log(x) + core::f64::consts::LN_2 + z * p;
    }
    // The near-1/midrange log1p form measured 1.43x (sqrt-bound); libm::acosh is tighter.
    libm::acosh(x)
}

#[inline]
pub fn atanh(x: f64) -> f64 {
    // atanh(x) = sign(x)·0.5·log1p(2|x|/(1-|x|)), rides the fast `log1p`. |x| >= 1
    // (poles ±1 -> ±inf, |x| > 1 domain -> NaN, NaN) defers to libm::atanh for exact
    // FE flags. Small |x| stays accurate (log1p(2x) ~ 2x).
    let ax = x.abs();
    if !(ax < 1.0) {
        return libm::atanh(x);
    }
    let r = 0.5 * crate::math::log1p(2.0 * ax / (1.0 - ax));
    if x.is_sign_negative() { -r } else { r }
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
