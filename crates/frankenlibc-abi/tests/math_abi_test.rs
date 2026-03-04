#![cfg(target_os = "linux")]

//! Integration tests for `<math.h>` ABI entrypoints.
//!
//! Covers: basic trig, inverse trig, hyperbolic, exp/log, power/root,
//! rounding, classification, fmin/fmax, fma, Bessel, gamma/erf,
//! sincos, modf, frexp/ldexp, remquo, nextafter, copysign, fdim,
//! nan, scalbn/scalbln, ilogb/logb, float (f32) variants,
//! C23 fmaximum/fminimum, and type-generic width aliases.

use std::ffi::c_int;

// ---------------------------------------------------------------------------
// Helper: approximate equality for floating-point
// ---------------------------------------------------------------------------

fn approx_eq_f64(a: f64, b: f64, tol: f64) -> bool {
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a.is_infinite() && b.is_infinite() {
        return a.is_sign_positive() == b.is_sign_positive();
    }
    (a - b).abs() <= tol
}

fn approx_eq_f32(a: f32, b: f32, tol: f32) -> bool {
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a.is_infinite() && b.is_infinite() {
        return a.is_sign_positive() == b.is_sign_positive();
    }
    (a - b).abs() <= tol
}

// ---------------------------------------------------------------------------
// Basic trig (f64)
// ---------------------------------------------------------------------------

#[test]
fn sin_known_values() {
    use frankenlibc_abi::math_abi::sin;
    let cases: &[(f64, f64)] = &[
        (0.0, 0.0),
        (std::f64::consts::FRAC_PI_2, 1.0),
        (std::f64::consts::PI, 0.0),
        (-std::f64::consts::FRAC_PI_2, -1.0),
    ];
    for &(input, expected) in cases {
        let got = unsafe { sin(input) };
        assert!(
            approx_eq_f64(got, expected, 1e-12),
            "sin({input}) = {got}, expected {expected}"
        );
    }
}

#[test]
fn sin_special_values() {
    use frankenlibc_abi::math_abi::sin;
    let nan_result = unsafe { sin(f64::NAN) };
    assert!(nan_result.is_nan(), "sin(NaN) should be NaN");

    let inf_result = unsafe { sin(f64::INFINITY) };
    assert!(inf_result.is_nan(), "sin(Inf) should be NaN");
}

#[test]
fn cos_known_values() {
    use frankenlibc_abi::math_abi::cos;
    let cases: &[(f64, f64)] = &[
        (0.0, 1.0),
        (std::f64::consts::FRAC_PI_2, 0.0),
        (std::f64::consts::PI, -1.0),
    ];
    for &(input, expected) in cases {
        let got = unsafe { cos(input) };
        assert!(
            approx_eq_f64(got, expected, 1e-12),
            "cos({input}) = {got}, expected {expected}"
        );
    }
}

#[test]
fn tan_known_values() {
    use frankenlibc_abi::math_abi::tan;
    let got = unsafe { tan(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15), "tan(0) = {got}");

    let got = unsafe { tan(std::f64::consts::FRAC_PI_4) };
    assert!(approx_eq_f64(got, 1.0, 1e-12), "tan(pi/4) = {got}");
}

// ---------------------------------------------------------------------------
// Inverse trig (f64)
// ---------------------------------------------------------------------------

#[test]
fn asin_known_values() {
    use frankenlibc_abi::math_abi::asin;
    let got = unsafe { asin(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { asin(1.0) };
    assert!(approx_eq_f64(got, std::f64::consts::FRAC_PI_2, 1e-12));
}

#[test]
fn asin_domain_error() {
    use frankenlibc_abi::math_abi::asin;
    let got = unsafe { asin(2.0) };
    assert!(got.is_nan(), "asin(2.0) should be NaN (domain error)");
}

#[test]
fn acos_known_values() {
    use frankenlibc_abi::math_abi::acos;
    let got = unsafe { acos(1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { acos(0.0) };
    assert!(approx_eq_f64(got, std::f64::consts::FRAC_PI_2, 1e-12));
}

#[test]
fn atan_known_values() {
    use frankenlibc_abi::math_abi::atan;
    let got = unsafe { atan(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { atan(1.0) };
    assert!(approx_eq_f64(got, std::f64::consts::FRAC_PI_4, 1e-12));
}

#[test]
fn atan2_known_values() {
    use frankenlibc_abi::math_abi::atan2;
    let got = unsafe { atan2(0.0, 1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { atan2(1.0, 1.0) };
    assert!(approx_eq_f64(got, std::f64::consts::FRAC_PI_4, 1e-12));
    let got = unsafe { atan2(1.0, 0.0) };
    assert!(approx_eq_f64(got, std::f64::consts::FRAC_PI_2, 1e-12));
}

// ---------------------------------------------------------------------------
// Hyperbolic (f64)
// ---------------------------------------------------------------------------

#[test]
fn sinh_cosh_tanh_basic() {
    use frankenlibc_abi::math_abi::{cosh, sinh, tanh};
    let s = unsafe { sinh(0.0) };
    assert!(approx_eq_f64(s, 0.0, 1e-15));
    let c = unsafe { cosh(0.0) };
    assert!(approx_eq_f64(c, 1.0, 1e-15));
    let t = unsafe { tanh(0.0) };
    assert!(approx_eq_f64(t, 0.0, 1e-15));

    // tanh approaches +/-1 at large values
    let t_large = unsafe { tanh(20.0) };
    assert!(approx_eq_f64(t_large, 1.0, 1e-9));
}

#[test]
fn asinh_acosh_atanh_basic() {
    use frankenlibc_abi::math_abi::{acosh, asinh, atanh};
    let a = unsafe { asinh(0.0) };
    assert!(approx_eq_f64(a, 0.0, 1e-15));

    let a = unsafe { acosh(1.0) };
    assert!(approx_eq_f64(a, 0.0, 1e-15));

    let a = unsafe { atanh(0.0) };
    assert!(approx_eq_f64(a, 0.0, 1e-15));
}

#[test]
fn acosh_domain_error() {
    use frankenlibc_abi::math_abi::acosh;
    let got = unsafe { acosh(0.5) };
    assert!(got.is_nan(), "acosh(0.5) should be NaN");
}

#[test]
fn atanh_pole_and_domain() {
    use frankenlibc_abi::math_abi::atanh;
    let pole = unsafe { atanh(1.0) };
    assert!(pole.is_infinite(), "atanh(1) should be +Inf");

    let dom = unsafe { atanh(2.0) };
    assert!(dom.is_nan(), "atanh(2) should be NaN");
}

// ---------------------------------------------------------------------------
// Exponential / logarithmic (f64)
// ---------------------------------------------------------------------------

#[test]
fn exp_known_values() {
    use frankenlibc_abi::math_abi::exp;
    let got = unsafe { exp(0.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
    let got = unsafe { exp(1.0) };
    assert!(approx_eq_f64(got, std::f64::consts::E, 1e-12));
}

#[test]
fn exp2_known_values() {
    use frankenlibc_abi::math_abi::exp2;
    let got = unsafe { exp2(0.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
    let got = unsafe { exp2(10.0) };
    assert!(approx_eq_f64(got, 1024.0, 1e-10));
}

#[test]
fn expm1_small_values() {
    use frankenlibc_abi::math_abi::expm1;
    let got = unsafe { expm1(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    // For small x, expm1(x) ~ x
    let got = unsafe { expm1(1e-15) };
    assert!(approx_eq_f64(got, 1e-15, 1e-25));
}

#[test]
fn log_known_values() {
    use frankenlibc_abi::math_abi::log;
    let got = unsafe { log(1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { log(std::f64::consts::E) };
    assert!(approx_eq_f64(got, 1.0, 1e-12));
}

#[test]
fn log_domain_and_pole() {
    use frankenlibc_abi::math_abi::log;
    let neg = unsafe { log(-1.0) };
    assert!(neg.is_nan(), "log(-1) should be NaN");
    let zero = unsafe { log(0.0) };
    assert!(zero.is_infinite() && zero.is_sign_negative(), "log(0) should be -Inf");
}

#[test]
fn log2_known_values() {
    use frankenlibc_abi::math_abi::log2;
    let got = unsafe { log2(1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { log2(1024.0) };
    assert!(approx_eq_f64(got, 10.0, 1e-10));
}

#[test]
fn log10_known_values() {
    use frankenlibc_abi::math_abi::log10;
    let got = unsafe { log10(1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    let got = unsafe { log10(1000.0) };
    assert!(approx_eq_f64(got, 3.0, 1e-12));
}

#[test]
fn log1p_known_values() {
    use frankenlibc_abi::math_abi::log1p;
    let got = unsafe { log1p(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    // log1p(-1) = log(0) = -Inf
    let got = unsafe { log1p(-1.0) };
    assert!(got.is_infinite() && got.is_sign_negative());
}

// ---------------------------------------------------------------------------
// Power / root (f64)
// ---------------------------------------------------------------------------

#[test]
fn pow_known_values() {
    use frankenlibc_abi::math_abi::pow;
    let got = unsafe { pow(2.0, 10.0) };
    assert!(approx_eq_f64(got, 1024.0, 1e-10));
    let got = unsafe { pow(9.0, 0.5) };
    assert!(approx_eq_f64(got, 3.0, 1e-12));
    let got = unsafe { pow(5.0, 0.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
}

#[test]
fn pow_domain_error() {
    use frankenlibc_abi::math_abi::pow;
    let got = unsafe { pow(-2.0, 0.5) };
    assert!(got.is_nan(), "pow(-2, 0.5) should be NaN");
}

#[test]
fn sqrt_known_values() {
    use frankenlibc_abi::math_abi::sqrt;
    let got = unsafe { sqrt(4.0) };
    assert!(approx_eq_f64(got, 2.0, 1e-15));
    let got = unsafe { sqrt(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
}

#[test]
fn sqrt_domain_error() {
    use frankenlibc_abi::math_abi::sqrt;
    let got = unsafe { sqrt(-1.0) };
    assert!(got.is_nan(), "sqrt(-1) should be NaN");
}

#[test]
fn cbrt_known_values() {
    use frankenlibc_abi::math_abi::cbrt;
    let got = unsafe { cbrt(27.0) };
    assert!(approx_eq_f64(got, 3.0, 1e-12));
    let got = unsafe { cbrt(-8.0) };
    assert!(approx_eq_f64(got, -2.0, 1e-12));
}

#[test]
fn hypot_known_values() {
    use frankenlibc_abi::math_abi::hypot;
    let got = unsafe { hypot(3.0, 4.0) };
    assert!(approx_eq_f64(got, 5.0, 1e-12));
    let got = unsafe { hypot(0.0, 0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
}

// ---------------------------------------------------------------------------
// Rounding (f64)
// ---------------------------------------------------------------------------

#[test]
fn ceil_known_values() {
    use frankenlibc_abi::math_abi::ceil;
    assert_eq!(unsafe { ceil(2.3) }, 3.0);
    assert_eq!(unsafe { ceil(-2.3) }, -2.0);
    assert_eq!(unsafe { ceil(0.0) }, 0.0);
    assert_eq!(unsafe { ceil(5.0) }, 5.0);
}

#[test]
fn floor_known_values() {
    use frankenlibc_abi::math_abi::floor;
    assert_eq!(unsafe { floor(2.7) }, 2.0);
    assert_eq!(unsafe { floor(-2.3) }, -3.0);
    assert_eq!(unsafe { floor(0.0) }, 0.0);
}

#[test]
fn round_known_values() {
    use frankenlibc_abi::math_abi::round;
    assert_eq!(unsafe { round(2.5) }, 3.0);
    assert_eq!(unsafe { round(-2.5) }, -3.0);
    assert_eq!(unsafe { round(2.3) }, 2.0);
}

#[test]
fn trunc_known_values() {
    use frankenlibc_abi::math_abi::trunc;
    assert_eq!(unsafe { trunc(2.9) }, 2.0);
    assert_eq!(unsafe { trunc(-2.9) }, -2.0);
    assert_eq!(unsafe { trunc(0.0) }, 0.0);
}

#[test]
fn rint_known_values() {
    use frankenlibc_abi::math_abi::rint;
    // Default rounding is to nearest, ties to even
    let got = unsafe { rint(2.5) };
    assert_eq!(got, 2.0, "rint(2.5) should round to 2 (ties to even)");
    let got = unsafe { rint(3.5) };
    assert_eq!(got, 4.0, "rint(3.5) should round to 4 (ties to even)");
}

#[test]
fn nearbyint_known_values() {
    use frankenlibc_abi::math_abi::nearbyint;
    let got = unsafe { nearbyint(2.5) };
    assert_eq!(got, 2.0);
    let got = unsafe { nearbyint(3.5) };
    assert_eq!(got, 4.0);
}

#[test]
fn lrint_llrint_known() {
    use frankenlibc_abi::math_abi::{llrint, lrint};
    let l = unsafe { lrint(2.7) };
    assert_eq!(l, 3);
    let ll = unsafe { llrint(-2.7) };
    assert_eq!(ll, -3);
}

#[test]
fn lround_llround_known() {
    use frankenlibc_abi::math_abi::{llround, lround};
    let l = unsafe { lround(2.5) };
    assert_eq!(l, 3);
    let ll = unsafe { llround(-2.5) };
    assert_eq!(ll, -3);
}

// ---------------------------------------------------------------------------
// Classification / manipulation (f64)
// ---------------------------------------------------------------------------

#[test]
fn fabs_known_values() {
    use frankenlibc_abi::math_abi::fabs;
    assert_eq!(unsafe { fabs(-5.0) }, 5.0);
    assert_eq!(unsafe { fabs(5.0) }, 5.0);
    assert_eq!(unsafe { fabs(0.0) }, 0.0);
}

#[test]
fn copysign_known_values() {
    use frankenlibc_abi::math_abi::copysign;
    assert_eq!(unsafe { copysign(5.0, -1.0) }, -5.0);
    assert_eq!(unsafe { copysign(-5.0, 1.0) }, 5.0);
}

#[test]
fn fmod_known_values() {
    use frankenlibc_abi::math_abi::fmod;
    let got = unsafe { fmod(7.0, 3.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
    let got = unsafe { fmod(-7.0, 3.0) };
    assert!(approx_eq_f64(got, -1.0, 1e-15));
}

#[test]
fn remainder_known_values() {
    use frankenlibc_abi::math_abi::remainder;
    let got = unsafe { remainder(7.0, 3.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
    let got = unsafe { remainder(8.0, 3.0) };
    assert!(approx_eq_f64(got, -1.0, 1e-15));
}

#[test]
fn fmin_fmax_known_values() {
    use frankenlibc_abi::math_abi::{fmax, fmin};
    assert_eq!(unsafe { fmin(2.0, 3.0) }, 2.0);
    assert_eq!(unsafe { fmax(2.0, 3.0) }, 3.0);

    // NaN handling: fmin/fmax should return the non-NaN argument
    let got = unsafe { fmin(f64::NAN, 5.0) };
    assert_eq!(got, 5.0, "fmin(NaN, 5) should be 5");
    let got = unsafe { fmax(f64::NAN, 5.0) };
    assert_eq!(got, 5.0, "fmax(NaN, 5) should be 5");
}

#[test]
fn fdim_known_values() {
    use frankenlibc_abi::math_abi::fdim;
    assert_eq!(unsafe { fdim(5.0, 3.0) }, 2.0);
    assert_eq!(unsafe { fdim(3.0, 5.0) }, 0.0);
}

#[test]
fn fma_known_values() {
    use frankenlibc_abi::math_abi::fma;
    // fma(x, y, z) = x*y + z
    let got = unsafe { fma(2.0, 3.0, 4.0) };
    assert!(approx_eq_f64(got, 10.0, 1e-15));
}

// ---------------------------------------------------------------------------
// modf, frexp, ldexp, scalbn, scalbln, ilogb, logb
// ---------------------------------------------------------------------------

#[test]
fn modf_splits_correctly() {
    use frankenlibc_abi::math_abi::modf;
    let mut ipart: f64 = 0.0;
    let fpart = unsafe { modf(3.75, &mut ipart) };
    assert!(approx_eq_f64(ipart, 3.0, 1e-15));
    assert!(approx_eq_f64(fpart, 0.75, 1e-15));

    let fpart = unsafe { modf(-3.75, &mut ipart) };
    assert!(approx_eq_f64(ipart, -3.0, 1e-15));
    assert!(approx_eq_f64(fpart, -0.75, 1e-15));
}

#[test]
fn frexp_and_ldexp_round_trip() {
    use frankenlibc_abi::math_abi::{frexp, ldexp};
    let mut exp_val: c_int = 0;
    let frac = unsafe { frexp(8.0, &mut exp_val) };
    // 8.0 = 0.5 * 2^4
    assert!(approx_eq_f64(frac, 0.5, 1e-15));
    assert_eq!(exp_val, 4);

    let reconstructed = unsafe { ldexp(frac, exp_val) };
    assert!(approx_eq_f64(reconstructed, 8.0, 1e-15));
}

#[test]
fn scalbn_known_values() {
    use frankenlibc_abi::math_abi::scalbn;
    let got = unsafe { scalbn(1.5, 3) };
    assert!(approx_eq_f64(got, 12.0, 1e-15), "1.5 * 2^3 = 12.0");
}

#[test]
fn scalbln_known_values() {
    use frankenlibc_abi::math_abi::scalbln;
    let got = unsafe { scalbln(1.0, 10) };
    assert!(approx_eq_f64(got, 1024.0, 1e-10));
}

#[test]
fn ilogb_known_values() {
    use frankenlibc_abi::math_abi::ilogb;
    assert_eq!(unsafe { ilogb(8.0) }, 3);
    assert_eq!(unsafe { ilogb(1.0) }, 0);
}

#[test]
fn logb_known_values() {
    use frankenlibc_abi::math_abi::logb;
    assert!(approx_eq_f64(unsafe { logb(8.0) }, 3.0, 1e-15));
    assert!(approx_eq_f64(unsafe { logb(1.0) }, 0.0, 1e-15));
}

// ---------------------------------------------------------------------------
// nextafter, nexttoward
// ---------------------------------------------------------------------------

#[test]
fn nextafter_increments() {
    use frankenlibc_abi::math_abi::nextafter;
    let next = unsafe { nextafter(1.0, 2.0) };
    assert!(next > 1.0, "nextafter(1,2) should be > 1");
    assert!(next < 1.0 + 1e-10, "nextafter(1,2) should be barely > 1");

    let prev = unsafe { nextafter(1.0, 0.0) };
    assert!(prev < 1.0, "nextafter(1,0) should be < 1");
}

#[test]
fn nexttoward_basic() {
    use frankenlibc_abi::math_abi::nexttoward;
    let next = unsafe { nexttoward(1.0, 2.0) };
    assert!(next > 1.0);
}

// ---------------------------------------------------------------------------
// remquo
// ---------------------------------------------------------------------------

#[test]
fn remquo_known_values() {
    use frankenlibc_abi::math_abi::remquo;
    let mut quo: c_int = 0;
    let rem = unsafe { remquo(10.0, 3.0, &mut quo) };
    assert!(approx_eq_f64(rem, 1.0, 1e-12));
    // quo should have the low bits of the quotient (3)
    assert_eq!(quo & 0x7, 3);
}

// ---------------------------------------------------------------------------
// sincos
// ---------------------------------------------------------------------------

#[test]
fn sincos_consistency() {
    use frankenlibc_abi::math_abi::{cos, sin, sincos};
    let x = 1.234;
    let mut s: f64 = 0.0;
    let mut c: f64 = 0.0;
    unsafe { sincos(x, &mut s, &mut c) };

    let s_ref = unsafe { sin(x) };
    let c_ref = unsafe { cos(x) };
    assert!(
        approx_eq_f64(s, s_ref, 1e-15),
        "sincos sin component: {s} vs {s_ref}"
    );
    assert!(
        approx_eq_f64(c, c_ref, 1e-15),
        "sincos cos component: {c} vs {c_ref}"
    );
}

// ---------------------------------------------------------------------------
// nan
// ---------------------------------------------------------------------------

#[test]
fn nan_returns_nan() {
    use frankenlibc_abi::math_abi::nan;
    let got = unsafe { nan(c"".as_ptr()) };
    assert!(got.is_nan());
}

// ---------------------------------------------------------------------------
// erf, erfc, tgamma, lgamma
// ---------------------------------------------------------------------------

#[test]
fn erf_known_values() {
    use frankenlibc_abi::math_abi::erf;
    let got = unsafe { erf(0.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
    // erf(large) -> 1
    let got = unsafe { erf(5.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-10));
}

#[test]
fn erfc_known_values() {
    use frankenlibc_abi::math_abi::erfc;
    let got = unsafe { erfc(0.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
}

#[test]
fn tgamma_known_values() {
    use frankenlibc_abi::math_abi::tgamma;
    // gamma(1) = 0! = 1
    let got = unsafe { tgamma(1.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-12));
    // gamma(5) = 4! = 24
    let got = unsafe { tgamma(5.0) };
    assert!(approx_eq_f64(got, 24.0, 1e-10));
    // gamma(0.5) = sqrt(pi)
    let got = unsafe { tgamma(0.5) };
    assert!(approx_eq_f64(got, std::f64::consts::PI.sqrt(), 1e-12));
}

#[test]
fn lgamma_known_values() {
    use frankenlibc_abi::math_abi::lgamma;
    // lgamma(1) = ln(0!) = 0
    let got = unsafe { lgamma(1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-12));
    // lgamma(2) = ln(1!) = 0
    let got = unsafe { lgamma(2.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-12));
}

#[test]
fn lgamma_r_returns_sign() {
    use frankenlibc_abi::math_abi::lgamma_r;
    let mut sign: c_int = 0;
    let got = unsafe { lgamma_r(1.0, &mut sign) };
    assert!(approx_eq_f64(got, 0.0, 1e-12));
    assert_eq!(sign, 1, "sign of gamma(1) should be positive");
}

// ---------------------------------------------------------------------------
// Bessel functions
// ---------------------------------------------------------------------------

#[test]
fn j0_j1_jn_basic() {
    use frankenlibc_abi::math_abi::{j0, j1, jn};
    let j0_0 = unsafe { j0(0.0) };
    assert!(approx_eq_f64(j0_0, 1.0, 1e-12), "J0(0) = 1");

    let j1_0 = unsafe { j1(0.0) };
    assert!(approx_eq_f64(j1_0, 0.0, 1e-12), "J1(0) = 0");

    let jn_0 = unsafe { jn(0, 0.0) };
    assert!(approx_eq_f64(jn_0, 1.0, 1e-12), "Jn(0, 0) = J0(0) = 1");
}

#[test]
fn y0_y1_yn_basic() {
    use frankenlibc_abi::math_abi::{y0, y1, yn};
    // Y0(0) = -Inf (pole)
    let y0_0 = unsafe { y0(0.0) };
    assert!(
        y0_0.is_infinite() && y0_0.is_sign_negative(),
        "Y0(0) should be -Inf"
    );

    // Y0 at a positive value should be finite
    let y0_1 = unsafe { y0(1.0) };
    assert!(y0_1.is_finite(), "Y0(1) should be finite");

    // Y1 at a positive value should be finite
    let y1_1 = unsafe { y1(1.0) };
    assert!(y1_1.is_finite(), "Y1(1) should be finite");

    // Yn(0, x) = Y0(x)
    let yn_0_1 = unsafe { yn(0, 1.0) };
    assert!(approx_eq_f64(yn_0_1, y0_1, 1e-12));
}

// ---------------------------------------------------------------------------
// Float (f32) variants
// ---------------------------------------------------------------------------

#[test]
fn sinf_cosf_tanf_basic() {
    use frankenlibc_abi::math_abi::{cosf, sinf, tanf};
    let s = unsafe { sinf(0.0) };
    assert!(approx_eq_f32(s, 0.0, 1e-6));
    let c = unsafe { cosf(0.0) };
    assert!(approx_eq_f32(c, 1.0, 1e-6));
    let t = unsafe { tanf(0.0) };
    assert!(approx_eq_f32(t, 0.0, 1e-6));
}

#[test]
fn expf_logf_basic() {
    use frankenlibc_abi::math_abi::{expf, logf};
    let e = unsafe { expf(0.0) };
    assert!(approx_eq_f32(e, 1.0, 1e-6));
    let l = unsafe { logf(1.0) };
    assert!(approx_eq_f32(l, 0.0, 1e-6));
}

#[test]
fn sqrtf_basic() {
    use frankenlibc_abi::math_abi::sqrtf;
    let got = unsafe { sqrtf(4.0) };
    assert!(approx_eq_f32(got, 2.0, 1e-6));
}

#[test]
fn fabsf_basic() {
    use frankenlibc_abi::math_abi::fabsf;
    assert_eq!(unsafe { fabsf(-7.5) }, 7.5);
    assert_eq!(unsafe { fabsf(7.5) }, 7.5);
}

#[test]
fn ceilf_floorf_roundf_truncf() {
    use frankenlibc_abi::math_abi::{ceilf, floorf, roundf, truncf};
    assert_eq!(unsafe { ceilf(2.3) }, 3.0);
    assert_eq!(unsafe { floorf(2.7) }, 2.0);
    assert_eq!(unsafe { roundf(2.5) }, 3.0);
    assert_eq!(unsafe { truncf(2.9) }, 2.0);
}

#[test]
fn fmodf_basic() {
    use frankenlibc_abi::math_abi::fmodf;
    let got = unsafe { fmodf(7.0, 3.0) };
    assert!(approx_eq_f32(got, 1.0, 1e-6));
}

#[test]
fn hypotf_basic() {
    use frankenlibc_abi::math_abi::hypotf;
    let got = unsafe { hypotf(3.0, 4.0) };
    assert!(approx_eq_f32(got, 5.0, 1e-5));
}

#[test]
fn copysignf_basic() {
    use frankenlibc_abi::math_abi::copysignf;
    assert_eq!(unsafe { copysignf(5.0, -1.0) }, -5.0);
}

#[test]
fn fminf_fmaxf_basic() {
    use frankenlibc_abi::math_abi::{fmaxf, fminf};
    assert_eq!(unsafe { fminf(2.0, 3.0) }, 2.0);
    assert_eq!(unsafe { fmaxf(2.0, 3.0) }, 3.0);
}

#[test]
fn fmaf_basic() {
    use frankenlibc_abi::math_abi::fmaf;
    let got = unsafe { fmaf(2.0, 3.0, 4.0) };
    assert!(approx_eq_f32(got, 10.0, 1e-6));
}

#[test]
fn erff_erfcf_basic() {
    use frankenlibc_abi::math_abi::{erfcf, erff};
    let e = unsafe { erff(0.0) };
    assert!(approx_eq_f32(e, 0.0, 1e-6));
    let ec = unsafe { erfcf(0.0) };
    assert!(approx_eq_f32(ec, 1.0, 1e-6));
}

#[test]
fn tgammaf_lgammaf_basic() {
    use frankenlibc_abi::math_abi::{lgammaf, tgammaf};
    let g = unsafe { tgammaf(5.0) };
    assert!(approx_eq_f32(g, 24.0, 1e-3));
    let lg = unsafe { lgammaf(1.0) };
    assert!(approx_eq_f32(lg, 0.0, 1e-5));
}

#[test]
fn lgammaf_r_returns_sign() {
    use frankenlibc_abi::math_abi::lgammaf_r;
    let mut sign: c_int = 0;
    let got = unsafe { lgammaf_r(1.0, &mut sign) };
    assert!(approx_eq_f32(got, 0.0, 1e-5));
    assert_eq!(sign, 1);
}

#[test]
fn rintf_nearbyintf_basic() {
    use frankenlibc_abi::math_abi::{nearbyintf, rintf};
    let r = unsafe { rintf(2.5) };
    assert_eq!(r, 2.0, "rintf ties to even");
    let n = unsafe { nearbyintf(3.5) };
    assert_eq!(n, 4.0, "nearbyintf ties to even");
}

#[test]
fn frexpf_ldexpf_round_trip() {
    use frankenlibc_abi::math_abi::{frexpf, ldexpf};
    let mut exp_val: c_int = 0;
    let frac = unsafe { frexpf(16.0, &mut exp_val) };
    assert!(approx_eq_f32(frac, 0.5, 1e-6));
    assert_eq!(exp_val, 5, "16 = 0.5 * 2^5");
    let reconstructed = unsafe { ldexpf(frac, exp_val) };
    assert!(approx_eq_f32(reconstructed, 16.0, 1e-6));
}

#[test]
fn modff_splits_correctly() {
    use frankenlibc_abi::math_abi::modff;
    let mut ipart: f32 = 0.0;
    let fpart = unsafe { modff(3.75, &mut ipart) };
    assert!(approx_eq_f32(ipart, 3.0, 1e-6));
    assert!(approx_eq_f32(fpart, 0.75, 1e-6));
}

#[test]
fn ilogbf_scalbnf_basic() {
    use frankenlibc_abi::math_abi::{ilogbf, scalbnf};
    assert_eq!(unsafe { ilogbf(8.0) }, 3);
    let got = unsafe { scalbnf(1.5, 3) };
    assert!(approx_eq_f32(got, 12.0, 1e-6));
}

#[test]
fn nextafterf_basic() {
    use frankenlibc_abi::math_abi::nextafterf;
    let next = unsafe { nextafterf(1.0, 2.0) };
    assert!(next > 1.0);
}

#[test]
fn remquof_basic() {
    use frankenlibc_abi::math_abi::remquof;
    let mut quo: c_int = 0;
    let rem = unsafe { remquof(10.0, 3.0, &mut quo) };
    assert!(approx_eq_f32(rem, 1.0, 1e-5));
    assert_eq!(quo & 0x7, 3);
}

#[test]
fn sincosf_consistency() {
    use frankenlibc_abi::math_abi::{cosf, sinf, sincosf};
    let x: f32 = 1.234;
    let mut s: f32 = 0.0;
    let mut c: f32 = 0.0;
    unsafe { sincosf(x, &mut s, &mut c) };
    let s_ref = unsafe { sinf(x) };
    let c_ref = unsafe { cosf(x) };
    assert!(approx_eq_f32(s, s_ref, 1e-6));
    assert!(approx_eq_f32(c, c_ref, 1e-6));
}

#[test]
fn nanf_returns_nan() {
    use frankenlibc_abi::math_abi::nanf;
    let got = unsafe { nanf(c"".as_ptr()) };
    assert!(got.is_nan());
}

#[test]
fn j0f_j1f_basic() {
    use frankenlibc_abi::math_abi::{j0f, j1f};
    let got = unsafe { j0f(0.0) };
    assert!(approx_eq_f32(got, 1.0, 1e-5));
    let got = unsafe { j1f(0.0) };
    assert!(approx_eq_f32(got, 0.0, 1e-5));
}

#[test]
fn fdimf_basic() {
    use frankenlibc_abi::math_abi::fdimf;
    assert_eq!(unsafe { fdimf(5.0, 3.0) }, 2.0);
    assert_eq!(unsafe { fdimf(3.0, 5.0) }, 0.0);
}

#[test]
fn remainderf_basic() {
    use frankenlibc_abi::math_abi::remainderf;
    let got = unsafe { remainderf(7.0, 3.0) };
    assert!(approx_eq_f32(got, 1.0, 1e-5));
}

// ---------------------------------------------------------------------------
// C23 fmaximum / fminimum (IEEE 754-2019)
// ---------------------------------------------------------------------------

#[test]
fn fmaximum_basic() {
    use frankenlibc_abi::math_abi::fmaximum;
    assert_eq!(unsafe { fmaximum(2.0, 3.0) }, 3.0);
    assert_eq!(unsafe { fmaximum(-1.0, -2.0) }, -1.0);
}

#[test]
fn fmaximum_nan_propagation() {
    use frankenlibc_abi::math_abi::fmaximum;
    // C23 fmaximum: if either arg is NaN, result is NaN (unlike fmax)
    let got = unsafe { fmaximum(f64::NAN, 5.0) };
    assert!(got.is_nan(), "fmaximum(NaN, 5) should be NaN per C23");
    let got = unsafe { fmaximum(5.0, f64::NAN) };
    assert!(got.is_nan(), "fmaximum(5, NaN) should be NaN per C23");
}

#[test]
fn fmaximumf_basic() {
    use frankenlibc_abi::math_abi::fmaximumf;
    assert_eq!(unsafe { fmaximumf(2.0, 3.0) }, 3.0_f32);
    let got = unsafe { fmaximumf(f32::NAN, 5.0) };
    assert!(got.is_nan());
}

#[test]
fn fmaximum_num_nan_handling() {
    use frankenlibc_abi::math_abi::fmaximum_num;
    // fmaximum_num: NaN is treated as missing, returns the non-NaN arg
    let got = unsafe { fmaximum_num(f64::NAN, 5.0) };
    assert_eq!(got, 5.0, "fmaximum_num(NaN, 5) should be 5");
    let got = unsafe { fmaximum_num(5.0, f64::NAN) };
    assert_eq!(got, 5.0, "fmaximum_num(5, NaN) should be 5");
}

// ---------------------------------------------------------------------------
// C23 fminimum / fminimum_num
// ---------------------------------------------------------------------------

#[test]
fn fminimum_basic() {
    use frankenlibc_abi::math_abi::fminimum;
    assert_eq!(unsafe { fminimum(2.0, 3.0) }, 2.0);
}

#[test]
fn fminimum_nan_propagation() {
    use frankenlibc_abi::math_abi::fminimum;
    let got = unsafe { fminimum(f64::NAN, 5.0) };
    assert!(got.is_nan(), "fminimum(NaN, 5) should be NaN per C23");
}

#[test]
fn fminimumf_basic() {
    use frankenlibc_abi::math_abi::fminimumf;
    assert_eq!(unsafe { fminimumf(2.0, 3.0) }, 2.0_f32);
}

#[test]
fn fminimum_num_nan_handling() {
    use frankenlibc_abi::math_abi::fminimum_num;
    let got = unsafe { fminimum_num(f64::NAN, 5.0) };
    assert_eq!(got, 5.0);
}

// ---------------------------------------------------------------------------
// C23 fmaximum_mag / fminimum_mag
// ---------------------------------------------------------------------------

#[test]
fn fmaximum_mag_basic() {
    use frankenlibc_abi::math_abi::fmaximum_mag;
    // Returns arg with greater absolute value
    let got = unsafe { fmaximum_mag(-5.0, 3.0) };
    assert_eq!(got, -5.0, "|-5| > |3| so result is -5");
    let got = unsafe { fmaximum_mag(2.0, -2.0) };
    // Equal magnitude: returns the positive one (or the first, per IEEE)
    assert!(got.abs() == 2.0);
}

#[test]
fn fminimum_mag_basic() {
    use frankenlibc_abi::math_abi::fminimum_mag;
    let got = unsafe { fminimum_mag(-5.0, 3.0) };
    assert_eq!(got, 3.0, "|3| < |-5| so result is 3");
}

// ---------------------------------------------------------------------------
// Type-generic width aliases (f32/f64 variants)
// ---------------------------------------------------------------------------

#[test]
fn sinf32_cosf64_aliases() {
    use frankenlibc_abi::math_abi::{cosf64, sinf32};
    let s = unsafe { sinf32(0.0) };
    assert!(approx_eq_f32(s, 0.0, 1e-6));
    let c = unsafe { cosf64(0.0) };
    assert!(approx_eq_f64(c, 1.0, 1e-15));
}

#[test]
fn expf32_logf64_aliases() {
    use frankenlibc_abi::math_abi::{expf32, logf64};
    let e = unsafe { expf32(0.0) };
    assert!(approx_eq_f32(e, 1.0, 1e-6));
    let l = unsafe { logf64(1.0) };
    assert!(approx_eq_f64(l, 0.0, 1e-15));
}

#[test]
fn sqrtf32_sqrtf64_aliases() {
    use frankenlibc_abi::math_abi::{sqrtf32, sqrtf64};
    let s32 = unsafe { sqrtf32(4.0) };
    assert!(approx_eq_f32(s32, 2.0, 1e-6));
    let s64 = unsafe { sqrtf64(9.0) };
    assert!(approx_eq_f64(s64, 3.0, 1e-15));
}

#[test]
fn fabsf32_fabsf64_aliases() {
    use frankenlibc_abi::math_abi::{fabsf32, fabsf64};
    assert_eq!(unsafe { fabsf32(-3.0) }, 3.0_f32);
    assert_eq!(unsafe { fabsf64(-7.0) }, 7.0_f64);
}

// ---------------------------------------------------------------------------
// Negative zero handling
// ---------------------------------------------------------------------------

#[test]
fn negative_zero_propagation() {
    use frankenlibc_abi::math_abi::{ceil, floor, sin, trunc};
    // sin(-0) should be -0
    let got = unsafe { sin(-0.0_f64) };
    assert!(got == 0.0 && got.is_sign_negative(), "sin(-0) should be -0");

    // floor(-0) = -0
    let got = unsafe { floor(-0.0_f64) };
    assert!(got == 0.0 && got.is_sign_negative(), "floor(-0) should be -0");

    // ceil(-0) = -0
    let got = unsafe { ceil(-0.0_f64) };
    assert!(got == 0.0 && got.is_sign_negative(), "ceil(-0) should be -0");

    // trunc(-0) = -0
    let got = unsafe { trunc(-0.0_f64) };
    assert!(got == 0.0 && got.is_sign_negative(), "trunc(-0) should be -0");
}

// ---------------------------------------------------------------------------
// Infinity handling
// ---------------------------------------------------------------------------

#[test]
fn exp_overflow_to_infinity() {
    use frankenlibc_abi::math_abi::exp;
    let got = unsafe { exp(1000.0) };
    assert!(got.is_infinite() && got.is_sign_positive());
}

#[test]
fn exp_underflow_to_zero() {
    use frankenlibc_abi::math_abi::exp;
    let got = unsafe { exp(-1000.0) };
    assert_eq!(got, 0.0);
}

#[test]
fn log_infinity() {
    use frankenlibc_abi::math_abi::log;
    let got = unsafe { log(f64::INFINITY) };
    assert!(got.is_infinite() && got.is_sign_positive());
}

// ---------------------------------------------------------------------------
// Long-double (f64 aliases on x86_64) spot checks
// ---------------------------------------------------------------------------

#[test]
fn sinl_cosl_basic() {
    use frankenlibc_abi::math_abi::{cosl, sinl};
    let s = unsafe { sinl(0.0) };
    assert!(approx_eq_f64(s, 0.0, 1e-15));
    let c = unsafe { cosl(0.0) };
    assert!(approx_eq_f64(c, 1.0, 1e-15));
}

#[test]
fn expl_logl_basic() {
    use frankenlibc_abi::math_abi::{expl, logl};
    let e = unsafe { expl(0.0) };
    assert!(approx_eq_f64(e, 1.0, 1e-15));
    let l = unsafe { logl(1.0) };
    assert!(approx_eq_f64(l, 0.0, 1e-15));
}

#[test]
fn sqrtl_basic() {
    use frankenlibc_abi::math_abi::sqrtl;
    let got = unsafe { sqrtl(25.0) };
    assert!(approx_eq_f64(got, 5.0, 1e-15));
}

#[test]
fn ceill_floorl_roundl_truncl() {
    use frankenlibc_abi::math_abi::{ceill, floorl, roundl, truncl};
    assert_eq!(unsafe { ceill(2.3) }, 3.0);
    assert_eq!(unsafe { floorl(2.7) }, 2.0);
    assert_eq!(unsafe { roundl(2.5) }, 3.0);
    assert_eq!(unsafe { truncl(2.9) }, 2.0);
}

#[test]
fn fabsl_basic() {
    use frankenlibc_abi::math_abi::fabsl;
    assert_eq!(unsafe { fabsl(-9.0) }, 9.0);
}

#[test]
fn sincosl_consistency() {
    use frankenlibc_abi::math_abi::{cosl, sincosl, sinl};
    let x = 1.5;
    let mut s: f64 = 0.0;
    let mut c: f64 = 0.0;
    unsafe { sincosl(x, &mut s, &mut c) };
    let s_ref = unsafe { sinl(x) };
    let c_ref = unsafe { cosl(x) };
    assert!(approx_eq_f64(s, s_ref, 1e-15));
    assert!(approx_eq_f64(c, c_ref, 1e-15));
}

// ---------------------------------------------------------------------------
// __finite aliases (spot checks)
// ---------------------------------------------------------------------------

#[test]
fn __exp_finite_alias() {
    use frankenlibc_abi::math_abi::__exp_finite;
    let got = unsafe { __exp_finite(0.0) };
    assert!(approx_eq_f64(got, 1.0, 1e-15));
}

#[test]
fn __log_finite_alias() {
    use frankenlibc_abi::math_abi::__log_finite;
    let got = unsafe { __log_finite(1.0) };
    assert!(approx_eq_f64(got, 0.0, 1e-15));
}

#[test]
fn __pow_finite_alias() {
    use frankenlibc_abi::math_abi::__pow_finite;
    let got = unsafe { __pow_finite(2.0, 10.0) };
    assert!(approx_eq_f64(got, 1024.0, 1e-10));
}

#[test]
fn __sqrt_finite_alias() {
    use frankenlibc_abi::math_abi::__sqrt_finite;
    let got = unsafe { __sqrt_finite(16.0) };
    assert!(approx_eq_f64(got, 4.0, 1e-15));
}

// ---------------------------------------------------------------------------
// Additional __finite aliases (spot checks)
// ---------------------------------------------------------------------------

#[test]
fn __expf_finite_alias() {
    use frankenlibc_abi::math_abi::__expf_finite;
    let got = unsafe { __expf_finite(0.0) };
    assert!(approx_eq_f32(got, 1.0, 1e-6));
}

#[test]
fn __sqrtf_finite_alias() {
    use frankenlibc_abi::math_abi::__sqrtf_finite;
    let got = unsafe { __sqrtf_finite(9.0) };
    assert!(approx_eq_f32(got, 3.0, 1e-5));
}
