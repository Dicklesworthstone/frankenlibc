#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math + fetestexcept oracle
//! C99/IEEE floating-point exception-flag parity vs glibc for math functions on
//! domain/pole/overflow inputs. libm software impls return the correct VALUE but
//! often omit the flag glibc raises; fl re-raises FE_DIVBYZERO (log(±0)),
//! FE_INVALID (log(x<0), tgamma(neg-int)) on the cold special path. Programs
//! using feenableexcept / fetestexcept (scientific NaN-trapping) depend on this.
//! Checks both the raised flags AND the returned value.

use frankenlibc_core::math as fl;
use std::ffi::c_int;
unsafe extern "C" {
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
    fn sqrt(x: f64) -> f64; fn log(x: f64) -> f64; fn log2(x: f64) -> f64; fn log10(x: f64) -> f64;
    fn exp(x: f64) -> f64; fn pow(x: f64, y: f64) -> f64; fn acos(x: f64) -> f64; fn asin(x: f64) -> f64;
    fn acosh(x: f64) -> f64; fn atanh(x: f64) -> f64; fn tgamma(x: f64) -> f64; fn fmod(x: f64, y: f64) -> f64;
    fn logf(x: f32)->f32; fn log2f(x: f32)->f32; fn log10f(x: f32)->f32; fn sqrtf(x: f32)->f32;
    fn acosf(x: f32)->f32; fn acoshf(x: f32)->f32; fn tgammaf(x: f32)->f32; fn powf(x: f32,y: f32)->f32;
    fn nextafter(x: f64, y: f64) -> f64; fn nextafterf(x: f32, y: f32) -> f32;
    fn lgamma(x: f64)->f64; fn lgammaf(x: f32)->f32; fn exp2(x: f64)->f64; fn expm1(x: f64)->f64;
    fn atanhf(x: f32)->f32; fn log1p(x: f64)->f64; fn log1pf(x: f32)->f32;
}
const HARD: c_int = 0x1D; // INVALID|DIVBYZERO|OVERFLOW|UNDERFLOW (drop noisy INEXACT)
fn key(x: f64) -> i64 { let b = x.to_bits() as i64; if b < 0 { i64::MIN - b } else { b } }
// Value parity: NaN<->NaN, exact at inf/zero boundaries, <=4 ULP for finite
// transcendental results (the math conformance contract; exception flags stay exact).
fn beq(a: f64, b: f64) -> bool {
    if a.is_nan() && b.is_nan() { return true; }
    if a.is_nan() != b.is_nan() { return false; }
    if a.is_infinite() || b.is_infinite() || a == 0.0 || b == 0.0 { return a.to_bits() == b.to_bits(); }
    (key(a).wrapping_sub(key(b))).unsigned_abs() <= 4
}

#[test]
fn fp_exception_and_value_parity_vs_glibc() {
    let mut div = Vec::new();
    macro_rules! chk { ($lbl:literal, $flf:expr, $gf:expr) => {{
        unsafe { feclearexcept(HARD); }
        let fv = $flf;
        let ff = unsafe { fetestexcept(HARD) };
        unsafe { feclearexcept(HARD); }
        let gv = unsafe { $gf };
        let gf = unsafe { fetestexcept(HARD) };
        if (ff & HARD) != (gf & HARD) {
            div.push(format!("{} flags: fl={:#x} glibc={:#x}", $lbl, ff & HARD, gf & HARD));
        }
        if !beq(fv, gv) {
            div.push(format!("{} value: fl={:?} glibc={:?}", $lbl, fv, gv));
        }
    }}; }
    chk!("sqrt(-1)", fl::sqrt(-1.0), sqrt(-1.0));
    chk!("log(0)", fl::log(0.0), log(0.0));
    chk!("log(-0)", fl::log(-0.0), log(-0.0));
    chk!("log(-1)", fl::log(-1.0), log(-1.0));
    chk!("log(-inf)", fl::log(f64::NEG_INFINITY), log(f64::NEG_INFINITY));
    chk!("log2(0)", fl::log2(0.0), log2(0.0));
    chk!("log10(-2)", fl::log10(-2.0), log10(-2.0));
    chk!("exp(1000)", fl::exp(1000.0), exp(1000.0));
    chk!("pow(0,-1)", fl::pow(0.0,-1.0), pow(0.0,-1.0));
    chk!("pow(-1,0.5)", fl::pow(-1.0,0.5), pow(-1.0,0.5));
    chk!("acos(2)", fl::acos(2.0), acos(2.0));
    chk!("asin(-2)", fl::asin(-2.0), asin(-2.0));
    chk!("acosh(0.5)", fl::acosh(0.5), acosh(0.5));
    chk!("atanh(2)", fl::atanh(2.0), atanh(2.0));
    chk!("tgamma(0)", fl::tgamma(0.0), tgamma(0.0));
    chk!("tgamma(-1)", fl::tgamma(-1.0), tgamma(-1.0));
    chk!("tgamma(-5)", fl::tgamma(-5.0), tgamma(-5.0));
    chk!("tgamma(-2.5)", fl::tgamma(-2.5), tgamma(-2.5));
    chk!("fmod(1,0)", fl::fmod(1.0,0.0), fmod(1.0,0.0));

    // f32 variants (libm f32 omits the same flags; fl re-raises)
    macro_rules! chkf { ($lbl:literal, $flf:expr, $gf:expr) => {{
        unsafe { feclearexcept(HARD); }
        let _ = std::hint::black_box($flf);
        let ff = unsafe { fetestexcept(HARD) };
        unsafe { feclearexcept(HARD); }
        let _ = std::hint::black_box(unsafe { $gf });
        let gf = unsafe { fetestexcept(HARD) };
        if (ff & HARD) != (gf & HARD) {
            div.push(format!("{} flags: fl={:#x} glibc={:#x}", $lbl, ff & HARD, gf & HARD));
        }
    }}; }
    chkf!("logf(0)", fl::logf(0.0), logf(0.0));
    chkf!("logf(-1)", fl::logf(-1.0), logf(-1.0));
    chkf!("log2f(0)", fl::log2f(0.0), log2f(0.0));
    chkf!("log2f(-1)", fl::log2f(-1.0), log2f(-1.0));
    chkf!("log10f(-2)", fl::log10f(-2.0), log10f(-2.0));
    chkf!("sqrtf(-1)", fl::sqrtf(-1.0), sqrtf(-1.0));
    chkf!("acosf(2)", fl::acosf(2.0), acosf(2.0));
    chkf!("acoshf(0.5)", fl::acoshf(0.5), acoshf(0.5));
    chkf!("tgammaf(-1)", fl::tgammaf(-1.0), tgammaf(-1.0));
    chkf!("tgammaf(-5)", fl::tgammaf(-5.0), tgammaf(-5.0));
    chkf!("powf(0,-1)", fl::powf(0.0,-1.0), powf(0.0,-1.0));

    // nextafter / nextafterf: C99 F.10.8.3 OVERFLOW (finite->inf) + UNDERFLOW
    // (result subnormal/zero). The flag-only macros reuse chkf; for f64 wrap via
    // a closure-free direct call.
    macro_rules! chk2 { ($lbl:literal, $flf:expr, $gf:expr) => {{
        unsafe { feclearexcept(HARD); } let _ = std::hint::black_box($flf); let ff = unsafe { fetestexcept(HARD) };
        unsafe { feclearexcept(HARD); } let _ = std::hint::black_box(unsafe { $gf }); let gf = unsafe { fetestexcept(HARD) };
        if (ff & HARD) != (gf & HARD) { div.push(format!("{} flags: fl={:#x} glibc={:#x}", $lbl, ff & HARD, gf & HARD)); }
    }}; }
    chk2!("nextafter(0,1)", fl::nextafter(0.0,1.0), nextafter(0.0,1.0));
    chk2!("nextafter(0,-1)", fl::nextafter(0.0,-1.0), nextafter(0.0,-1.0));
    chk2!("nextafter(MAX,INF)", fl::nextafter(f64::MAX,f64::INFINITY), nextafter(f64::MAX,f64::INFINITY));
    chk2!("nextafter(minpos,0)", fl::nextafter(f64::MIN_POSITIVE,0.0), nextafter(f64::MIN_POSITIVE,0.0));
    chk2!("nextafter(5,5)", fl::nextafter(5.0,5.0), nextafter(5.0,5.0));
    chk2!("nextafter(1,2)", fl::nextafter(1.0,2.0), nextafter(1.0,2.0));
    chk2!("nextafterf(0,1)", fl::nextafterf(0.0,1.0), nextafterf(0.0,1.0));
    chk2!("nextafterf(MAX,INF)", fl::nextafterf(f32::MAX,f32::INFINITY), nextafterf(f32::MAX,f32::INFINITY));
    chk2!("nextafterf(minpos,0)", fl::nextafterf(f32::MIN_POSITIVE,0.0), nextafterf(f32::MIN_POSITIVE,0.0));

    // lgamma poles (DIVBYZERO at non-positive integers) + the OVERFLOW family
    // (tgamma/exp2/pow). All currently correct vs glibc; pinned so a future
    // change can't silently drop the flag (complements the tgamma-pole fix).
    chk2!("lgamma(0)", fl::lgamma(0.0), lgamma(0.0));
    chk2!("lgamma(-1)", fl::lgamma(-1.0), lgamma(-1.0));
    chk2!("lgamma(-2)", fl::lgamma(-2.0), lgamma(-2.0));
    chk2!("lgammaf(0)", fl::lgammaf(0.0), lgammaf(0.0));
    chk2!("lgammaf(-1)", fl::lgammaf(-1.0), lgammaf(-1.0));
    chk2!("tgamma(200)", fl::tgamma(200.0), tgamma(200.0));
    chk2!("exp2(2000)", fl::exp2(2000.0), exp2(2000.0));
    chk2!("exp2(-2000)", fl::exp2(-2000.0), exp2(-2000.0));
    chk2!("expm1(1000)", fl::expm1(1000.0), expm1(1000.0));
    chk2!("pow(10,400)", fl::pow(10.0,400.0), pow(10.0,400.0));
    chk2!("pow(0.1,400)", fl::pow(0.1,400.0), pow(0.1,400.0));

    // atanh / log1p poles (DIVBYZERO) + domain (INVALID): log1p(-1)/log1pf(-1)
    // were under-raising the pole flag (fixed); the rest pin currently-correct
    // behavior (libm raises atanh poles + log1p domain).
    chk2!("atanh(1)", fl::atanh(1.0), atanh(1.0));
    chk2!("atanh(-1)", fl::atanh(-1.0), atanh(-1.0));
    chk2!("atanh(2)", fl::atanh(2.0), atanh(2.0));
    chk2!("atanhf(1)", fl::atanhf(1.0), atanhf(1.0));
    chk2!("log1p(-1)", fl::log1p(-1.0), log1p(-1.0));
    chk2!("log1p(-2)", fl::log1p(-2.0), log1p(-2.0));
    chk2!("log1p(-1.5)", fl::log1p(-1.5), log1p(-1.5));
    chk2!("log1pf(-1)", fl::log1pf(-1.0), log1pf(-1.0));
    chk2!("log1pf(-2)", fl::log1pf(-2.0), log1pf(-2.0));
    assert!(div.is_empty(), "fp-exception/value divergences vs glibc:\n  {}", div.join("\n  "));
}
