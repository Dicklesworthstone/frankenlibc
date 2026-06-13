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
    assert!(div.is_empty(), "fp-exception/value divergences vs glibc:\n  {}", div.join("\n  "));
}
