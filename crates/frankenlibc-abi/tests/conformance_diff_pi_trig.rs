//! Differential gate for the C23 pi-scaled trig functions sinpi/cospi/tanpi
//! (+ f32) vs host glibc.
//!
//! These must produce EXACT results at integer and half-integer arguments
//! (sinpi(n)=±0, cospi(n+0.5)=+0, cospi(n)=±1, tanpi(n+0.5)=±inf with
//! FE_DIVBYZERO) and stay correct for huge arguments — properties the naive
//! `sin(x*PI)` formulation violates. fl is called via Rust paths; glibc is
//! reached through `dlsym` on libm.so.6 so the fn pointer bypasses fl's
//! no_mangle interposition of the same symbol. FP exception flags are hardware
//! (MXCSR), read directly with fetestexcept — no interposition concern.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const HARD: c_int = 0x1D; // INVALID|DIVBYZERO|OVERFLOW|UNDERFLOW

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
}

fn libm() -> *mut c_void {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm failed");
    h
}
fn sym(h: *mut c_void, name: &std::ffi::CStr) -> *mut c_void {
    let p = unsafe { dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing libm symbol {name:?}");
    p
}

fn ulp_ok_f64(a: f64, b: f64) -> bool {
    // b is the glibc reference. Exact bit match for non-finite / zero (sign
    // matters); <=4 ULP for finite nonzero (the math conformance contract).
    if b.is_nan() {
        return a.is_nan();
    }
    if !b.is_finite() || b == 0.0 {
        return a.to_bits() == b.to_bits();
    }
    if a.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }
    let ai = a.to_bits() as i64;
    let bi = b.to_bits() as i64;
    (ai - bi).unsigned_abs() <= 4
}
fn ulp_ok_f32(a: f32, b: f32) -> bool {
    if b.is_nan() {
        return a.is_nan();
    }
    if !b.is_finite() || b == 0.0 {
        return a.to_bits() == b.to_bits();
    }
    if a.is_nan() || a.is_sign_negative() != b.is_sign_negative() {
        return false;
    }
    let ai = a.to_bits() as i32;
    let bi = b.to_bits() as i32;
    (ai - bi).unsigned_abs() <= 4
}

const XS: &[f64] = &[
    0.0,
    -0.0,
    0.5,
    1.0,
    1.5,
    2.0,
    2.5,
    3.0,
    -0.5,
    -1.0,
    -1.5,
    -2.0,
    -2.5,
    -3.0,
    0.25,
    0.75,
    -0.25,
    0.1,
    0.2,
    0.3,
    0.4,
    0.45,
    0.7,
    1.3,
    2.7,
    -3.3,
    4.25,
    10.1,
    10.25,
    -0.123,
    100.5,
    1000.25,
    1.0 / 3.0,
    1e15,
    1e20,
    -1e20,
    9007199254740992.0,
    0.5 + 1e15,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
];
const XSF: &[f32] = &[
    0.0,
    -0.0,
    0.5,
    1.0,
    1.5,
    2.0,
    -0.5,
    -1.0,
    0.25,
    0.75,
    0.1,
    0.3,
    0.7,
    10.25,
    16777216.0,
    f32::INFINITY,
    f32::NAN,
];

#[test]
fn pi_trig_matches_glibc() {
    let h = libm();
    let g_sinpi: extern "C" fn(f64) -> f64 = unsafe { core::mem::transmute(sym(h, c"sinpi")) };
    let g_cospi: extern "C" fn(f64) -> f64 = unsafe { core::mem::transmute(sym(h, c"cospi")) };
    let g_tanpi: extern "C" fn(f64) -> f64 = unsafe { core::mem::transmute(sym(h, c"tanpi")) };
    let g_sinpif: extern "C" fn(f32) -> f32 = unsafe { core::mem::transmute(sym(h, c"sinpif")) };
    let g_cospif: extern "C" fn(f32) -> f32 = unsafe { core::mem::transmute(sym(h, c"cospif")) };
    let g_tanpif: extern "C" fn(f32) -> f32 = unsafe { core::mem::transmute(sym(h, c"tanpif")) };

    let mut div: Vec<String> = Vec::new();

    macro_rules! cmp64 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let x: f64 = $x;
            unsafe { feclearexcept(HARD) };
            let fv = unsafe { $flf(x) };
            let ff = unsafe { fetestexcept(HARD) } & HARD;
            unsafe { feclearexcept(HARD) };
            let gv = $gf(x);
            let gf2 = unsafe { fetestexcept(HARD) } & HARD;
            if !ulp_ok_f64(fv, gv) || ff != gf2 {
                div.push(format!(
                    "{}({:.6e}): fl={:016x}/flags{:#x} glibc={:016x}/flags{:#x}",
                    $name,
                    x,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gf2
                ));
            }
        }};
    }
    macro_rules! cmp32 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let x: f32 = $x;
            unsafe { feclearexcept(HARD) };
            let fv = unsafe { $flf(x) };
            let ff = unsafe { fetestexcept(HARD) } & HARD;
            unsafe { feclearexcept(HARD) };
            let gv = $gf(x);
            let gf2 = unsafe { fetestexcept(HARD) } & HARD;
            if !ulp_ok_f32(fv, gv) || ff != gf2 {
                div.push(format!(
                    "{}({:.6e}): fl={:08x}/flags{:#x} glibc={:08x}/flags{:#x}",
                    $name,
                    x,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gf2
                ));
            }
        }};
    }

    for &x in XS {
        cmp64!("sinpi", fl::sinpi, g_sinpi, x);
        cmp64!("cospi", fl::cospi, g_cospi, x);
        cmp64!("tanpi", fl::tanpi, g_tanpi, x);
    }
    for &x in XSF {
        cmp32!("sinpif", fl::sinpif, g_sinpif, x);
        cmp32!("cospif", fl::cospif, g_cospif, x);
        cmp32!("tanpif", fl::tanpif, g_tanpif, x);
    }

    assert!(
        div.is_empty(),
        "pi-trig divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
