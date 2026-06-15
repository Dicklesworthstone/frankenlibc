//! Differential gate for the C23 exp2m1/exp10m1 (+ f32) functions vs host glibc.
//!
//! 2^x-1 and 10^x-1 were implemented as the naive `expm1(x*ln(base))`. That
//! reduction multiplies the argument by a rounded constant (LN_2 / LN_10) and
//! then lets the exponential amplify the round-off, diverging from glibc by
//! hundreds of ULP for large |x| (measured: exp2m1 ~703 ULP at x~956, exp10m1
//! ~1080 ULP at x~301, exp2m1f ~68 ULP, exp10m1f ~83 ULP) — far past the 4-ULP
//! conformance contract. The fix uses exp2(x)-1 / exp10(x)-1 away from 0 (where
//! the subtraction is benign and tracks glibc's correctly-rounded exp*) and
//! keeps expm1 only in the near-0 band where 1 sits within an ULP of the result.
//!
//! fl is called through Rust paths; glibc is reached via `dlsym` on libm.so.6 so
//! the fn pointer bypasses fl's no_mangle interposition of the same symbol.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
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

// Curated edges + a dense sweep across the finite ranges of each function.
fn xs_f64(max: f64, step: f64) -> Vec<f64> {
    let mut v = vec![
        0.0,
        -0.0,
        0.5,
        -0.5,
        1.0,
        -1.0,
        f64::MIN_POSITIVE,
        -f64::MIN_POSITIVE,
        1e-300,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
    ];
    let mut x = -max;
    while x <= max {
        v.push(x);
        x += step;
    }
    v
}
fn xs_f32(max: f32, step: f32) -> Vec<f32> {
    let mut v = vec![
        0.0_f32,
        -0.0,
        0.5,
        -0.5,
        1.0,
        -1.0,
        f32::MIN_POSITIVE,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ];
    let mut x = -max;
    while x <= max {
        v.push(x);
        x += step;
    }
    v
}

#[test]
fn exp2m1_exp10m1_matches_glibc() {
    let h = libm();
    let g_exp2m1: extern "C" fn(f64) -> f64 = unsafe { core::mem::transmute(sym(h, c"exp2m1")) };
    let g_exp10m1: extern "C" fn(f64) -> f64 = unsafe { core::mem::transmute(sym(h, c"exp10m1")) };
    let g_exp2m1f: extern "C" fn(f32) -> f32 = unsafe { core::mem::transmute(sym(h, c"exp2m1f")) };
    let g_exp10m1f: extern "C" fn(f32) -> f32 = unsafe { core::mem::transmute(sym(h, c"exp10m1f")) };

    let mut div: Vec<String> = Vec::new();

    macro_rules! cmp64 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let x: f64 = $x;
            let fv = unsafe { $flf(x) };
            let gv = $gf(x);
            if !ulp_ok_f64(fv, gv) {
                div.push(format!(
                    "{}({:.6e}): fl={:016x} glibc={:016x}",
                    $name,
                    x,
                    fv.to_bits(),
                    gv.to_bits()
                ));
            }
        }};
    }
    macro_rules! cmp32 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let x: f32 = $x;
            let fv = unsafe { $flf(x) };
            let gv = $gf(x);
            if !ulp_ok_f32(fv, gv) {
                div.push(format!(
                    "{}({:.6e}): fl={:08x} glibc={:08x}",
                    $name,
                    x,
                    fv.to_bits(),
                    gv.to_bits()
                ));
            }
        }};
    }

    // exp2m1: finite up to overflow near x=1024.
    for &x in &xs_f64(1023.0, 0.013) {
        cmp64!("exp2m1", fl::exp2m1, g_exp2m1, x);
    }
    // exp10m1: finite up to overflow near x=308.25.
    for &x in &xs_f64(308.0, 0.0041) {
        cmp64!("exp10m1", fl::exp10m1, g_exp10m1, x);
    }
    for &x in &xs_f32(127.0, 0.0019) {
        cmp32!("exp2m1f", fl::exp2m1f, g_exp2m1f, x);
    }
    for &x in &xs_f32(38.0, 0.0007) {
        cmp32!("exp10m1f", fl::exp10m1f, g_exp10m1f, x);
    }

    assert!(
        div.is_empty(),
        "exp2m1/exp10m1 divergences vs glibc ({}, showing first 20):\n  {}",
        div.len(),
        div.iter().take(20).cloned().collect::<Vec<_>>().join("\n  ")
    );
}
