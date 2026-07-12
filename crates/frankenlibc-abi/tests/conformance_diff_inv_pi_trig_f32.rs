//! Differential gate: C23 single-precision inverse pi-trig (acospif/asinpif/
//! atanpif/atan2pif) must be byte-exact with glibc.
//!
//! glibc computes these in double precision and rounds once:
//! `(float)(acos((double)x) / pi)`. fl previously did the division in f32
//! (`acosf(x) / pi_f32`), losing 1-2 ULP. Now fl routes through its f64
//! inverse-pi-trig, matching glibc bit-for-bit. glibc is reached via an
//! explicit libm.so.6 handle so fl's no_mangle interposition is bypassed.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type F1 = extern "C" fn(f32) -> f32;
type F2 = extern "C" fn(f32, f32) -> f32;

fn glibc() -> *mut c_void {
    // C23 inverse-pi-trig lives in libm; an explicit handle bypasses fl's
    // interposing definitions of the same symbols.
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm.so.6 failed");
    h
}
unsafe fn sym1(h: *mut c_void, n: &std::ffi::CStr) -> F1 {
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "dlsym {n:?} failed");
    unsafe { std::mem::transmute::<*mut c_void, F1>(p) }
}
unsafe fn sym2(h: *mut c_void, n: &std::ffi::CStr) -> F2 {
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "dlsym {n:?} failed");
    unsafe { std::mem::transmute::<*mut c_void, F2>(p) }
}

fn same_bits(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

#[test]
fn inv_pi_trig_f32_matches_glibc() {
    let h = glibc();
    let g_acospif = unsafe { sym1(h, c"acospif") };
    let g_asinpif = unsafe { sym1(h, c"asinpif") };
    let g_atanpif = unsafe { sym1(h, c"atanpif") };
    let g_atan2pif = unsafe { sym2(h, c"atan2pif") };

    let mut mismatches = 0u64;
    let mut first = String::new();
    let mut note = |cond: bool, msg: String| {
        if !cond {
            mismatches += 1;
            if first.is_empty() {
                first = msg;
            }
        }
    };

    // Domain [-1, 1] for acos/asin.
    for i in 0..=40000 {
        let x = -1.0f32 + 2.0f32 * (i as f32) / 40000.0f32;
        note(
            same_bits(unsafe { fl::acospif(x) }, g_acospif(x)),
            format!("acospif({x})"),
        );
        note(
            same_bits(unsafe { fl::asinpif(x) }, g_asinpif(x)),
            format!("asinpif({x})"),
        );
    }
    // Wide domain for atan.
    for i in 0..=40000 {
        let x = -2000.0f32 + 0.1f32 * (i as f32);
        note(
            same_bits(unsafe { fl::atanpif(x) }, g_atanpif(x)),
            format!("atanpif({x})"),
        );
    }
    // atan2 grid + sign/zero/inf specials.
    for i in -200..=200 {
        for j in -200..=200 {
            let y = i as f32 / 50.0;
            let x = j as f32 / 50.0;
            note(
                same_bits(unsafe { fl::atan2pif(y, x) }, g_atan2pif(y, x)),
                format!("atan2pif({y},{x})"),
            );
        }
    }
    let specials = [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        0.0,
        -0.0,
        1.0,
        -1.0,
        2.0,
        -2.0,
    ];
    for &x in &specials {
        note(
            same_bits(unsafe { fl::acospif(x) }, g_acospif(x)),
            format!("acospif({x})"),
        );
        note(
            same_bits(unsafe { fl::asinpif(x) }, g_asinpif(x)),
            format!("asinpif({x})"),
        );
        note(
            same_bits(unsafe { fl::atanpif(x) }, g_atanpif(x)),
            format!("atanpif({x})"),
        );
        for &y in &specials {
            note(
                same_bits(unsafe { fl::atan2pif(x, y) }, g_atan2pif(x, y)),
                format!("atan2pif({x},{y})"),
            );
        }
    }

    assert_eq!(
        mismatches, 0,
        "inverse pi-trig f32 diverged from glibc; first: {first}"
    );
}
