//! Differential gate: C23 single-precision log2p1f/log10p1f/exp2m1f/exp10m1f
//! must be byte-exact with glibc.
//!
//! glibc computes these in double precision and rounds once. fl previously did
//! the work in f32 (e.g. log1pf(x)/LN_2_f32, or an expm1f/exp2f split), losing
//! 2-3 ULP. fl now routes through its f64 versions, matching glibc bit-for-bit.
//! glibc is reached via an explicit libm.so.6 handle to bypass fl's no_mangle
//! interposition.
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
unsafe fn sym1(h: *mut c_void, n: &std::ffi::CStr) -> F1 {
    let p = unsafe { dlsym(h, n.as_ptr()) };
    assert!(!p.is_null(), "dlsym {n:?} failed");
    unsafe { std::mem::transmute::<*mut c_void, F1>(p) }
}
fn same_bits(a: f32, b: f32) -> bool {
    a.to_bits() == b.to_bits() || (a.is_nan() && b.is_nan())
}

#[test]
fn c23_logexp_f32_matches_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm.so.6 failed");
    let g_log2p1f = unsafe { sym1(h, c"log2p1f") };
    let g_log10p1f = unsafe { sym1(h, c"log10p1f") };
    let g_exp2m1f = unsafe { sym1(h, c"exp2m1f") };
    let g_exp10m1f = unsafe { sym1(h, c"exp10m1f") };

    let mut mism = 0u64;
    let mut first = String::new();
    let mut note = |ok: bool, m: String| {
        if !ok {
            mism += 1;
            if first.is_empty() {
                first = m;
            }
        }
    };

    // log*p1f domain is (-1, +inf); sweep around the -1 pole and out.
    for i in 0..=400_000i64 {
        let x = -0.999f32 + 3.0f32 * (i as f32) / 400_000.0f32;
        note(same_bits(unsafe { fl::log2p1f(x) }, g_log2p1f(x)), format!("log2p1f({x})"));
        note(same_bits(unsafe { fl::log10p1f(x) }, g_log10p1f(x)), format!("log10p1f({x})"));
    }
    // exp*m1f across underflow→overflow.
    for i in 0..=400_000i64 {
        let x = -160.0f32 + 320.0f32 * (i as f32) / 400_000.0f32;
        note(same_bits(unsafe { fl::exp2m1f(x) }, g_exp2m1f(x)), format!("exp2m1f({x})"));
        note(same_bits(unsafe { fl::exp10m1f(x) }, g_exp10m1f(x)), format!("exp10m1f({x})"));
    }

    let specials = [
        0.0f32, -0.0, 1.0, -1.0, -0.5, 0.5, 2.0, 1e30, -1e30, 7.0, 38.0, 39.0, 128.0, -150.0,
        f32::INFINITY, f32::NEG_INFINITY, f32::NAN,
    ];
    for &x in &specials {
        note(same_bits(unsafe { fl::log2p1f(x) }, g_log2p1f(x)), format!("log2p1f({x})"));
        note(same_bits(unsafe { fl::log10p1f(x) }, g_log10p1f(x)), format!("log10p1f({x})"));
        note(same_bits(unsafe { fl::exp2m1f(x) }, g_exp2m1f(x)), format!("exp2m1f({x})"));
        note(same_bits(unsafe { fl::exp10m1f(x) }, g_exp10m1f(x)), format!("exp10m1f({x})"));
    }

    assert_eq!(mism, 0, "C23 log/exp f32 diverged from glibc; first: {first}");
}
