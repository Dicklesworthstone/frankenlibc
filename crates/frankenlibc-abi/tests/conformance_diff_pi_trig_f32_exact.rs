//! Differential gate: C23 single-precision forward pi-trig (sinpif/cospif/
//! tanpif) must be byte-exact with glibc.
//!
//! glibc computes these in double precision and rounds once. fl previously did
//! the arg-reduction in f32, which lost up to ~28000 ULP near cospi's zeros and
//! tanpi's poles (cosf/division amplifies the f32 `r*pi` rounding error). fl now
//! routes through its f64 sinpi/cospi/tanpi, matching glibc bit-for-bit. glibc
//! is reached via an explicit libm.so.6 handle to bypass fl's no_mangle
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
fn forward_pi_trig_f32_matches_glibc() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm.so.6 failed");
    let g_sinpif = unsafe { sym1(h, c"sinpif") };
    let g_cospif = unsafe { sym1(h, c"cospif") };
    let g_tanpif = unsafe { sym1(h, c"tanpif") };

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

    // Fine sweep including the near-zero / near-pole danger zones.
    for i in 0..=400_000i64 {
        let x = -200.0f32 + 0.001f32 * (i as f32);
        note(
            same_bits(unsafe { fl::sinpif(x) }, g_sinpif(x)),
            format!("sinpif({x})"),
        );
        note(
            same_bits(unsafe { fl::cospif(x) }, g_cospif(x)),
            format!("cospif({x})"),
        );
        note(
            same_bits(unsafe { fl::tanpif(x) }, g_tanpif(x)),
            format!("tanpif({x})"),
        );
    }

    // Large magnitudes + specials.
    let specials = [
        0.0f32,
        -0.0,
        0.5,
        -0.5,
        1.0,
        -1.0,
        2.0,
        16777216.0,
        16777218.0,
        -16777216.0,
        1e30,
        -1e30,
        8388608.5,
        f32::INFINITY,
        f32::NEG_INFINITY,
        f32::NAN,
    ];
    for &x in &specials {
        note(
            same_bits(unsafe { fl::sinpif(x) }, g_sinpif(x)),
            format!("sinpif({x})"),
        );
        note(
            same_bits(unsafe { fl::cospif(x) }, g_cospif(x)),
            format!("cospif({x})"),
        );
        note(
            same_bits(unsafe { fl::tanpif(x) }, g_tanpif(x)),
            format!("tanpif({x})"),
        );
    }

    assert_eq!(
        mism, 0,
        "forward pi-trig f32 diverged from glibc; first: {first}"
    );
}
