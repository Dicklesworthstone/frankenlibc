//! Differential gate: nearbyint/nearbyintf must match glibc's value AND its
//! exception-flag state vs host glibc.
//!
//! `nearbyint` rounds to integer in the current rounding mode but, by
//! definition, does NOT raise FE_INEXACT — that suppression is the *only*
//! difference from `rint`. Routing through `libm::rint` gives the right value
//! but raises the spurious FE_INEXACT that nearbyint must hide. This pins both
//! the value and the suppressed-flag contract, in the default rounding mode and
//! under each non-default mode (where the value must still track glibc).
//!
//! glibc reached via dlsym on libm.so.6 to bypass fl's no_mangle interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const ALL: c_int = 0x3D; // INVALID|DIVBYZERO|OVERFLOW|UNDERFLOW|INEXACT
const FE_TONEAREST: c_int = 0x000;
const FE_DOWNWARD: c_int = 0x400;
const FE_UPWARD: c_int = 0x800;
const FE_TOWARDZERO: c_int = 0xc00;

unsafe extern "C" {
    fn dlopen(f: *const c_char, fl: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, s: *const c_char) -> *mut c_void;
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
    fn fesetround(m: c_int) -> c_int;
}

const XS: &[f64] = &[
    0.0,
    -0.0,
    0.5,
    -0.5,
    1.5,
    -1.5,
    2.5,
    -2.5,
    3.5,
    0.1,
    -0.1,
    0.4,
    0.9,
    -0.9,
    100.5,
    -100.5,
    101.5,
    123456.7,
    -123456.7,
    1.0 / 3.0,
    2.0,
    -3.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
];

#[test]
fn nearbyint_value_and_flag_parity() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm failed");
    let g: extern "C" fn(f64) -> f64 =
        unsafe { core::mem::transmute(dlsym(h, c"nearbyint".as_ptr())) };
    let gf: extern "C" fn(f32) -> f32 =
        unsafe { core::mem::transmute(dlsym(h, c"nearbyintf".as_ptr())) };

    let mut div: Vec<String> = Vec::new();

    for &mode in &[FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO] {
        for &x in XS {
            unsafe { fesetround(mode) };
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { fl::nearbyint(x) };
            let ff = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { fesetround(mode) };
            unsafe { feclearexcept(ALL) };
            let gv = g(x);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            let veq = (fv.is_nan() && gv.is_nan()) || fv.to_bits() == gv.to_bits();
            if !veq || ff != gg {
                div.push(format!(
                    "nearbyint({x},m{mode:#x}): fl={:016x}/f{:#x} glibc={:016x}/f{:#x}",
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gg
                ));
            }

            let xf = x as f32;
            unsafe { fesetround(mode) };
            unsafe { feclearexcept(ALL) };
            let fvf = unsafe { fl::nearbyintf(xf) };
            let fff = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { fesetround(mode) };
            unsafe { feclearexcept(ALL) };
            let gvf = gf(xf);
            let ggf = unsafe { fetestexcept(ALL) } & ALL;
            let veqf = (fvf.is_nan() && gvf.is_nan()) || fvf.to_bits() == gvf.to_bits();
            if !veqf || fff != ggf {
                div.push(format!(
                    "nearbyintf({xf},m{mode:#x}): fl={:08x}/f{:#x} glibc={:08x}/f{:#x}",
                    fvf.to_bits(),
                    fff,
                    gvf.to_bits(),
                    ggf
                ));
            }
        }
    }
    unsafe { fesetround(FE_TONEAREST) };

    assert!(
        div.is_empty(),
        "nearbyint value/flag divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
