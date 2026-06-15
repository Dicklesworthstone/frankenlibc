//! Differential gate: significand/significandf (and modf/modff regression guard)
//! FP-exception-flag parity vs host glibc.
//!
//! glibc significand(x) = scalbn(x, -ilogb(x)); ilogb(0/inf/NaN) raises
//! FE_INVALID, which propagates. fl previously returned the correct VALUE
//! (0/inf/nan) for those three special inputs but raised no flag (bd-2g7oyh.405).
//! modf/modff must raise NO FP exceptions on any input. Normal finite-nonzero
//! significand values match glibc exactly (value + flags).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const ALL: c_int = 0x3D;

unsafe extern "C" {
    fn dlopen(f: *const c_char, fl: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, s: *const c_char) -> *mut c_void;
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
}

const XS: &[f64] = &[
    0.0,
    -0.0,
    0.5,
    -0.5,
    1.5,
    2.5,
    0.1,
    -0.1,
    0.9,
    100.5,
    123456.7,
    1.0 / 3.0,
    3.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1e300,
    f64::MIN_POSITIVE,
];

#[test]
fn diff_significand_modf_flags() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm");
    let g_sig: extern "C" fn(f64) -> f64 =
        unsafe { core::mem::transmute(dlsym(h, c"significand".as_ptr())) };
    let g_sigf: extern "C" fn(f32) -> f32 =
        unsafe { core::mem::transmute(dlsym(h, c"significandf".as_ptr())) };
    let g_modf: extern "C" fn(f64, *mut f64) -> f64 =
        unsafe { core::mem::transmute(dlsym(h, c"modf".as_ptr())) };
    let g_modff: extern "C" fn(f32, *mut f32) -> f32 =
        unsafe { core::mem::transmute(dlsym(h, c"modff".as_ptr())) };

    let veq = |a: f64, b: f64| (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits();
    let veqf = |a: f32, b: f32| (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits();

    let mut div = Vec::new();
    for &x in XS {
        // significand (f64)
        unsafe { feclearexcept(ALL) };
        let fs = unsafe { fl::significand(x) };
        let fsf = unsafe { fetestexcept(ALL) } & ALL;
        unsafe { feclearexcept(ALL) };
        let gs = g_sig(x);
        let gsf = unsafe { fetestexcept(ALL) } & ALL;
        if !veq(fs, gs) || fsf != gsf {
            div.push(format!(
                "significand({x}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                fs.to_bits(),
                fsf,
                gs.to_bits(),
                gsf
            ));
        }

        // significandf (f32)
        let xf = x as f32;
        unsafe { feclearexcept(ALL) };
        let fsm = unsafe { fl::significandf(xf) };
        let fsmf = unsafe { fetestexcept(ALL) } & ALL;
        unsafe { feclearexcept(ALL) };
        let gsm = g_sigf(xf);
        let gsmf = unsafe { fetestexcept(ALL) } & ALL;
        if !veqf(fsm, gsm) || fsmf != gsmf {
            div.push(format!(
                "significandf({xf}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                fsm.to_bits(),
                fsmf,
                gsm.to_bits(),
                gsmf
            ));
        }

        // modf (f64) — regression guard: NO flags
        let (mut fip, mut gip) = (0.0f64, 0.0f64);
        unsafe { feclearexcept(ALL) };
        let fmv = unsafe { fl::modf(x, &mut fip) };
        let fmf = unsafe { fetestexcept(ALL) } & ALL;
        unsafe { feclearexcept(ALL) };
        let gmv = g_modf(x, &mut gip);
        let gmf = unsafe { fetestexcept(ALL) } & ALL;
        if !veq(fmv, gmv) || !veq(fip, gip) || fmf != gmf {
            div.push(format!(
                "modf({x}): fl={:#x},ip={:#x}/f{:#x} g={:#x},ip={:#x}/f{:#x}",
                fmv.to_bits(),
                fip.to_bits(),
                fmf,
                gmv.to_bits(),
                gip.to_bits(),
                gmf
            ));
        }

        // modff (f32) — regression guard: NO flags
        let (mut fipf, mut gipf) = (0.0f32, 0.0f32);
        unsafe { feclearexcept(ALL) };
        let fmvf = unsafe { fl::modff(xf, &mut fipf) };
        let fmff = unsafe { fetestexcept(ALL) } & ALL;
        unsafe { feclearexcept(ALL) };
        let gmvf = g_modff(xf, &mut gipf);
        let gmff = unsafe { fetestexcept(ALL) } & ALL;
        if !veqf(fmvf, gmvf) || !veqf(fipf, gipf) || fmff != gmff {
            div.push(format!(
                "modff({xf}): fl={:#x},ip={:#x}/f{:#x} g={:#x},ip={:#x}/f{:#x}",
                fmvf.to_bits(),
                fipf.to_bits(),
                fmff,
                gmvf.to_bits(),
                gipf.to_bits(),
                gmff
            ));
        }
    }
    assert!(
        div.is_empty(),
        "significand/modf flag divergences ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
