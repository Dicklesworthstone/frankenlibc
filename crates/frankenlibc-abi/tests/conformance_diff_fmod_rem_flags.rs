//! Differential gate: fmod/remainder/remquo/drem family FP-exception-flag parity vs glibc.
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

const PAIRS: &[(f64, f64)] = &[
    (5.0, 3.0),
    (5.0, 0.0),
    (-5.0, 0.0),
    (0.0, 0.0),
    (f64::INFINITY, 3.0),
    (f64::NEG_INFINITY, 3.0),
    (f64::INFINITY, f64::INFINITY),
    (f64::INFINITY, 0.0),
    (f64::NAN, 3.0),
    (3.0, f64::NAN),
    (f64::NAN, 0.0),
    (1.0, f64::INFINITY),
    (1e300, 1e-300),
];

fn veq(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn veqf(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

#[test]
fn diff_fmod_rem_flags() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    macro_rules! sym2 {
        ($n:literal, $t:ty) => {
            unsafe { core::mem::transmute::<_, $t>(dlsym(h, $n.as_ptr())) }
        };
    }
    let g_fmod = sym2!(c"fmod", extern "C" fn(f64, f64) -> f64);
    let g_fmodf = sym2!(c"fmodf", extern "C" fn(f32, f32) -> f32);
    let g_rem = sym2!(c"remainder", extern "C" fn(f64, f64) -> f64);
    let g_remf = sym2!(c"remainderf", extern "C" fn(f32, f32) -> f32);
    let g_drem = sym2!(c"drem", extern "C" fn(f64, f64) -> f64);
    let g_remquo = sym2!(c"remquo", extern "C" fn(f64, f64, *mut c_int) -> f64);
    let g_remquof = sym2!(c"remquof", extern "C" fn(f32, f32, *mut c_int) -> f32);

    let mut div = Vec::new();
    macro_rules! probe64 {
        ($name:expr, $flf:expr, $gf:expr, $x:expr, $y:expr) => {{
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { $flf($x, $y) };
            let ff = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { feclearexcept(ALL) };
            let gv = $gf($x, $y);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            if !veq(fv, gv) || ff != gg {
                div.push(format!(
                    "{}({},{}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                    $name,
                    $x,
                    $y,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gg
                ));
            }
        }};
    }
    macro_rules! probe32 {
        ($name:expr, $flf:expr, $gf:expr, $x:expr, $y:expr) => {{
            let (xf, yf) = ($x as f32, $y as f32);
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { $flf(xf, yf) };
            let ff = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { feclearexcept(ALL) };
            let gv = $gf(xf, yf);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            if !veqf(fv, gv) || ff != gg {
                div.push(format!(
                    "{}({},{}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                    $name,
                    xf,
                    yf,
                    fv.to_bits(),
                    ff,
                    gv.to_bits(),
                    gg
                ));
            }
        }};
    }

    for &(x, y) in PAIRS {
        probe64!("fmod", fl::fmod, g_fmod, x, y);
        probe64!("remainder", fl::remainder, g_rem, x, y);
        probe64!("drem", fl::drem, g_drem, x, y);
        probe32!("fmodf", fl::fmodf, g_fmodf, x, y);
        probe32!("remainderf", fl::remainderf, g_remf, x, y);
        // remquo: compare value + flags (ignore quo sign bits beyond low 3)
        unsafe { feclearexcept(ALL) };
        let (mut fq, mut gq) = (0i32, 0i32);
        let fv = unsafe { fl::remquo(x, y, &mut fq) };
        let ff = unsafe { fetestexcept(ALL) } & ALL;
        unsafe { feclearexcept(ALL) };
        let gv = g_remquo(x, y, &mut gq);
        let gg = unsafe { fetestexcept(ALL) } & ALL;
        if !veq(fv, gv) || ff != gg {
            div.push(format!(
                "remquo({x},{y}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                fv.to_bits(),
                ff,
                gv.to_bits(),
                gg
            ));
        }
        let (xf, yf) = (x as f32, y as f32);
        unsafe { feclearexcept(ALL) };
        let (mut fqf, mut gqf) = (0i32, 0i32);
        let fvf = unsafe { fl::remquof(xf, yf, &mut fqf) };
        let fff = unsafe { fetestexcept(ALL) } & ALL;
        unsafe { feclearexcept(ALL) };
        let gvf = g_remquof(xf, yf, &mut gqf);
        let ggf = unsafe { fetestexcept(ALL) } & ALL;
        if !veqf(fvf, gvf) || fff != ggf {
            div.push(format!(
                "remquof({xf},{yf}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                fvf.to_bits(),
                fff,
                gvf.to_bits(),
                ggf
            ));
        }
    }
    assert!(
        div.is_empty(),
        "fmod/rem flag divergences ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
