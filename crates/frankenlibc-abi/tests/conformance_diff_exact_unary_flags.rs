//! Differential gate: floor/ceil/trunc + fdim/fmax/fmin/copysign/fabs value+flag parity vs glibc.
//! These are exact ops and (per glibc/IEEE) must NOT raise FE_INEXACT.
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
    -0.9,
    100.5,
    123456.7,
    1.0 / 3.0,
    3.0,
    -3.0,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::NAN,
    1e300,
    f64::MIN_POSITIVE,
    2.4999999999999996,
];

fn veq(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn veqf(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

#[test]
fn diff_exact_unary_flags() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    macro_rules! sym {
        ($n:literal, $t:ty) => {
            unsafe { core::mem::transmute::<_, $t>(dlsym(h, $n.as_ptr())) }
        };
    }
    let mut div = Vec::new();

    // Unary f64
    let u64s: &[(
        &str,
        unsafe extern "C" fn(f64) -> f64,
        extern "C" fn(f64) -> f64,
    )] = &[
        (
            "floor",
            fl::floor,
            sym!(c"floor", extern "C" fn(f64) -> f64),
        ),
        ("ceil", fl::ceil, sym!(c"ceil", extern "C" fn(f64) -> f64)),
        (
            "trunc",
            fl::trunc,
            sym!(c"trunc", extern "C" fn(f64) -> f64),
        ),
        ("fabs", fl::fabs, sym!(c"fabs", extern "C" fn(f64) -> f64)),
    ];
    let u32s: &[(
        &str,
        unsafe extern "C" fn(f32) -> f32,
        extern "C" fn(f32) -> f32,
    )] = &[
        (
            "floorf",
            fl::floorf,
            sym!(c"floorf", extern "C" fn(f32) -> f32),
        ),
        (
            "ceilf",
            fl::ceilf,
            sym!(c"ceilf", extern "C" fn(f32) -> f32),
        ),
        (
            "truncf",
            fl::truncf,
            sym!(c"truncf", extern "C" fn(f32) -> f32),
        ),
        (
            "fabsf",
            fl::fabsf,
            sym!(c"fabsf", extern "C" fn(f32) -> f32),
        ),
    ];
    for &x in XS {
        for &(name, ff, gf) in u64s {
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { ff(x) };
            let flf = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { feclearexcept(ALL) };
            let gv = gf(x);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            if !veq(fv, gv) || flf != gg {
                div.push(format!(
                    "{name}({x}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                    fv.to_bits(),
                    flf,
                    gv.to_bits(),
                    gg
                ));
            }
        }
        for &(name, ff, gf) in u32s {
            let xf = x as f32;
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { ff(xf) };
            let flf = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { feclearexcept(ALL) };
            let gv = gf(xf);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            if !veqf(fv, gv) || flf != gg {
                div.push(format!(
                    "{name}({xf}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                    fv.to_bits(),
                    flf,
                    gv.to_bits(),
                    gg
                ));
            }
        }
    }

    // Binary f64: fdim/fmax/fmin/copysign
    let g_fdim = sym!(c"fdim", extern "C" fn(f64, f64) -> f64);
    let g_fmax = sym!(c"fmax", extern "C" fn(f64, f64) -> f64);
    let g_fmin = sym!(c"fmin", extern "C" fn(f64, f64) -> f64);
    let g_copysign = sym!(c"copysign", extern "C" fn(f64, f64) -> f64);
    let pairs = [
        (1.5, 2.5),
        (2.5, 1.5),
        (0.1, 0.1),
        (f64::INFINITY, 1.0),
        (1.0, f64::INFINITY),
        (f64::NAN, 1.0),
        (1.0, f64::NAN),
        (1e300, 1e-300),
        (-0.0, 0.0),
        (0.0, -0.0),
        (-0.0, -0.0),
        (0.0, 0.0),
    ];
    let g_fdimf = sym!(c"fdimf", extern "C" fn(f32, f32) -> f32);
    let g_fmaxf = sym!(c"fmaxf", extern "C" fn(f32, f32) -> f32);
    let g_fminf = sym!(c"fminf", extern "C" fn(f32, f32) -> f32);
    let g_copysignf = sym!(c"copysignf", extern "C" fn(f32, f32) -> f32);
    for (x, y) in pairs {
        let (xf, yf) = (x as f32, y as f32);
        for (name, ff, gf) in [
            (
                "fdimf",
                fl::fdimf as unsafe extern "C" fn(f32, f32) -> f32,
                g_fdimf,
            ),
            ("fmaxf", fl::fmaxf, g_fmaxf),
            ("fminf", fl::fminf, g_fminf),
            ("copysignf", fl::copysignf, g_copysignf),
        ] {
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { ff(xf, yf) };
            let flf = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { feclearexcept(ALL) };
            let gv = gf(xf, yf);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            if !veqf(fv, gv) || flf != gg {
                div.push(format!(
                    "{name}({xf},{yf}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                    fv.to_bits(),
                    flf,
                    gv.to_bits(),
                    gg
                ));
            }
        }
    }
    for (x, y) in pairs {
        for (name, ff, gf) in [
            (
                "fdim",
                fl::fdim as unsafe extern "C" fn(f64, f64) -> f64,
                g_fdim,
            ),
            ("fmax", fl::fmax, g_fmax),
            ("fmin", fl::fmin, g_fmin),
            ("copysign", fl::copysign, g_copysign),
        ] {
            unsafe { feclearexcept(ALL) };
            let fv = unsafe { ff(x, y) };
            let flf = unsafe { fetestexcept(ALL) } & ALL;
            unsafe { feclearexcept(ALL) };
            let gv = gf(x, y);
            let gg = unsafe { fetestexcept(ALL) } & ALL;
            if !veq(fv, gv) || flf != gg {
                div.push(format!(
                    "{name}({x},{y}): fl={:#x}/f{:#x} g={:#x}/f{:#x}",
                    fv.to_bits(),
                    flf,
                    gv.to_bits(),
                    gg
                ));
            }
        }
    }

    assert!(
        div.is_empty(),
        "exact-unary flag divergences ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
