//! Differential gate for the C23 `roundeven` family (round to nearest integer,
//! ties to EVEN) vs host glibc.
//!
//! roundeven differs from `round` (ties away from zero): roundeven(2.5)=2,
//! roundeven(3.5)=4, roundeven(0.5)=0, roundeven(-0.5)=-0. The result is an
//! integer-valued float, so it must be BIT-EXACT vs glibc (signed zero
//! matters). Per IEEE-754, roundToIntegralTiesToEven raises NO floating-point
//! exceptions (unlike rint, it never signals INEXACT), so the hardware flag
//! state must also match (both clear).
//!
//! fl is called via Rust paths; glibc is reached through `dlsym` on libm.so.6
//! so the fn pointer bypasses fl's no_mangle interposition of the same symbol.
//! This surface had ZERO test coverage — the ties-to-even logic in
//! roundeven_impl is hand-rolled (not a libm delegation), so a future refactor
//! to a different rounding primitive could silently break non-default ties
//! behavior while passing every other gate. This pins it.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const HARD: c_int = 0x1D; // INVALID|DIVBYZERO|OVERFLOW|UNDERFLOW
const INEXACT: c_int = 0x20;
const ALL_EXC: c_int = HARD | INEXACT;

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

// roundeven is exact: bit-identical to glibc, including signed zero and NaN
// payload preservation (NaN -> same NaN, but we compare is_nan to tolerate
// quiet-bit normalization differences which are permitted).
fn exact_ok_f64(a: f64, b: f64) -> bool {
    if b.is_nan() {
        return a.is_nan();
    }
    a.to_bits() == b.to_bits()
}
fn exact_ok_f32(a: f32, b: f32) -> bool {
    if b.is_nan() {
        return a.is_nan();
    }
    a.to_bits() == b.to_bits()
}

const XS: &[f64] = &[
    0.0, -0.0, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 3.5, -3.5, 4.5, -4.5,
    0.25, 0.75, -0.25, -0.75, 1.0, -1.0, 2.0, 2.4999999999999996, 2.5000000000000004,
    0.49999999999999994, 1.4999999999999998, 100.5, 101.5, -100.5, -101.5,
    1e15, 1e16, 1e15 + 0.5, 4503599627370495.5, 9007199254740992.0,
    1.0 / 3.0, -1.0 / 3.0, 123456.5, 123457.5, 0.1, -0.1, 0.9, -0.9,
    f64::MIN_POSITIVE, -f64::MIN_POSITIVE, f64::MAX, f64::MIN,
    f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
];
const XSF: &[f32] = &[
    0.0, -0.0, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 3.5, -3.5, 4.5, -4.5,
    0.25, 0.75, -0.25, 1.0, -1.0, 2.0, 100.5, 101.5, -100.5, -101.5,
    8388607.5, 8388608.0, 0.1, -0.1, 0.9, 0.49999997, 2.4999998,
    f32::MIN_POSITIVE, f32::MAX, f32::MIN, f32::INFINITY, f32::NEG_INFINITY, f32::NAN,
];

#[test]
fn roundeven_matches_glibc() {
    let h = libm();
    // base + aliases that exist in glibc with f64/f32 ABI.
    // NOTE: roundevenl is intentionally NOT compared — fl declares it
    // (f64)->f64 (its documented long-double-as-double convention), so calling
    // glibc's true 80-bit `roundevenl` through an f64 ABI would be a calling-
    // convention mismatch, not a meaningful value comparison.
    let g_roundeven: extern "C" fn(f64) -> f64 =
        unsafe { core::mem::transmute(sym(h, c"roundeven")) };
    let g_roundevenf: extern "C" fn(f32) -> f32 =
        unsafe { core::mem::transmute(sym(h, c"roundevenf")) };

    let mut div: Vec<String> = Vec::new();

    macro_rules! cmp64 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let x: f64 = $x;
            unsafe { feclearexcept(ALL_EXC) };
            let fv = unsafe { $flf(x) };
            let ff = unsafe { fetestexcept(ALL_EXC) } & ALL_EXC;
            unsafe { feclearexcept(ALL_EXC) };
            let gv = $gf(x);
            let gf2 = unsafe { fetestexcept(ALL_EXC) } & ALL_EXC;
            if !exact_ok_f64(fv, gv) || ff != gf2 {
                div.push(format!(
                    "{}({:.17e}): fl={:016x}/flags{:#x} glibc={:016x}/flags{:#x}",
                    $name, x, fv.to_bits(), ff, gv.to_bits(), gf2
                ));
            }
        }};
    }
    macro_rules! cmp32 {
        ($name:literal, $flf:path, $gf:expr, $x:expr) => {{
            let x: f32 = $x;
            unsafe { feclearexcept(ALL_EXC) };
            let fv = unsafe { $flf(x) };
            let ff = unsafe { fetestexcept(ALL_EXC) } & ALL_EXC;
            unsafe { feclearexcept(ALL_EXC) };
            let gv = $gf(x);
            let gf2 = unsafe { fetestexcept(ALL_EXC) } & ALL_EXC;
            if !exact_ok_f32(fv, gv) || ff != gf2 {
                div.push(format!(
                    "{}({:.9e}): fl={:08x}/flags{:#x} glibc={:08x}/flags{:#x}",
                    $name, x, fv.to_bits(), ff, gv.to_bits(), gf2
                ));
            }
        }};
    }

    for &x in XS {
        cmp64!("roundeven", fl::roundeven, g_roundeven, x);
        // f64-ABI alias must route to the identical result.
        cmp64!("roundevenf64", fl::roundevenf64, g_roundeven, x);
    }
    for &x in XSF {
        cmp32!("roundevenf", fl::roundevenf, g_roundevenf, x);
        cmp32!("roundevenf32", fl::roundevenf32, g_roundevenf, x);
    }

    assert!(
        div.is_empty(),
        "roundeven divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
