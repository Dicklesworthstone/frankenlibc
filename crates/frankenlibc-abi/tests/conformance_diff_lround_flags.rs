//! Differential gate: the lround/llround/lroundf/llroundf family must match
//! glibc's integer result AND exception-flag state vs host glibc.
//!
//! C F.10.6.5: the l*round functions round to nearest, ties away from zero, and
//! do NOT raise FE_INEXACT. The trap: a `+0.5`-arithmetic round (as
//! `libm::round`/`libm::roundf` use under the hood) spuriously raises FE_INEXACT
//! on every non-integer argument. fl routes these through an integer-domain
//! round kernel so the family stays exception-free, matching glibc.
//!
//! glibc reached via dlsym on libm.so.6 to bypass fl's no_mangle interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_longlong, c_void};

const RTLD_NOW: c_int = 2;
const ALL: c_int = 0x3D; // INVALID|DIVBYZERO|OVERFLOW|UNDERFLOW|INEXACT

unsafe extern "C" {
    fn dlopen(f: *const c_char, fl: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, s: *const c_char) -> *mut c_void;
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
}

// In-range arguments only (the FE_INVALID-on-overflow behavior is a separate
// concern); covers ties (always away from zero), sub-half, and signed values.
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
    -0.4,
    0.9,
    -0.9,
    100.5,
    -100.5,
    101.5,
    123456.7,
    -123456.7,
    1.0 / 3.0,
    2.0,
    -2.0,
    1e6 + 0.5,
];

#[test]
fn lround_family_value_and_flag_parity() {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm failed");
    let mut div: Vec<String> = Vec::new();

    macro_rules! probe {
        ($n:literal, $flf:path, $sym:expr, $ret:ty, $arg:ty) => {{
            let p = unsafe { dlsym(h, $sym.as_ptr()) };
            assert!(!p.is_null(), "missing libm symbol {:?}", $sym);
            let g: extern "C" fn($arg) -> $ret = unsafe { core::mem::transmute(p) };
            for &x in XS {
                let xc = x as $arg;
                unsafe { feclearexcept(ALL) };
                let fv = unsafe { $flf(xc) };
                let ff = unsafe { fetestexcept(ALL) } & ALL;
                unsafe { feclearexcept(ALL) };
                let gv = g(xc);
                let gg = unsafe { fetestexcept(ALL) } & ALL;
                if i128::from(fv) != i128::from(gv) || ff != gg {
                    div.push(format!(
                        "{}({x}): fl={fv}/flags{:#x} glibc={gv}/flags{:#x}",
                        $n, ff, gg
                    ));
                }
            }
        }};
    }

    probe!("lround", fl::lround, c"lround", c_long, f64);
    probe!("llround", fl::llround, c"llround", c_longlong, f64);
    probe!("lroundf", fl::lroundf, c"lroundf", c_long, f32);
    probe!("llroundf", fl::llroundf, c"llroundf", c_longlong, f32);

    assert!(
        div.is_empty(),
        "lround-family value/flag divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
