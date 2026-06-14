//! Differential gate: the exact integral-rounding functions
//! round/roundf/trunc/truncf/floor/floorf/ceil/ceilf must produce bit-exact
//! results AND match glibc's floating-point exception flags vs host glibc.
//!
//! These are IEEE exact integral operations: glibc raises NO FP exceptions for
//! any of them (in particular NOT FE_INEXACT, even on non-integer arguments,
//! and NOT FE_INVALID on infinities). The `round`/`roundf` ties-away-from-zero
//! variants are the trap: a `+0.5`-arithmetic implementation (as `libm::round`
//! uses) spuriously raises FE_INEXACT on every non-integer. fl implements them
//! in the integer (bit) domain to stay exception-free. trunc/floor/ceil
//! delegate to libm's bit-manipulation kernels (already clean) and are pinned
//! here too.
//!
//! glibc reached via dlsym on libm.so.6 to bypass fl's no_mangle interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const ALL: c_int = 0x3D; // INVALID|DIVBYZERO|OVERFLOW|UNDERFLOW|INEXACT

unsafe extern "C" {
    fn dlopen(f: *const c_char, fl: c_int) -> *mut c_void;
    fn dlsym(h: *mut c_void, s: *const c_char) -> *mut c_void;
    fn feclearexcept(e: c_int) -> c_int;
    fn fetestexcept(e: c_int) -> c_int;
}

fn libm() -> *mut c_void {
    let h = unsafe { dlopen(c"libm.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null(), "dlopen libm failed");
    h
}

const XS: &[f64] = &[
    0.0, -0.0, 0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 3.5, 0.1, -0.1, 0.9, -0.9, 0.25, 0.75,
    100.5, -100.5, 101.5, 123456.7, -123456.7, 1e15, 1e16, 1.0 / 3.0, -1.0 / 3.0,
    4503599627370495.5, 9007199254740992.0, f64::MIN_POSITIVE, -f64::MIN_POSITIVE,
    f64::MAX, f64::MIN, f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
];

#[test]
fn round_family_exact_and_flag_parity() {
    let h = libm();
    let g = |n: &std::ffi::CStr| -> extern "C" fn(f64) -> f64 {
        let p = unsafe { dlsym(h, n.as_ptr()) };
        assert!(!p.is_null(), "missing libm symbol {n:?}");
        unsafe { core::mem::transmute(p) }
    };
    let gf = |n: &std::ffi::CStr| -> extern "C" fn(f32) -> f32 {
        let p = unsafe { dlsym(h, n.as_ptr()) };
        assert!(!p.is_null(), "missing libm symbol {n:?}");
        unsafe { core::mem::transmute(p) }
    };

    let mut div: Vec<String> = Vec::new();

    macro_rules! p64 {
        ($n:literal, $f:path, $gn:expr) => {{
            let gff = g($gn);
            for &x in XS {
                unsafe { feclearexcept(ALL) };
                let fv = unsafe { $f(x) };
                let ff = unsafe { fetestexcept(ALL) } & ALL;
                unsafe { feclearexcept(ALL) };
                let gv = gff(x);
                let gg = unsafe { fetestexcept(ALL) } & ALL;
                let veq = (fv.is_nan() && gv.is_nan()) || fv.to_bits() == gv.to_bits();
                if !veq || ff != gg {
                    div.push(format!(
                        "{}({x:.4e}): fl={:016x}/f{:#x} glibc={:016x}/f{:#x}",
                        $n, fv.to_bits(), ff, gv.to_bits(), gg
                    ));
                }
            }
        }};
    }
    macro_rules! p32 {
        ($n:literal, $f:path, $gn:expr) => {{
            let gff = gf($gn);
            for &x in XS {
                let x = x as f32;
                unsafe { feclearexcept(ALL) };
                let fv = unsafe { $f(x) };
                let ff = unsafe { fetestexcept(ALL) } & ALL;
                unsafe { feclearexcept(ALL) };
                let gv = gff(x);
                let gg = unsafe { fetestexcept(ALL) } & ALL;
                let veq = (fv.is_nan() && gv.is_nan()) || fv.to_bits() == gv.to_bits();
                if !veq || ff != gg {
                    div.push(format!(
                        "{}({x:.4e}): fl={:08x}/f{:#x} glibc={:08x}/f{:#x}",
                        $n, fv.to_bits(), ff, gv.to_bits(), gg
                    ));
                }
            }
        }};
    }

    p64!("round", fl::round, c"round");
    p64!("trunc", fl::trunc, c"trunc");
    p64!("floor", fl::floor, c"floor");
    p64!("ceil", fl::ceil, c"ceil");
    p32!("roundf", fl::roundf, c"roundf");
    p32!("truncf", fl::truncf, c"truncf");
    p32!("floorf", fl::floorf, c"floorf");
    p32!("ceilf", fl::ceilf, c"ceilf");

    assert!(
        div.is_empty(),
        "round-family value/flag divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
