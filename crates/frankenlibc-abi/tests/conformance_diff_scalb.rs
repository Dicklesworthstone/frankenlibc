#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

//! Differential conformance gate for the obsolete SVID `scalb`/`scalbf`/`scalbl`.
//!
//! glibc implements `__ieee754_scalb`: a NON-INTEGER binary exponent yields
//! NaN + FE_INVALID, and an infinite exponent uses the `x*fn` / `x/(-fn)` forms.
//! fl previously computed `x * 2.0.powf(exp)`, which returned a bogus *finite*
//! value for non-integer exponents (`scalb(3, 2.5)` -> 16.97 instead of NaN,
//! `scalb(0, 2.5)` -> 0 instead of NaN) and never raised FE_INVALID. This test
//! compares the exact result bits AND the FE_INVALID flag against host glibc.

use frankenlibc_abi::math_abi::scalbl as fl_scalbl;
use frankenlibc_abi::unistd_abi::{scalb as fl_scalb, scalbf as fl_scalbf};

const FE_INVALID: i32 = 0x01;

unsafe extern "C" {
    fn scalb(x: f64, fn_: f64) -> f64;
    fn scalbf(x: f32, fn_: f32) -> f32;
    fn feclearexcept(e: i32) -> i32;
    fn fetestexcept(e: i32) -> i32;
}

/// (result bits, INVALID raised) for a host call.
fn host64(x: f64, e: f64) -> (u64, bool) {
    unsafe {
        feclearexcept(FE_INVALID);
        let r = scalb(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0)
    }
}
fn fl64(x: f64, e: f64) -> (u64, bool) {
    unsafe {
        feclearexcept(FE_INVALID);
        let r = fl_scalb(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0)
    }
}
fn host32(x: f32, e: f32) -> (u32, bool) {
    unsafe {
        feclearexcept(FE_INVALID);
        let r = scalbf(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0)
    }
}
fn fl32(x: f32, e: f32) -> (u32, bool) {
    unsafe {
        feclearexcept(FE_INVALID);
        let r = fl_scalbf(x, e);
        (r.to_bits(), fetestexcept(FE_INVALID) != 0)
    }
}

fn nan_eq_bits(a: u64, b: u64) -> bool {
    // Both NaN (any payload) counts as equal; otherwise exact bit match.
    if (a & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000) && (a & 0x000f_ffff_ffff_ffff != 0)
        && (b & 0x7ff0_0000_0000_0000 == 0x7ff0_0000_0000_0000) && (b & 0x000f_ffff_ffff_ffff != 0)
    {
        return true;
    }
    a == b
}
fn nan_eq_bits32(a: u32, b: u32) -> bool {
    if (a & 0x7f80_0000 == 0x7f80_0000) && (a & 0x007f_ffff != 0)
        && (b & 0x7f80_0000 == 0x7f80_0000) && (b & 0x007f_ffff != 0)
    {
        return true;
    }
    a == b
}

#[test]
fn scalb_matches_glibc() {
    let xs = [
        0.0f64, -0.0, 1.0, -1.0, 3.0, -5.0, 1.5, 7.0, 2.0,
        1e300, 1e-300, f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
        f64::MIN_POSITIVE, 0.9, 123.456,
    ];
    let es = [
        0.0f64, 1.0, 2.0, 3.0, -2.0, -4.0, 1023.0, 1024.0, -1074.0, -1075.0,
        2.5, 0.5, -2.5, 0.9, -0.1, 70000.0, -70000.0, 65000.0, 65001.0,
        f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
    ];

    let mut div: Vec<String> = Vec::new();
    for &x in &xs {
        for &e in &es {
            // f64 / scalb
            let (hb, hi) = host64(x, e);
            let (fb, fi) = fl64(x, e);
            if !nan_eq_bits(hb, fb) || hi != fi {
                div.push(format!(
                    "scalb({x}, {e}): fl bits={fb:016x} inv={fi}, glibc bits={hb:016x} inv={hi}"
                ));
            }
            // long-double scalbl shares the f64 surface in fl; glibc scalb is the oracle.
            unsafe {
                feclearexcept(FE_INVALID);
                let r = fl_scalbl(x, e);
                let (lb, li) = (r.to_bits(), fetestexcept(FE_INVALID) != 0);
                if !nan_eq_bits(hb, lb) || hi != li {
                    div.push(format!(
                        "scalbl({x}, {e}): fl bits={lb:016x} inv={li}, glibc bits={hb:016x} inv={hi}"
                    ));
                }
            }
            // f32 / scalbf
            let (xf, ef) = (x as f32, e as f32);
            let (hb32, hi32) = host32(xf, ef);
            let (fb32, fi32) = fl32(xf, ef);
            if !nan_eq_bits32(hb32, fb32) || hi32 != fi32 {
                div.push(format!(
                    "scalbf({xf}, {ef}): fl bits={fb32:08x} inv={fi32}, glibc bits={hb32:08x} inv={hi32}"
                ));
            }
        }
    }
    assert!(
        div.is_empty(),
        "scalb/scalbf/scalbl divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}
