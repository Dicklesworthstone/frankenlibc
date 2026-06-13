#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc math oracle
//! Special-value parity for the multi-output / two-result math functions
//! (frexp, modf, remquo, lgamma_r, sincos, ldexp) vs host glibc. These have a
//! richer surface than plain unary functions — a second output and/or a sign —
//! that random/ULP sweeps miss. fl returns tuples; glibc uses out-pointers.
//!
//! `nexttoward*` are intentionally NOT exercised here: their C ABI second
//! argument is `long double`, which cannot be passed from Rust over the x86-64
//! SysV ABI (fl handles it via a dedicated `nexttoward*_long_double_bits` path,
//! out of scope for this differential).

use frankenlibc_core::math as fl;
use std::ffi::c_int;

unsafe extern "C" {
    fn frexp(x: f64, e: *mut c_int) -> f64;
    fn modf(x: f64, i: *mut f64) -> f64;
    fn remquo(x: f64, y: f64, q: *mut c_int) -> f64;
    fn lgamma_r(x: f64, s: *mut c_int) -> f64;
    fn sincos(x: f64, s: *mut f64, c: *mut f64);
    fn ldexp(x: f64, e: c_int) -> f64;
    fn frexpf(x: f32, e: *mut c_int) -> f32;
    fn modff(x: f32, i: *mut f32) -> f32;
}

fn key(x: f64) -> i64 { let b = x.to_bits() as i64; if b < 0 { i64::MIN - b } else { b } }
fn ulp(a: f64, b: f64) -> u64 { (key(a).wrapping_sub(key(b))).unsigned_abs() }
fn exact(a: f64, b: f64) -> bool { (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits() }
fn beqf(a: f32, b: f32) -> bool { (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits() }
fn approx(a: f64, b: f64, t: u64) -> bool {
    if a.is_nan() && b.is_nan() { return true; }
    if a.is_nan() != b.is_nan() { return false; }
    if a.is_infinite() || b.is_infinite() || a == 0.0 || b == 0.0 { return a.to_bits() == b.to_bits(); }
    ulp(a, b) <= t
}

const SP: &[f64] = &[
    0.0, -0.0, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.0, -3.0, 7.0, -7.0,
    f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -f64::NAN,
    f64::MIN_POSITIVE, -f64::MIN_POSITIVE, f64::MAX, f64::MIN, 5e-324, -5e-324,
    1.5, -1.5, 100.0, -100.0, 0.1, -0.1, 2.5, -2.5, 123.875, -123.875,
];

#[test]
fn math_multi_output_parity_vs_glibc() {
    let mut div = Vec::new();

    // frexp: mantissa (bit-exact) + exponent (for finite inputs).
    for &x in SP {
        let (fm, fe) = fl::frexp(x);
        let mut ge: c_int = 0;
        let gm = unsafe { frexp(x, &mut ge) };
        if !exact(fm, gm) || (x.is_finite() && fe != ge) {
            div.push(format!("frexp({x:e}): fl=({fm:?},{fe}) glibc=({gm:?},{ge})"));
        }
    }
    // modf: fractional + integral parts, both bit-exact (incl. signed zero, inf).
    for &x in SP {
        let (ff, fi) = fl::modf(x);
        let mut gi: f64 = 0.0;
        let gf = unsafe { modf(x, &mut gi) };
        if !exact(ff, gf) || !exact(fi, gi) {
            div.push(format!("modf({x:e}): fl=(frac {ff:?}, int {fi:?}) glibc=(frac {gf:?}, int {gi:?})"));
        }
    }
    // remquo: remainder bit-exact; quotient agrees on the C99-mandated low 3 bits.
    for &x in SP { for &y in SP {
        let (fr, fq) = fl::remquo(x, y);
        let mut gq: c_int = 0;
        let gr = unsafe { remquo(x, y, &mut gq) };
        if !exact(fr, gr) {
            div.push(format!("remquo({x:e},{y:e}) rem: fl={fr:?} glibc={gr:?}"));
        }
        if fr.is_finite() && gr.is_finite() && (fq & 7) != (gq & 7) {
            div.push(format!("remquo({x:e},{y:e}) quo low3: fl={} glibc={}", fq & 7, gq & 7));
        }
    }}
    // lgamma_r: value within tolerance + sign of gamma for finite results.
    for &x in SP {
        let (fv, fs) = fl::lgamma_r(x);
        let mut gs: c_int = 0;
        let gv = unsafe { lgamma_r(x, &mut gs) };
        if !approx(fv, gv, 8) { div.push(format!("lgamma_r({x:e}) val: fl={fv:?} glibc={gv:?}")); }
        if fv.is_finite() && gv.is_finite() && fs != gs {
            div.push(format!("lgamma_r({x:e}) sign: fl={fs} glibc={gs}"));
        }
    }
    // sincos: both outputs within tolerance (special-value boundaries exact).
    for &x in SP {
        let (fsin, fcos) = fl::sincos(x);
        let mut gsin: f64 = 0.0; let mut gcos: f64 = 0.0;
        unsafe { sincos(x, &mut gsin, &mut gcos) };
        if !approx(fsin, gsin, 2) { div.push(format!("sincos({x:e}) sin: fl={fsin:?} glibc={gsin:?}")); }
        if !approx(fcos, gcos, 2) { div.push(format!("sincos({x:e}) cos: fl={fcos:?} glibc={gcos:?}")); }
    }
    // ldexp edges (bit-exact across the over/underflow range).
    for &x in SP {
        for e in [0, 1, -1, 1024, -1074, 2000, -2000] {
            let f = fl::ldexp(x, e); let g = unsafe { ldexp(x, e) };
            if !exact(f, g) { div.push(format!("ldexp({x:e},{e}): fl={f:?} glibc={g:?}")); }
        }
    }
    // f32 frexpf / modff.
    for &x in SP {
        let xf = x as f32;
        let (fm, fe) = fl::frexpf(xf);
        let mut ge: c_int = 0;
        let gm = unsafe { frexpf(xf, &mut ge) };
        if !beqf(fm, gm) || (xf.is_finite() && fe != ge) {
            div.push(format!("frexpf({xf:e}): fl=({fm:?},{fe}) glibc=({gm:?},{ge})"));
        }
        let (ff, fi) = fl::modff(xf);
        let mut gi: f32 = 0.0;
        let gf = unsafe { modff(xf, &mut gi) };
        if !beqf(ff, gf) || !beqf(fi, gi) {
            div.push(format!("modff({xf:e}): fl=(frac {ff:?}, int {fi:?}) glibc=(frac {gf:?}, int {gi:?})"));
        }
    }

    assert!(div.is_empty(), "multi-output math divergences vs glibc:\n  {}", div.join("\n  "));
}
