#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc Bessel oracle
//! jn/yn (+ f32 jnf/ynf) arbitrary-order Bessel parity vs host glibc, focused on
//! the signed-zero-at-infinity convention. libm returns +0 for several
//! odd-order cases at +-inf where glibc returns -0 (e.g. jn(-1,+inf),
//! jn(1,-inf), yn(-1,+inf)); fl routes orders 0/+-1 through j0/j1/y0/y1 + the
//! identity {J,Y}_{-n} = (-1)^n {J,Y}_n to match. |n| >= 2 stays on libm
//! (already matches glibc). Finite-x values are checked within tolerance.

use frankenlibc_core::math as fl;
use std::ffi::c_int;
unsafe extern "C" {
    fn jn(n: c_int, x: f64) -> f64;
    fn yn(n: c_int, x: f64) -> f64;
    fn jnf(n: c_int, x: f32) -> f32;
    fn ynf(n: c_int, x: f32) -> f32;
}
fn key(x: f64) -> i64 { let b = x.to_bits() as i64; if b<0 { i64::MIN-b } else { b } }
fn ulp(a: f64, b: f64) -> u64 { (key(a).wrapping_sub(key(b))).unsigned_abs() }
fn approx(a: f64, b: f64, t: u64) -> bool {
    if a.is_nan() && b.is_nan() { return true; }
    if a.is_nan() != b.is_nan() { return false; }
    if a.is_infinite() || b.is_infinite() || a==0.0 || b==0.0 { return a.to_bits()==b.to_bits(); }
    ulp(a,b) <= t
}
fn keyf(x: f32) -> i32 { let b = x.to_bits() as i32; if b<0 { i32::MIN-b } else { b } }
fn approxf(a: f32, b: f32, t: u32) -> bool {
    if a.is_nan() && b.is_nan() { return true; }
    if a.is_nan() != b.is_nan() { return false; }
    if a.is_infinite() || b.is_infinite() || a==0.0 || b==0.0 { return a.to_bits()==b.to_bits(); }
    (keyf(a).wrapping_sub(keyf(b))).unsigned_abs() <= t
}
const SP: &[f64] = &[0.0,-0.0,1.0,-1.0,2.0,-2.0,0.5,-0.5,3.5,-3.5,10.0,-10.0,
    f64::INFINITY,f64::NEG_INFINITY,f64::NAN,-f64::NAN,
    f64::MIN_POSITIVE,-f64::MIN_POSITIVE,f64::MAX,5e-324,1e-300,100.0,-100.0,0.1];

#[test]
fn bessel_jn_yn_parity_vs_glibc() {
    let mut div = Vec::new();
    for n in [-3i32,-2,-1,0,1,2,3,5,10,-5] {
        for &x in SP {
            let f = fl::jn(n,x); let g = unsafe { jn(n,x) };
            if !approx(f,g,16) { div.push(format!("jn({n},{x:e}): fl={f:?}({:#018x}) glibc={g:?}({:#018x})", f.to_bits(), g.to_bits())); }
            let fy = fl::yn(n,x); let gy = unsafe { yn(n,x) };
            if !approx(fy,gy,16) { div.push(format!("yn({n},{x:e}): fl={fy:?}({:#018x}) glibc={gy:?}({:#018x})", fy.to_bits(), gy.to_bits())); }
            let xf = x as f32;
            let ff = fl::jnf(n,xf); let gf = unsafe { jnf(n,xf) };
            if !approxf(ff,gf,16) { div.push(format!("jnf({n},{xf:e}): fl={ff:?}({:#010x}) glibc={gf:?}({:#010x})", ff.to_bits(), gf.to_bits())); }
            let fyf = fl::ynf(n,xf); let gyf = unsafe { ynf(n,xf) };
            if !approxf(fyf,gyf,16) { div.push(format!("ynf({n},{xf:e}): fl={fyf:?}({:#010x}) glibc={gyf:?}({:#010x})", fyf.to_bits(), gyf.to_bits())); }
        }
    }
    assert!(div.is_empty(), "Bessel jn/yn divergences vs glibc:\n  {}", div.join("\n  "));
}
