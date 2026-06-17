//! Differential gate: f128 fmax/fmin/fmaxmag/fminmag/fdim/modf/nextafter match
//! glibc bit-for-bit incl. errno (bd-9z5ikz batch 3). Previously broken f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn fmaxf128(x: f128, y: f128) -> f128;
    fn fminf128(x: f128, y: f128) -> f128;
    fn fmaxmagf128(x: f128, y: f128) -> f128;
    fn fminmagf128(x: f128, y: f128) -> f128;
    fn fdimf128(x: f128, y: f128) -> f128;
    fn nextafterf128(x: f128, y: f128) -> f128;
    fn modff128(x: f128, iptr: *mut f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 1.0, -1.0, 2.0, -2.0, 3.0, -3.0, 2.5, -2.5, 0.5, 1e300f128, -1e300f128,
        1e-300f128, 123.456f128, -789.0f128,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                                     // smallest subnormal
        f128::from_bits(1u128 << 112),                          // smallest normal
        f128::from_bits(0x7ffe_u128 << 112),                    // near-largest finite
    ];
    let mut st: u64 = 0xc0ffee_1234_5678;
    for _ in 0..30 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        v.push(f128::from_bits(((hi as u128) << 64) | st as u128));
    }
    v
}

#[test]
fn f128_minmax_dim_nextafter_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();

    // 2-arg, value only (fmax/fmin/fmaxmag/fminmag have no errno).
    macro_rules! ck2 {
        ($name:literal, $g:path, $f:path) => {
            for &x in &vals {
                for &y in &vals {
                    let g = unsafe { $g(x, y) }.to_bits();
                    let f = unsafe { $f(x, y) }.to_bits();
                    if g != f {
                        mism.push(format!("{} x={:#034x} y={:#034x}: glibc={g:#034x} fl={f:#034x}", $name, x.to_bits(), y.to_bits()));
                    }
                }
            }
        };
    }
    ck2!("fmax", fmaxf128, ma::fmaxf128);
    ck2!("fmin", fminf128, ma::fminf128);
    ck2!("fmaxmag", fmaxmagf128, ma::fmaxmagf128);
    ck2!("fminmag", fminmagf128, ma::fminmagf128);

    // fdim + nextafter: value AND errno.
    macro_rules! ck2e {
        ($name:literal, $g:path, $f:path) => {
            for &x in &vals {
                for &y in &vals {
                    unsafe { *el() = 0 };
                    let g = unsafe { $g(x, y) }.to_bits();
                    let ge = unsafe { *el() };
                    unsafe { *el() = 0 };
                    let f = unsafe { $f(x, y) }.to_bits();
                    let fe = unsafe { *el() };
                    if g != f || ge != fe {
                        mism.push(format!("{} x={:#034x} y={:#034x}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})", $name, x.to_bits(), y.to_bits()));
                    }
                }
            }
        };
    }
    ck2e!("fdim", fdimf128, ma::fdimf128);
    ck2e!("nextafter", nextafterf128, ma::nextafterf128);

    // modf: return + integer out-param.
    for &x in &vals {
        let mut gi: f128 = 0.0;
        let mut fi: f128 = 0.0;
        let g = unsafe { modff128(x, &mut gi) }.to_bits();
        let f = unsafe { ma::modff128(x, &mut fi) }.to_bits();
        if g != f || gi.to_bits() != fi.to_bits() {
            mism.push(format!("modf x={:#034x}: glibc=(frac={g:#034x},int={:#034x}) fl=(frac={f:#034x},int={:#034x})", x.to_bits(), gi.to_bits(), fi.to_bits()));
        }
    }

    assert!(mism.is_empty(), "f128 minmax/dim/nextafter diverged ({}):\n{}", mism.len(), mism.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}
