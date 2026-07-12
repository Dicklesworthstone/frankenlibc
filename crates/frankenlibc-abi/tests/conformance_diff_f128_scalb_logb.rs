//! Differential gate: f128 scalbn/ldexp/scalbln + logb/ilogb/llogb match glibc
//! bit-for-bit incl. errno (bd-9z5ikz batch 5). Previously broken f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_int, c_long};

unsafe extern "C" {
    fn scalbnf128(x: f128, n: c_int) -> f128;
    fn ldexpf128(x: f128, n: c_int) -> f128;
    fn scalblnf128(x: f128, n: c_long) -> f128;
    fn logbf128(x: f128) -> f128;
    fn ilogbf128(x: f128) -> c_int;
    fn llogbf128(x: f128) -> c_long;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        2.0,
        -2.0,
        3.0,
        0.5,
        -0.5,
        123.456f128,
        1e300f128,
        -1e-300f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(0x1_0000),           // subnormal
        f128::from_bits(1u128 << 112),       // smallest normal
        f128::from_bits(0x7ffe_u128 << 112), // near-largest finite
    ];
    let mut st: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..30 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.push(f128::from_bits(((hi as u128) << 64) | st as u128));
    }
    v
}

#[test]
fn f128_scalb_logb_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();

    // scalbn / ldexp over a grid of exponents incl. overflow/underflow/subnormal.
    let ns: &[c_int] = &[
        0, 1, -1, 2, -2, 16, -16, 113, -113, 16383, 16384, -16382, -16383, -16494, -16495, 100000,
        -100000, 50, -50, 200, -200,
    ];
    for &x in &vals {
        for &n in ns {
            for (name, gf, ff) in [
                (
                    "scalbn",
                    scalbnf128 as unsafe extern "C" fn(f128, c_int) -> f128,
                    ma::scalbnf128 as unsafe extern "C" fn(f128, c_int) -> f128,
                ),
                ("ldexp", ldexpf128, ma::ldexpf128),
            ] {
                unsafe { *el() = 0 };
                let g = unsafe { gf(x, n) }.to_bits();
                let ge = unsafe { *el() };
                unsafe { *el() = 0 };
                let f = unsafe { ff(x, n) }.to_bits();
                let fe = unsafe { *el() };
                if g != f || ge != fe {
                    mism.push(format!(
                        "{name} x={:#034x} n={n}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                        x.to_bits()
                    ));
                }
            }
        }
        // scalbln (c_long n)
        for &n in &[0i64, -16494, 100000, -100000] {
            unsafe { *el() = 0 };
            let g = unsafe { scalblnf128(x, n) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::scalblnf128(x, n) }.to_bits();
            let fe = unsafe { *el() };
            if g != f || ge != fe {
                mism.push(format!(
                    "scalbln x={:#034x} n={n}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                    x.to_bits()
                ));
            }
        }
    }

    // logb (f128 result + errno)
    for &x in &vals {
        unsafe { *el() = 0 };
        let g = unsafe { logbf128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::logbf128(x) }.to_bits();
        let fe = unsafe { *el() };
        if g != f || ge != fe {
            mism.push(format!(
                "logb x={:#034x}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }

    // ilogb / llogb (int result + errno)
    for &x in &vals {
        unsafe { *el() = 0 };
        let g = unsafe { ilogbf128(x) };
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::ilogbf128(x) };
        let fe = unsafe { *el() };
        if g != f || ge != fe {
            mism.push(format!(
                "ilogb x={:#034x}: glibc=({g},e={ge}) fl=({f},e={fe})",
                x.to_bits()
            ));
        }
        unsafe { *el() = 0 };
        let g = unsafe { llogbf128(x) };
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::llogbf128(x) };
        let fe = unsafe { *el() };
        if g != f || ge != fe {
            mism.push(format!(
                "llogb x={:#034x}: glibc=({g},e={ge}) fl=({f},e={fe})",
                x.to_bits()
            ));
        }
    }

    assert!(
        mism.is_empty(),
        "f128 scalb/logb diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
