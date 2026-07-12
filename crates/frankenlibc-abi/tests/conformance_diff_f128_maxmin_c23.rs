//! Differential gate: f128 nextup/nextdown + the C23 fmaximum/fminimum family
//! match glibc bit-for-bit incl. errno (bd-9z5ikz batch 8). Previously broken
//! f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn nextupf128(x: f128) -> f128;
    fn nextdownf128(x: f128) -> f128;
    fn fmaximumf128(x: f128, y: f128) -> f128;
    fn fminimumf128(x: f128, y: f128) -> f128;
    fn fmaximum_numf128(x: f128, y: f128) -> f128;
    fn fminimum_numf128(x: f128, y: f128) -> f128;
    fn fmaximum_magf128(x: f128, y: f128) -> f128;
    fn fminimum_magf128(x: f128, y: f128) -> f128;
    fn fmaximum_mag_numf128(x: f128, y: f128) -> f128;
    fn fminimum_mag_numf128(x: f128, y: f128) -> f128;
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
        -3.0,
        0.5,
        5.0,
        -5.0,
        1e300f128,
        -1e-300f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(1u128 << 112),       // smallest normal
        f128::from_bits(0x7ffe_u128 << 112), // near-largest finite
    ];
    let mut st: u64 = 0x1357_9bdf_2468_ace0;
    for _ in 0..24 {
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
fn f128_maxmin_c23_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();

    // nextup / nextdown (single-arg, value + errno).
    for &x in &vals {
        for (name, gf, ff) in [
            (
                "nextup",
                nextupf128 as unsafe extern "C" fn(f128) -> f128,
                ma::nextupf128 as unsafe extern "C" fn(f128) -> f128,
            ),
            ("nextdown", nextdownf128, ma::nextdownf128),
        ] {
            unsafe { *el() = 0 };
            let g = unsafe { gf(x) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ff(x) }.to_bits();
            let fe = unsafe { *el() };
            if g != f || ge != fe {
                mism.push(format!(
                    "{name} x={:#034x}: glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                    x.to_bits()
                ));
            }
        }
    }

    // C23 max/min family (2-arg).
    type F = unsafe extern "C" fn(f128, f128) -> f128;
    let fns: &[(&str, F, F)] = &[
        ("fmaximum", fmaximumf128, ma::fmaximumf128),
        ("fminimum", fminimumf128, ma::fminimumf128),
        ("fmaximum_num", fmaximum_numf128, ma::fmaximum_numf128),
        ("fminimum_num", fminimum_numf128, ma::fminimum_numf128),
        ("fmaximum_mag", fmaximum_magf128, ma::fmaximum_magf128),
        ("fminimum_mag", fminimum_magf128, ma::fminimum_magf128),
        (
            "fmaximum_mag_num",
            fmaximum_mag_numf128,
            ma::fmaximum_mag_numf128,
        ),
        (
            "fminimum_mag_num",
            fminimum_mag_numf128,
            ma::fminimum_mag_numf128,
        ),
    ];
    for &(name, gf, ff) in fns {
        for &x in &vals {
            for &y in &vals {
                let g = unsafe { gf(x, y) }.to_bits();
                let f = unsafe { ff(x, y) }.to_bits();
                if g != f {
                    mism.push(format!(
                        "{name} x={:#034x} y={:#034x}: glibc={g:#034x} fl={f:#034x}",
                        x.to_bits(),
                        y.to_bits()
                    ));
                }
            }
        }
    }

    assert!(
        mism.is_empty(),
        "f128 C23 max/min diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
