//! Differential gate: f128 powrf128 (C23) matches glibc bit-for-bit on value +
//! errno (bd-9z5ikz). Was a garbage f64-ABI stub. The fix mirrors glibc's
//! s_powr template: |x|^y (x>=0 required) via the byte-exact powl_f128, with the
//! powr-specific domain lattice (x<0, 0^0, 1^inf, inf^0 → EDOM) and ERANGE on
//! over/underflow. Byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn powrf128(x: f128, y: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn vals() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        2.0,
        -2.0,
        0.5,
        3.0,
        10.0,
        0.1,
        1.5,
        100.0,
        2.5,
        -3.0,
        7.0,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    for k in -8i64..=8 {
        v.push(k as f128);
        v.push(k as f128 + 0.5);
    }
    v
}

#[test]
fn f128_powr_matches_glibc() {
    let v = vals();
    let mut mism = Vec::new();
    for &x in &v {
        for &y in &v {
            unsafe { *el() = 0 };
            let g = unsafe { powrf128(x, y) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::powrf128(x, y) }.to_bits();
            let fe = unsafe { *el() };
            if g != f || ge != fe {
                mism.push(format!(
                    "powr({:#034x},{:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                    x.to_bits(),
                    y.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "powrf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
