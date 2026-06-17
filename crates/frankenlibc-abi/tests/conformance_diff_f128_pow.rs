//! Differential gate: f128 powf128 matches glibc bit-for-bit on VALUE
//! (bd-9z5ikz). powf128 was a garbage f64-ABI stub. The fix ports glibc's
//! ldbl-128 `__ieee754_powl` (fdlibm) verbatim — full special-case lattice +
//! two-piece log2(x) (LN/LD rational) + simulated extended-precision y·log2(x)
//! + 2^n·exp(y'·log2) (PN/PD rational). Self-contained → byte-exact. (errno is
//! layered in a follow-up; this gate pins the value contract.)
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn powf128(x: f128, y: f128) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.0, -3.0, 10.0, 0.1,
        1.5, -1.5, 4.0, 0.25, 100.0, -100.0, 1e10f128, 1e-10f128,
        2.5, -2.5, 7.0, 0.3333333333333333f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    // integer and half-integer exponents, both signs
    for k in -20i64..=20 {
        v.push(k as f128);
        v.push(k as f128 + 0.5);
    }
    // PRNG bases/exps
    let mut st: u64 = 0x70_77_65_72_5f_66_31_32;
    for _ in 0..120 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3ff0 + (hi % 0x0030)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_pow_matches_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &vals {
        for &y in &vals {
            unsafe { *el() = 0 };
            let g = unsafe { powf128(x, y) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::powf128(x, y) }.to_bits();
            let fe = unsafe { *el() };
            n += 1;
            if g != f || ge != fe {
                mism.push(format!("pow({:#034x},{:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})", x.to_bits(), y.to_bits()));
            }
        }
    }
    assert!(mism.is_empty(), "powf128 diverged ({}/{}):\n{}", mism.len(), n, mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}
