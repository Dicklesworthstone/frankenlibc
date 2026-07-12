//! Differential gate: f128 rsqrtf128 (C23 reciprocal sqrt) matches glibc
//! bit-for-bit on value and errno (bd-9z5ikz). Was a garbage f64-ABI stub; the
//! fix is glibc's s_rsqrt verbatim: `1/sqrtl(x)` with EDOM for x<0 and ERANGE
//! for x==0 (no errno for NaN, since islessequal is false when unordered).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn rsqrtf128(x: f128) -> f128;
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
        4.0,
        0.25,
        2.0,
        100.0,
        -100.0,
        1e30f128,
        1e-30f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut st: u64 = 0x51ce_d00d_f00d_1234;
    for _ in 0..2000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (hi % 0x7fff) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 13) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_rsqrt_matches_glibc() {
    let mut mism = Vec::new();
    for &x in &values() {
        unsafe { *el() = 0 };
        let g = unsafe { rsqrtf128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::rsqrtf128(x) }.to_bits();
        let fe = unsafe { *el() };
        if g != f || ge != fe {
            mism.push(format!(
                "rsqrt({:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "rsqrtf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
