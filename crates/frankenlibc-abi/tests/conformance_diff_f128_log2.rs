//! Differential gate: f128 log2f128 matches glibc bit-for-bit on value + errno
//! (bd-9z5ikz). log2f128 was a garbage f64-ABI stub. The fix ports glibc's
//! ldbl-128 `__ieee754_log2l` (Cephes) verbatim — frexp + R/S (|e|>2) or P/Q
//! log(1+x), combined via LOG2EA = log2(e)-1 + integer exponent. Self-contained
//! → byte-exact. ERANGE pole at 0, EDOM x<0.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn log2f128(x: f128) -> f128;
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
        4.0,
        8.0,
        0.5,
        0.25,
        0.7071067811865475244f128,
        1.4142135623730951f128,
        1e30f128,
        1e-30f128,
        1e300f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut q: i64 = 700;
    while q <= 1400 {
        v.push(q as f128 / 1024.0);
        q += 1;
    }
    let mut st: u64 = 0x2020_3030_4040_5050;
    for _ in 0..6000 {
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
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_log2_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        unsafe { *el() = 0 };
        let g = unsafe { log2f128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::log2f128(x) }.to_bits();
        let fe = unsafe { *el() };
        n += 1;
        if g != f || ge != fe {
            mism.push(format!(
                "log2({:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "log2f128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
