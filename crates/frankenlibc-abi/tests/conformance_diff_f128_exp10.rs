//! Differential gate: f128 exp10f128 matches glibc bit-for-bit on value + errno
//! (bd-9z5ikz). exp10f128 was a garbage f64-ABI stub. The fix ports glibc's
//! ldbl-128 `__ieee754_exp10l` verbatim (hi/lo split + arg·ln10 + expl·expl).
//! Built on the byte-exact expl_f128 → byte-exact. ERANGE over/underflow.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn exp10f128(x: f128) -> f128;
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
        3.0,
        -3.0,
        0.5,
        10.0,
        4932.0,
        4933.0,
        4934.0,
        -4974.0,
        -4975.0,
        -5000.0,
        1e-30f128,
        -1e-30f128,
        1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf → 0
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -50000;
    while q <= 50000 {
        v.push(q as f128 / 10.0);
        q += 51;
    }
    let mut st: u64 = 0x3141_5926_5358_9793;
    for _ in 0..5000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fc0 + (hi % 0x0040)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_exp10_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        unsafe { *el() = 0 };
        let g = unsafe { exp10f128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::exp10f128(x) }.to_bits();
        let fe = unsafe { *el() };
        n += 1;
        if g != f || ge != fe {
            mism.push(format!(
                "exp10({:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "exp10f128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
