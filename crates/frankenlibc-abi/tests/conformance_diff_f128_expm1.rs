//! Differential gate: f128 expm1f128 matches glibc bit-for-bit on value + errno
//! (bd-9z5ikz). expm1f128 was a garbage f64-ABI stub. The fix ports glibc's
//! ldbl-128 `__expm1l` (Cephes) — plain expl for x>=64, else ln2 reduction +
//! P/Q rational for exp(r)-1 then 2^k(qx+1)-1. Built on the byte-exact
//! expl_f128 → byte-exact. ERANGE on overflow.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn expm1f128(x: f128) -> f128;
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
        0.5,
        -0.5,
        1e-10f128,
        -1e-10f128,
        1e-40f128,
        63.0,
        64.0,
        65.0,
        100.0,
        11356.0,
        11357.0, // overflow
        -79.0,
        -80.0, // near minarg
        -100.0,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf → -1
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -900;
    while q <= 11500 {
        v.push(q as f128 / 16.0);
        q += 7;
    }
    let mut st: u64 = 0x5deece66d_u64 ^ 0xabcd;
    for _ in 0..5000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fb0 + (hi % 0x0060)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_expm1_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        unsafe { *el() = 0 };
        let g = unsafe { expm1f128(x) }.to_bits();
        let ge = unsafe { *el() };
        unsafe { *el() = 0 };
        let f = unsafe { ma::expm1f128(x) }.to_bits();
        let fe = unsafe { *el() };
        n += 1;
        if g != f || ge != fe {
            mism.push(format!(
                "expm1({:#034x}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "expm1f128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
