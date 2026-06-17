//! Differential gate: f128 acosf128 matches glibc bit-for-bit (bd-9z5ikz).
//! acosf128 was a garbage f64-ABI stub. The fix ports glibc's ldbl-128
//! `__ieee754_acosl` verbatim (five range branches: pS/qS, P/Q, rS/sS, and the
//! sqrt path with extended-precision correction). Self-contained (only sqrtl +
//! algebraic f128), polynomials as sequential Horner → byte-exact. Domain [-1,1].
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn acosf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.5,
        -0.5,
        0.4375,
        0.5625,
        0.625,
        1e-20f128,
        1e-40f128,
        f128::from_bits(1),                                     // smallest subnormal
        1.5f128,
        -2.0f128,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -1024;
    while q <= 1024 {
        v.push((q as f128) / 1024.0);
        q += 1;
    }
    for &b in &[0.4375f128, 0.5, 0.5625, 0.625, 1.0] {
        for d in [-1e-3f128, -1e-9, 0.0, 1e-9, 1e-3] {
            v.push(b + d);
            v.push(-(b + d));
        }
    }
    let mut st: u64 = 0xc2b2_ae3d_27d4_eb4f;
    for _ in 0..4000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3f00 + (hi % 0x0100)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_acos_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        let g = unsafe { acosf128(x) }.to_bits();
        let f = unsafe { ma::acosf128(x) }.to_bits();
        n += 1;
        if g != f {
            mism.push(format!("acos({:#034x}): glibc={g:#034x} fl={f:#034x}", x.to_bits()));
        }
    }
    assert!(
        mism.is_empty(),
        "acosf128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
