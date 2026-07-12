//! Differential gate: f128 asinf128 matches glibc bit-for-bit (bd-9z5ikz).
//! asinf128 was a garbage f64-ABI stub. The fix ports glibc's ldbl-128
//! `__ieee754_asinl` verbatim (three range-split rational approximations +
//! sqrt with a hi/lo split). Self-contained (only sqrtl + algebraic f128),
//! polynomials as sequential Horner → byte-exact. Domain is [-1, 1].
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn asinf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.5,
        -0.5,
        0.5625,
        0.625,
        0.975,
        0.09375,
        1e-20f128,
        1e-30f128,
        f128::from_bits(1), // smallest subnormal
        1.5f128,            // > 1 → NaN
        -2.0f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf → NaN
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    // Dense coverage of [-1, 1] across all the range-split boundaries.
    let mut q: i64 = -1024;
    while q <= 1024 {
        v.push((q as f128) / 1024.0);
        q += 1;
    }
    // Cluster near the branch cut points 0.5, 0.5625, 0.625, 0.975, 1.0.
    for &b in &[0.5f128, 0.5625, 0.625, 0.975, 1.0] {
        for d in [-1e-3f128, -1e-9, 0.0, 1e-9, 1e-3] {
            v.push(b + d);
            v.push(-(b + d));
        }
    }
    // PRNG within [-1,1]: take random mantissa, exponent in [0x3f00, 0x3fff].
    let mut st: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..4000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3f00 + (hi % 0x0100)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_asin_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        let g = unsafe { asinf128(x) }.to_bits();
        let f = unsafe { ma::asinf128(x) }.to_bits();
        n += 1;
        if g != f {
            mism.push(format!(
                "asin({:#034x}): glibc={g:#034x} fl={f:#034x}",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "asinf128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
