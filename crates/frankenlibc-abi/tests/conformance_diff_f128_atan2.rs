//! Differential gate: f128 atan2f128 matches glibc bit-for-bit (bd-9z5ikz).
//! atan2f128 was a garbage f64-ABI stub. The fix ports glibc's ldbl-128
//! `__ieee754_atan2l` verbatim — IEEE special cases + quadrant placement of
//! atan(|y/x|). Depends only on the byte-exact atan_f128 + algebraic f128 ops,
//! so it is byte-exact. (Signature is atan2(y, x).)
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn atan2f128(y: f128, x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        2.0,
        -2.0,
        0.5,
        -0.5,
        3.0,
        100.0,
        -100.0,
        1e-20f128,
        1e20f128,
        1e300f128,
        1e-300f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),                  // smallest subnormal
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut st: u64 = 0x2468_ace0_1357_9bdf;
    for _ in 0..90 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3e00 + (hi % 0x0400)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 21) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_atan2_matches_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &y in &vals {
        for &x in &vals {
            let g = unsafe { atan2f128(y, x) }.to_bits();
            let f = unsafe { ma::atan2f128(y, x) }.to_bits();
            n += 1;
            if g != f {
                mism.push(format!(
                    "atan2(y={:#034x}, x={:#034x}): glibc={g:#034x} fl={f:#034x}",
                    y.to_bits(),
                    x.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "atan2f128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
