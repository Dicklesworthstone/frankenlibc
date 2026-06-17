//! Differential gate: f128 cbrtf128 matches glibc bit-for-bit (bd-9z5ikz).
//! Previously the stub declared the f64 ABI (`cbrtf128(x: f64) -> f64`), so a
//! real `_Float128` call read the wrong register and returned garbage. The fix
//! ports glibc's ldbl-128 Cephes/Moshier `__cbrtl` verbatim (frexp + degree-5
//! mantissa polynomial + cbrt(2^rem) scaling + 3 Newton iterations) using only
//! correctly-rounded f128 `+ - * /`, so the result is byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn cbrtf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        8.0,
        -8.0,
        27.0,
        -27.0,
        2.0,
        0.5,
        0.125,
        1000.0,
        -1000.0,
        1e30f128,
        -1e30f128,
        1e-30f128,
        1e300f128,
        1e-300f128,
        1e4000f128,
        1e-4000f128, // subnormal-range magnitudes
        3.141592653589793238462643383279f128,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                                     // smallest subnormal
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::MIN,
    ];
    // Pseudo-random spread across the exponent range, both signs.
    let mut st: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..4000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        // exponent field anywhere in the normal range, random mantissa + sign.
        let ef = (hi % 0x7fff) as u128; // 0..=0x7ffe
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 13) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_cbrt_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        let g = unsafe { cbrtf128(x) }.to_bits();
        let f = unsafe { ma::cbrtf128(x) }.to_bits();
        n += 1;
        if g != f {
            mism.push(format!("cbrt({:#034x}): glibc={g:#034x} fl={f:#034x}", x.to_bits()));
        }
    }
    assert!(
        mism.is_empty(),
        "cbrtf128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
