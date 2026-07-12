//! Differential gate: f128 tanhf128 matches glibc bit-for-bit (bd-9z5ikz).
//! tanhf128 was a garbage f64-ABI stub. The fix ports glibc's ldbl-128 `__tanhl`
//! verbatim (tanh via expm1l(±2|x|), ±1 saturation for |x|>=40). Built on the
//! byte-exact expm1l_f128 → byte-exact. No errno.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn tanhf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.5,
        -0.5,
        40.0,
        41.0,
        100.0,
        1e-20f128,
        -1e-20f128,
        1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112), // +inf → 1
        f128::from_bits(0xffff_u128 << 112), // -inf → -1
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut q: i64 = -1400;
    while q <= 1400 {
        v.push(q as f128 / 32.0);
        q += 1;
    }
    let mut st: u64 = 0x1111_2222_3333_4444;
    for _ in 0..4000 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fb0 + (hi % 0x0070)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_tanh_matches_glibc() {
    let mut mism = Vec::new();
    for &x in &values() {
        let g = unsafe { tanhf128(x) }.to_bits();
        let f = unsafe { ma::tanhf128(x) }.to_bits();
        if g != f {
            mism.push(format!(
                "tanh({:#034x}): glibc={g:#034x} fl={f:#034x}",
                x.to_bits()
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "tanhf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
