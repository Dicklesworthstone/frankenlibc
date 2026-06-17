//! Differential gate: f128 tanf128 matches glibc bit-for-bit (bd-9z5ikz).
//! Was a garbage f64-ABI stub. The fix ports glibc's ldbl-128 __kernel_tanl +
//! s_tanl over the byte-exact rem_pio2l reduction → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn tanf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 0.5, -0.5, 0.6743316650390625f128, 0.7853981633974483096f128,
        1.0, 1.5707963267948966192f128, 2.0, 3.0, 10.0, 100.0, 1e6f128, 1e30f128,
        1e300f128, 1e4000f128, 1e-20f128, 1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut q: i64 = -16000;
    while q <= 16000 {
        v.push(q as f128 / 1000.0);
        q += 1;
    }
    let mut st: u64 = 0x54_61_6e_31_32_38_ff_aa;
    for _ in 0..8000 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (hi % 0x7fff) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_tan_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        let g = unsafe { tanf128(x) }.to_bits();
        let f = unsafe { ma::tanf128(x) }.to_bits();
        n += 1;
        if g != f {
            mism.push(format!("tan({:#034x}): glibc={g:#034x} fl={f:#034x}", x.to_bits()));
        }
    }
    assert!(mism.is_empty(), "tanf128 diverged ({}/{}):\n{}", mism.len(), n, mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}
