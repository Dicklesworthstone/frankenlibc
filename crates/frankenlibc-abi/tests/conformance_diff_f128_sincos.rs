//! Differential gate: f128 sinf128 + cosf128 match glibc bit-for-bit
//! (bd-9z5ikz). Both were garbage f64-ABI stubs. The fix ports glibc's ldbl-128
//! trig cluster verbatim — __kernel_rem_pio2 (Payne-Hanek with the 2/pi table)
//! + __ieee754_rem_pio2l + __kernel_sincosl (Chebyshev + the 83-point sin/cos
//! table) + the sinl/cosl dispatchers — so they are byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;

unsafe extern "C" {
    fn sinf128(x: f128) -> f128;
    fn cosf128(x: f128) -> f128;
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        0.5,
        -0.5,
        0.7853981633974483096f128, // ~pi/4
        1.0,
        1.5707963267948966192f128, // ~pi/2
        2.0,
        3.141592653589793238f128, // ~pi
        3.0,
        4.0,
        6.283185307179586f128, // ~2pi
        10.0,
        100.0,
        1000.0,
        1e6f128,
        1e18f128,
        1e30f128,
        1e300f128,
        1e1000f128,
        1e4000f128,
        0.1484375f128, // kernel branch boundary
        0.1f128,
        1e-20f128,
        1e-40f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),                    // +inf → NaN+EDOM
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    // Dense sweep across several periods (exercises reduction heavily).
    let mut q: i64 = -20000;
    while q <= 20000 {
        v.push(q as f128 / 1000.0);
        q += 1;
    }
    // PRNG across magnitudes (large args drive the multi-precision reduction).
    let mut st: u64 = 0x5369_6e43_6f73_3132;
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
fn f128_sincos_matches_glibc() {
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &x in &values() {
        for (name, g, f) in [
            ("sin", sinf128 as unsafe extern "C" fn(f128) -> f128, ma::sinf128 as unsafe extern "C" fn(f128) -> f128),
            ("cos", cosf128, ma::cosf128),
        ] {
            let gv = unsafe { g(x) }.to_bits();
            let fv = unsafe { f(x) }.to_bits();
            n += 1;
            if gv != fv {
                mism.push(format!("{name}({:#034x}): glibc={gv:#034x} fl={fv:#034x}", x.to_bits()));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "sin/cos f128 diverged ({}/{}):\n{}",
        mism.len(),
        n,
        mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n")
    );
}
