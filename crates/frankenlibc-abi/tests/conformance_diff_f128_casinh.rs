//! Differential gate: f128 complex inverse sin/cos family (casinh/casin/cacosh/
//! cacos) matches glibc bit-for-bit (bd-9z5ikz). All were garbage CDoubleComplex
//! stubs. The fix ports glibc's shared __kernel_casinh (k_casinh_template.c) +
//! the four dispatchers verbatim over CFloat128Complex, built on byte-exact
//! log/log1p/hypot/sqrt/atan2/clog/csqrt → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn casinhf128(z: C) -> C;
    fn casinf128(z: C) -> C;
    fn cacoshf128(z: C) -> C;
    fn cacosf128(z: C) -> C;
}

fn parts() -> Vec<f128> {
    let mut v = vec![
        0.0, -0.0f128, 1.0, -1.0, 0.5, -0.5, 0.75, -0.75, 1.5, -1.5, 2.0, -2.0,
        0.25, 0.9f128, 1.1f128, 1.25f128, 3.0, 1e10f128, 1e-10f128, 1e300f128,
        1e-300f128, f128::MIN_POSITIVE, f128::MAX,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x6361_7369_6e68_3132;
    for _ in 0..30 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fe0 + (hi % 0x0050)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_casinh_family_matches_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    for (name, g, f) in [
        ("casinh", casinhf128 as unsafe extern "C" fn(C) -> C, ma::casinhf128 as unsafe extern "C" fn(C) -> C),
        ("casin", casinf128, ma::casinf128),
        ("cacosh", cacoshf128, ma::cacoshf128),
        ("cacos", cacosf128, ma::cacosf128),
    ] {
        for &re in &p {
            for &im in &p {
                let z = C { re, im };
                let gv = unsafe { g(z) };
                let fv = unsafe { f(z) };
                if gv.re.to_bits() != fv.re.to_bits() || gv.im.to_bits() != fv.im.to_bits() {
                    mism.push(format!(
                        "{name}(re={:#034x},im={:#034x}): glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})",
                        re.to_bits(), im.to_bits(), gv.re.to_bits(), gv.im.to_bits(), fv.re.to_bits(), fv.im.to_bits()
                    ));
                }
            }
        }
    }
    assert!(mism.is_empty(), "casinh family diverged ({}):\n{}", mism.len(), mism.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}
