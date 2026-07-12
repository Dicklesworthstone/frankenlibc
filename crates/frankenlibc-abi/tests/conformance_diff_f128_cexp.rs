//! Differential gate: f128 cexpf128 matches glibc bit-for-bit (bd-9z5ikz).
//! Was a garbage CDoubleComplex-ABI stub. The fix ports glibc's s_cexp template
//! over the byte-exact expl/sinl/cosl → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn cexpf128(z: C) -> C;
}

fn parts() -> Vec<f128> {
    let mut v = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.5,
        2.0,
        3.0,
        10.0,
        100.0,
        700.0,
        11356.0,
        11357.0,
        30000.0,
        -100.0,
        1e-20f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x63_65_78_70_31_32_38_aa;
    for _ in 0..40 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3ff0 + (hi % 0x0030)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_cexp_matches_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    for &re in &p {
        for &im in &p {
            let z = C { re, im };
            let g = unsafe { cexpf128(z) };
            let f = unsafe { ma::cexpf128(z) };
            if g.re.to_bits() != f.re.to_bits() || g.im.to_bits() != f.im.to_bits() {
                mism.push(format!(
                    "cexp(re={:#034x},im={:#034x}): glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})",
                    re.to_bits(), im.to_bits(), g.re.to_bits(), g.im.to_bits(), f.re.to_bits(), f.im.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "cexpf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
