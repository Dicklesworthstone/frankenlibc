//! Differential gate: f128 clogf128 matches glibc bit-for-bit (bd-9z5ikz).
//! Was a garbage CDoubleComplex-ABI stub. The fix ports glibc's s_clog
//! template: Re = log|z| via range-split log1p/log (+ x2y2m1 + scaling), Im =
//! atan2(im,re). Built on the byte-exact log1pl/logl/hypot/atan2/scalbn →
//! byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn clogf128(z: C) -> C;
}

fn parts() -> Vec<f128> {
    let mut v = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        0.5,
        -0.5,
        0.75,
        1.5,
        -1.5,
        2.0,
        -2.0,
        3.0,
        0.9f128,
        1.1f128,
        0.6f128,
        1e300f128,
        1e-300f128,
        1e4000f128,
        1e-4000f128,
        f128::MIN_POSITIVE,
        f128::MAX,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x636c_6f67_3132_38ff;
    for _ in 0..30 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fc0 + (hi % 0x0080)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_clog_matches_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    for &re in &p {
        for &im in &p {
            let z = C { re, im };
            let g = unsafe { clogf128(z) };
            let f = unsafe { ma::clogf128(z) };
            if g.re.to_bits() != f.re.to_bits() || g.im.to_bits() != f.im.to_bits() {
                mism.push(format!(
                    "clog(re={:#034x},im={:#034x}): glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})",
                    re.to_bits(), im.to_bits(), g.re.to_bits(), g.im.to_bits(), f.re.to_bits(), f.im.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "clogf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
