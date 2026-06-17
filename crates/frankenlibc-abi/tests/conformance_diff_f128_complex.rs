//! Differential gate: the exact f128 complex accessors (creal/cimag/conj/cproj)
//! match glibc bit-for-bit (bd-9z5ikz batch 12). Previously broke the ABI
//! (complex-f64 instead of _Complex _Float128).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn crealf128(z: C) -> f128;
    fn cimagf128(z: C) -> f128;
    fn conjf128(z: C) -> C;
    fn cprojf128(z: C) -> C;
}

fn parts() -> Vec<f128> {
    vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        3.5,
        -7.25,
        1e300f128,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                                     // subnormal
    ]
}

#[test]
fn f128_complex_accessors_match_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    for &re in &p {
        for &im in &p {
            let z = C { re, im };
            // creal / cimag
            let (gr, fr) = (unsafe { crealf128(z) }.to_bits(), unsafe { ma::crealf128(z) }.to_bits());
            if gr != fr {
                mism.push(format!("creal re={:#034x} im={:#034x}: glibc={gr:#034x} fl={fr:#034x}", re.to_bits(), im.to_bits()));
            }
            let (gi, fi) = (unsafe { cimagf128(z) }.to_bits(), unsafe { ma::cimagf128(z) }.to_bits());
            if gi != fi {
                mism.push(format!("cimag re={:#034x} im={:#034x}: glibc={gi:#034x} fl={fi:#034x}", re.to_bits(), im.to_bits()));
            }
            // conj
            let (g, f) = (unsafe { conjf128(z) }, unsafe { ma::conjf128(z) });
            if g.re.to_bits() != f.re.to_bits() || g.im.to_bits() != f.im.to_bits() {
                mism.push(format!("conj re={:#034x} im={:#034x}: glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})", re.to_bits(), im.to_bits(), g.re.to_bits(), g.im.to_bits(), f.re.to_bits(), f.im.to_bits()));
            }
            // cproj
            let (g, f) = (unsafe { cprojf128(z) }, unsafe { ma::cprojf128(z) });
            if g.re.to_bits() != f.re.to_bits() || g.im.to_bits() != f.im.to_bits() {
                mism.push(format!("cproj re={:#034x} im={:#034x}: glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})", re.to_bits(), im.to_bits(), g.re.to_bits(), g.im.to_bits(), f.re.to_bits(), f.im.to_bits()));
            }
        }
    }
    assert!(mism.is_empty(), "f128 complex accessors diverged ({}):\n{}", mism.len(), mism.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
