//! Differential gate: f128 cargf128 matches glibc bit-for-bit (bd-9z5ikz).
//! cargf128 was a garbage stub (CDoubleComplex ABI). The fix is carg(z) =
//! atan2(cimag, creal) on the byte-exact atan2_f128 → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn cargf128(z: C) -> f128;
}

fn parts() -> Vec<f128> {
    vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        2.0,
        -2.0,
        0.5,
        -0.5,
        1e300f128,
        1e-300f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits(1),                  // subnormal
    ]
}

#[test]
fn f128_carg_matches_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    for &re in &p {
        for &im in &p {
            let z = C { re, im };
            let g = unsafe { cargf128(z) }.to_bits();
            let f = unsafe { ma::cargf128(z) }.to_bits();
            if g != f {
                mism.push(format!(
                    "carg(re={:#034x},im={:#034x}): glibc={g:#034x} fl={f:#034x}",
                    re.to_bits(),
                    im.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "cargf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
