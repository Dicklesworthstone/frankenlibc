//! Differential gate: f128 cpowf128 matches glibc bit-for-bit (bd-9z5ikz).
//! Was a garbage CDoubleComplex-ABI stub. The fix is glibc's s_cpow:
//! cpow(x,c) = cexp(c * clog(x)) with a __multc3-faithful complex product, on
//! the byte-exact cexp/clog → byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn cpowf128(a: C, b: C) -> C;
}

fn parts() -> Vec<f128> {
    let mut v = vec![
        0.0, -0.0f128, 1.0, -1.0, 2.0, -2.0, 0.5, 3.0, 0.25, 10.0, -0.5,
        1.5, 1e-10f128,
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x63_70_6f_77_31_32_38_ee;
    for _ in 0..14 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3ff0 + (hi % 0x0020)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_cpow_matches_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    let mut n = 0u64;
    for &ar in &p {
        for &ai in &p {
            for &br in &p {
                for &bi in &p {
                    let a = C { re: ar, im: ai };
                    let b = C { re: br, im: bi };
                    let g = unsafe { cpowf128(a, b) };
                    let f = unsafe { ma::cpowf128(a, b) };
                    n += 1;
                    if g.re.to_bits() != f.re.to_bits() || g.im.to_bits() != f.im.to_bits() {
                        mism.push(format!(
                            "cpow(({:#034x},{:#034x}),({:#034x},{:#034x})): glibc=({:#034x},{:#034x}) fl=({:#034x},{:#034x})",
                            ar.to_bits(), ai.to_bits(), br.to_bits(), bi.to_bits(),
                            g.re.to_bits(), g.im.to_bits(), f.re.to_bits(), f.im.to_bits()
                        ));
                    }
                }
            }
        }
    }
    assert!(mism.is_empty(), "cpowf128 diverged ({}/{}):\n{}", mism.len(), n, mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}
