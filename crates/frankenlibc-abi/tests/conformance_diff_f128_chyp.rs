//! Differential gate: f128 ccosh/csinh/ccos match glibc bit-for-bit
//! (bd-9z5ikz). All were garbage CDoubleComplex-ABI stubs. The fixes port
//! glibc's s_ccosh/s_csinh/s_ccos templates over the byte-exact
//! sincos/sinh/cosh/exp → byte-exact (ccos = ccosh(-im + i re)).
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi::{self as ma, CFloat128Complex as C};

unsafe extern "C" {
    fn ccoshf128(z: C) -> C;
    fn csinhf128(z: C) -> C;
    fn ccosf128(z: C) -> C;
}

fn parts() -> Vec<f128> {
    let mut v = vec![
        0.0, -0.0f128, 1.0, -1.0, 0.5, -0.5, 2.0, 3.0, 10.0, 100.0, 11355.0,
        11356.0, 30000.0, -2.0, 0.7853981633974483096f128, 1e-20f128,
        f128::from_bits(1),
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x63_68_79_70_31_32_38_cc;
    for _ in 0..36 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3ff0 + (hi % 0x0030)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_chyp_matches_glibc() {
    let p = parts();
    let mut mism = Vec::new();
    for (name, g, f) in [
        ("ccosh", ccoshf128 as unsafe extern "C" fn(C) -> C, ma::ccoshf128 as unsafe extern "C" fn(C) -> C),
        ("csinh", csinhf128, ma::csinhf128),
        ("ccos", ccosf128, ma::ccosf128),
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
    assert!(mism.is_empty(), "ccosh/csinh/ccos diverged ({}):\n{}", mism.len(), mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}
