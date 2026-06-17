//! Differential gate: f128 pownf128 (C23) matches glibc bit-for-bit on value +
//! errno (bd-9z5ikz). Was a garbage f64-ABI stub. For binary128 (MANT_DIG=113
//! >= 63) glibc's pown reduces to pow(x, (f128)n); the fix mirrors that on the
//! byte-exact powl_f128 with pown's ERANGE tail. Byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_int, c_longlong};

unsafe extern "C" {
    fn pownf128(x: f128, n: c_longlong) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn bases() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 1.0, -1.0, 2.0, -2.0, 0.5, -0.5, 3.0, 10.0, 1.5, -1.5,
        100.0, 0.1, 1e10f128, 1e-10f128,
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x504f_574e_3132_38ff;
    for _ in 0..40 {
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
fn f128_pown_matches_glibc() {
    let exps: Vec<c_longlong> = vec![
        0, 1, -1, 2, -2, 3, -3, 4, 5, -5, 10, -10, 63, -63, 100, -100, 1000,
        -1000, 16383, -16494,
    ];
    let mut mism = Vec::new();
    for &x in &bases() {
        for &n in &exps {
            unsafe { *el() = 0 };
            let g = unsafe { pownf128(x, n) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::pownf128(x, n) }.to_bits();
            let fe = unsafe { *el() };
            if g != f || ge != fe {
                mism.push(format!("pown({:#034x},{n}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})", x.to_bits()));
            }
        }
    }
    assert!(mism.is_empty(), "pownf128 diverged ({}):\n{}", mism.len(), mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}
