//! Differential gate: f128 compoundnf128 (C23) matches glibc bit-for-bit on
//! value + errno (bd-9z5ikz). Was a garbage f64-ABI stub. The fix ports glibc's
//! s_compoundn template verbatim (NUM_PARTS=1 for binary128): split 1+x hi/lo,
//! pown(xhi,y), times a compensated (1+xlo/xhi)^y factor via mul3_split +
//! cascade sums + exp. Built on the byte-exact powl_f128 + expl_f128 →
//! byte-exact.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_int, c_longlong};

unsafe extern "C" {
    fn compoundnf128(x: f128, n: c_longlong) -> f128;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn bases() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        1.0,
        -1.0,
        -0.5,
        0.5,
        2.0,
        -0.9f128,
        -0.99f128,
        3.0,
        0.1,
        -0.1,
        10.0,
        100.0,
        1e10f128,
        1e-10f128,
        -2.0,
        f128::from_bits(0x7fff_u128 << 112),
        f128::from_bits(0xffff_u128 << 112),
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),
    ];
    let mut st: u64 = 0x636f_6d70_6e31_3238;
    for _ in 0..50 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lo = st;
        let ef = (0x3fe0 + (hi % 0x0040)) as u128;
        let mant = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let sign = ((hi >> 23) & 1) as u128;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mant));
    }
    v
}

#[test]
fn f128_compoundn_matches_glibc() {
    let exps: Vec<c_longlong> = vec![
        0, 1, -1, 2, -2, 3, -3, 5, -5, 10, -10, 50, -50, 100, -100, 1000, -1000, 100000, -100000,
    ];
    let mut mism = Vec::new();
    for &x in &bases() {
        for &n in &exps {
            unsafe { *el() = 0 };
            let g = unsafe { compoundnf128(x, n) }.to_bits();
            let ge = unsafe { *el() };
            unsafe { *el() = 0 };
            let f = unsafe { ma::compoundnf128(x, n) }.to_bits();
            let fe = unsafe { *el() };
            if g != f || ge != fe {
                mism.push(format!(
                    "compoundn({:#034x},{n}): glibc=({g:#034x},e={ge}) fl=({f:#034x},e={fe})",
                    x.to_bits()
                ));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "compoundnf128 diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
