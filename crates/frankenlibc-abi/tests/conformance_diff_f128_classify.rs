//! Differential gate: the exact-operation f128 functions (classification, fabs,
//! copysign) match glibc bit-for-bit (bd-9z5ikz). These had a broken f64 arg-ABI
//! (read the wrong register -> garbage); now they operate on the f128 bits.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as gi;
use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn fabsf128(x: f128) -> f128;
    fn copysignf128(x: f128, y: f128) -> f128;
    fn __isnanf128(x: f128) -> c_int;
    fn __isinff128(x: f128) -> c_int;
    fn __signbitf128(x: f128) -> c_int;
    fn __finitef128(x: f128) -> c_int;
    fn __fpclassifyf128(x: f128) -> c_int;
    fn __issignalingf128(x: f128) -> c_int;
}

fn values() -> Vec<f128> {
    let mut v = vec![
        f128::from_bits(0),                                     // +0
        f128::from_bits(1u128 << 127),                          // -0
        1.0f128,
        -1.0f128,
        3.14159f128,
        -2.5f128,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits((0xffff_u128 << 112) | 1),              // -sNaN
        f128::from_bits(1),                                     // smallest subnormal
        f128::from_bits(0x1234_5678),                           // subnormal
        f128::from_bits(1u128 << 112),                          // smallest normal
        f128::from_bits(0x7ffe_u128 << 112),                    // near-largest
    ];
    let mut st: u64 = 0xfeed_1234_5678_9abc;
    for _ in 0..40 {
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = st;
        st = st.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        v.push(f128::from_bits(((hi as u128) << 64) | st as u128));
    }
    v
}

#[test]
fn f128_exact_ops_match_glibc() {
    let vals = values();
    let mut mism = Vec::new();
    for &x in &vals {
        macro_rules! ck {
            ($name:literal, $g:expr, $f:expr) => {
                if $g != $f {
                    mism.push(format!("{} bits={:#034x}: glibc={} fl={}", $name, x.to_bits(), $g, $f));
                }
            };
        }
        ck!("isnan", unsafe { __isnanf128(x) }, unsafe { gi::__isnanf128(x) });
        ck!("isinf", unsafe { __isinff128(x) }, unsafe { gi::__isinff128(x) });
        ck!("signbit", unsafe { __signbitf128(x) }, unsafe { gi::__signbitf128(x) });
        ck!("finite", unsafe { __finitef128(x) }, unsafe { ma::__finitef128(x) });
        ck!("fpclassify", unsafe { __fpclassifyf128(x) }, unsafe { gi::__fpclassifyf128(x) });
        ck!("issignaling", unsafe { __issignalingf128(x) }, unsafe { ma::__issignalingf128(x) });
        let gf = unsafe { fabsf128(x) }.to_bits();
        let ff = unsafe { ma::fabsf128(x) }.to_bits();
        if gf != ff {
            mism.push(format!("fabs bits={:#034x}: glibc={gf:#034x} fl={ff:#034x}", x.to_bits()));
        }
        for &y in &vals {
            let gc = unsafe { copysignf128(x, y) }.to_bits();
            let fc = unsafe { ma::copysignf128(x, y) }.to_bits();
            if gc != fc {
                mism.push(format!("copysign x={:#034x} y={:#034x}: glibc={gc:#034x} fl={fc:#034x}", x.to_bits(), y.to_bits()));
            }
        }
    }
    assert!(mism.is_empty(), "f128 exact ops diverged ({}):\n{}", mism.len(), mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}
