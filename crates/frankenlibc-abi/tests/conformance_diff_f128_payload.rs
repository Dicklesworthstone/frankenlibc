//! Differential gate: f128 getpayloadf128 + nanf128 match glibc bit-for-bit
//! (bd-9z5ikz batch 13). Previously broken f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{CStr, CString, c_char};

unsafe extern "C" {
    fn getpayloadf128(x: *const f128) -> f128;
    fn nanf128(s: *const c_char) -> f128;
}

#[test]
fn getpayload_matches_glibc() {
    let vals: Vec<f128> = vec![
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111) | 123), // qNaN(123)
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)),       // qNaN(0)
        f128::from_bits((0x7fff_u128 << 112) | 7),                    // sNaN(7)
        f128::from_bits((0x7fff_u128 << 112) | ((1u128 << 111) - 1)), // qNaN max payload
        1.0,
        -1.0,
        0.0,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits(1),                  // subnormal
    ];
    let mut mism = Vec::new();
    for v in &vals {
        let g = unsafe { getpayloadf128(v) }.to_bits();
        let f = unsafe { ma::getpayloadf128(v) }.to_bits();
        if g != f {
            mism.push(format!("getpayload({:#034x}): glibc={g:#034x} fl={f:#034x}", v.to_bits()));
        }
    }
    assert!(mism.is_empty(), "getpayloadf128 diverged:\n{}", mism.join("\n"));
}

#[test]
fn nan_matches_glibc() {
    let tags = ["", "0", "1", "123", "0x1f", "0xABCDEF", "0777", "abc", "12x", "999999999"];
    let mut mism = Vec::new();
    for t in tags {
        let c = CString::new(t).unwrap();
        let g = unsafe { nanf128(c.as_ptr()) }.to_bits();
        let f = unsafe { ma::nanf128(c.as_ptr()) }.to_bits();
        if g != f {
            mism.push(format!("nan({t:?}): glibc={g:#034x} fl={f:#034x}"));
        }
    }
    // (NULL tag is not tested: glibc's nanf128 dereferences the tag pointer and
    // crashes on NULL — UB — whereas fl handles it; can't compare.)
    assert!(mism.is_empty(), "nanf128 diverged:\n{}", mism.join("\n"));
    let _ = CStr::from_bytes_with_nul(b"\0");
}
