//! Differential gate: f128 setpayload/setpayloadsig match glibc bit-for-bit
//! (bd-9z5ikz batch 10). Previously broken f64 ABI.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::c_int;

unsafe extern "C" {
    fn setpayloadf128(res: *mut f128, pl: f128) -> c_int;
    fn setpayloadsigf128(res: *mut f128, pl: f128) -> c_int;
}

fn payloads() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, 1.0, 2.0, 123.0, 1000000.0, -1.0, -123.0, 2.5, 0.5,
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // nan
    ];
    // powers of two around the 2^111 payload limit, and the max valid payload
    for k in [109u32, 110, 111, 112] {
        v.push(f128::from_bits(((k + 16383) as u128) << 112)); // 2^k
    }
    // 2^111 - 1 (largest valid payload) and 2^110 + 7
    v.push(f128::from_bits((110u128 + 16383) << 112)); // 2^110
    v
}

#[test]
fn f128_setpayload_match_glibc() {
    let mut mism = Vec::new();
    for &pl in &payloads() {
        for (name, gf, ff) in [
            ("setpayload", setpayloadf128 as unsafe extern "C" fn(*mut f128, f128) -> c_int, ma::setpayloadf128 as unsafe extern "C" fn(*mut f128, f128) -> c_int),
            ("setpayloadsig", setpayloadsigf128, ma::setpayloadsigf128),
        ] {
            let mut gr: f128 = 7.0;
            let mut fr: f128 = 7.0;
            let grc = unsafe { gf(&mut gr, pl) };
            let frc = unsafe { ff(&mut fr, pl) };
            if grc != frc || gr.to_bits() != fr.to_bits() {
                mism.push(format!("{name} pl={:#034x}: glibc=(rc={grc},res={:#034x}) fl=(rc={frc},res={:#034x})", pl.to_bits(), gr.to_bits(), fr.to_bits()));
            }
        }
    }
    assert!(mism.is_empty(), "f128 setpayload diverged ({}):\n{}", mism.len(), mism.join("\n"));
}
