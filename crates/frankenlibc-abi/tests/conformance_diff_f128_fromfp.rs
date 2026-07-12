//! Differential gate: f128 fromfp/ufromfp/fromfpx/ufromfpx match glibc on value
//! and errno across rounding direction x width x value (bd-9z5ikz batch 11).
//! Previously broken f64 ABI. (FE_INEXACT, which only fromfpx/ufromfpx raise, is
//! not gated — value and errno are the checked contract.)
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{c_int, c_uint};

unsafe extern "C" {
    fn fromfpf128(x: f128, r: c_int, w: c_uint) -> i64;
    fn ufromfpf128(x: f128, r: c_int, w: c_uint) -> u64;
    fn fromfpxf128(x: f128, r: c_int, w: c_uint) -> i64;
    fn ufromfpxf128(x: f128, r: c_int, w: c_uint) -> u64;
}
fn el() -> *mut c_int {
    unsafe { libc::__errno_location() }
}

fn values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0,
        -0.0f128,
        0.5,
        -0.5,
        1.5,
        2.5,
        -2.5,
        3.5,
        1.0,
        -1.0,
        2.4,
        2.6,
        -2.4,
        -2.6,
        7.0,
        -8.0,
        8.0,
        -9.0,
        15.0,
        16.0,
        100.0,
        -100.0,
        1e30f128,
        -1e30f128,
        9223372036854775807.0f128,
        9223372036854775808.0f128,
        -9223372036854775808.0f128,
        f128::from_bits(0x7fff_u128 << 112), // +inf
        f128::from_bits(0xffff_u128 << 112), // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
    ];
    let mut st: u64 = 0xfeed_face_cafe_babe;
    for _ in 0..16 {
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let hi = st;
        st = st
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let ef = 0x3fe0u128 + (hi as u128 % 0x60);
        let mant = (((hi as u128) << 64) | st as u128) & ((1u128 << 112) - 1);
        v.push(f128::from_bits(
            ((hi as u128 >> 11 & 1) << 127) | (ef << 112) | mant,
        ));
    }
    v
}

#[test]
fn f128_fromfp_match_glibc() {
    let vals = values();
    let widths: &[c_uint] = &[0, 1, 2, 3, 4, 8, 16, 32, 63, 64, 65, 100];
    let mut mism = Vec::new();
    for &x in &vals {
        for &r in &[0i32, 1, 2, 3, 4] {
            for &w in widths {
                // signed fromfp / fromfpx
                for (name, gf, ff) in [
                    (
                        "fromfp",
                        fromfpf128 as unsafe extern "C" fn(f128, c_int, c_uint) -> i64,
                        ma::fromfpf128 as unsafe extern "C" fn(f128, c_int, c_uint) -> i64,
                    ),
                    ("fromfpx", fromfpxf128, ma::fromfpxf128),
                ] {
                    unsafe { *el() = 0 };
                    let g = unsafe { gf(x, r, w) };
                    let ge = unsafe { *el() };
                    unsafe { *el() = 0 };
                    let f = unsafe { ff(x, r, w) };
                    let fe = unsafe { *el() };
                    if g != f || ge != fe {
                        mism.push(format!(
                            "{name} x={:#034x} r={r} w={w}: glibc=({g},e={ge}) fl=({f},e={fe})",
                            x.to_bits()
                        ));
                    }
                }
                // unsigned ufromfp / ufromfpx
                for (name, gf, ff) in [
                    (
                        "ufromfp",
                        ufromfpf128 as unsafe extern "C" fn(f128, c_int, c_uint) -> u64,
                        ma::ufromfpf128 as unsafe extern "C" fn(f128, c_int, c_uint) -> u64,
                    ),
                    ("ufromfpx", ufromfpxf128, ma::ufromfpxf128),
                ] {
                    unsafe { *el() = 0 };
                    let g = unsafe { gf(x, r, w) };
                    let ge = unsafe { *el() };
                    unsafe { *el() = 0 };
                    let f = unsafe { ff(x, r, w) };
                    let fe = unsafe { *el() };
                    if g != f || ge != fe {
                        mism.push(format!(
                            "{name} x={:#034x} r={r} w={w}: glibc=({g},e={ge}) fl=({f},e={fe})",
                            x.to_bits()
                        ));
                    }
                }
            }
        }
    }
    assert!(
        mism.is_empty(),
        "f128 fromfp diverged ({}):\n{}",
        mism.len(),
        mism.iter().take(30).cloned().collect::<Vec<_>>().join("\n")
    );
}
