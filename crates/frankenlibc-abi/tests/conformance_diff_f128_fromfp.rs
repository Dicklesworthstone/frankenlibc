//! Differential gate: f128 fromfp/ufromfp/fromfpx/ufromfpx match glibc on value
//! and errno across rounding direction x width x value (bd-9z5ikz batch 11).
//! Previously broken f64 ABI. (FE_INEXACT, which only fromfpx/ufromfpx raise, is
//! not gated — value and errno are the checked contract.)
//!
//! The host arm is dlvsym-pinned to @GLIBC_2.26, NOT the default version:
//! glibc 2.43 re-cut the family so `fromfpf128@@GLIBC_2.43` returns its result
//! in the FLOATING argument's type (XMM0), while the 2.26 compat symbols keep
//! the intmax_t-in-RAX contract this gate pins and fl ships. A link-time or
//! plain-dlsym arm binds the 2.43 default and reads a stale integer register —
//! measured 2026-09-14 as fromfp(+0.0, r, w) = 4294950913 across 7801 tuples
//! (bd-7ilguh). The pin is what makes the arm an oracle again.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::math_abi as ma;
use std::ffi::{CStr, c_int, c_uint};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type FromFpF128 = unsafe extern "C" fn(f128, c_int, c_uint) -> i64;
type UFromFpF128 = unsafe extern "C" fn(f128, c_int, c_uint) -> u64;

/// Host arm, resolved once per test at the pinned compat version.
struct HostF128 {
    fromfp: unsafe extern "C" fn(f128, c_int, c_uint) -> i64,
    ufromfp: unsafe extern "C" fn(f128, c_int, c_uint) -> u64,
    fromfpx: unsafe extern "C" fn(f128, c_int, c_uint) -> i64,
    ufromfpx: unsafe extern "C" fn(f128, c_int, c_uint) -> u64,
}

fn host() -> HostF128 {
    // SAFETY: each pointer is resolved with the exact prototype applied at its
    // call sites below; `host_fn_versioned` aborts if the pinned version is
    // missing rather than silently degrading.
    unsafe {
        HostF128 {
            fromfp: dlsym_oracle::host_fn_versioned(
                CStr::from_bytes_with_nul(b"fromfpf128\0").unwrap(),
                CStr::from_bytes_with_nul(b"GLIBC_2.26\0").unwrap(),
                ma::fromfpf128 as *const (),
            ),
            ufromfp: dlsym_oracle::host_fn_versioned(
                CStr::from_bytes_with_nul(b"ufromfpf128\0").unwrap(),
                CStr::from_bytes_with_nul(b"GLIBC_2.26\0").unwrap(),
                ma::ufromfpf128 as *const (),
            ),
            fromfpx: dlsym_oracle::host_fn_versioned(
                CStr::from_bytes_with_nul(b"fromfpxf128\0").unwrap(),
                CStr::from_bytes_with_nul(b"GLIBC_2.26\0").unwrap(),
                ma::fromfpxf128 as *const (),
            ),
            ufromfpx: dlsym_oracle::host_fn_versioned(
                CStr::from_bytes_with_nul(b"ufromfpxf128\0").unwrap(),
                CStr::from_bytes_with_nul(b"GLIBC_2.26\0").unwrap(),
                ma::ufromfpxf128 as *const (),
            ),
        }
    }
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
    let h = host();
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
                        h.fromfp as FromFpF128,
                        ma::fromfpf128 as FromFpF128,
                    ),
                    (
                        "fromfpx",
                        h.fromfpx as FromFpF128,
                        ma::fromfpxf128 as FromFpF128,
                    ),
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
                        h.ufromfp as UFromFpF128,
                        ma::ufromfpf128 as UFromFpF128,
                    ),
                    (
                        "ufromfpx",
                        h.ufromfpx as UFromFpF128,
                        ma::ufromfpxf128 as UFromFpF128,
                    ),
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
