//! Differential gate: fl's strfromf128 matches glibc byte-for-byte (bd-trosmi).
//!
//! strfrom's format grammar is restricted to `%[.precision]CONV` (CONV in
//! a/A/e/E/f/F/g/G) — no flags, no width (glibc aborts on those, which the C
//! standard leaves undefined). We compare fl (the Rust symbol; debug build is
//! not no_mangle) against the linked glibc strfromf128 over that grammar.
#![cfg(target_os = "linux")]
#![feature(f128)]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{CStr, c_char, c_int};

unsafe extern "C" {
    fn strfromf128(s: *mut c_char, n: usize, f: *const c_char, v: f128) -> c_int;
}

const N: usize = 70000; // large enough for %f of extreme magnitudes

fn glibc(v: f128, fmt: &CStr) -> (c_int, String) {
    let mut b = vec![0u8; N];
    let rc = unsafe { strfromf128(b.as_mut_ptr() as *mut c_char, N, fmt.as_ptr(), v) };
    let s = CStr::from_bytes_until_nul(&b).unwrap().to_str().unwrap().to_string();
    (rc, s)
}
fn frank(v: f128, fmt: &CStr) -> (c_int, String) {
    let mut b = vec![0u8; N];
    let rc = unsafe { fl::strfromf128(b.as_mut_ptr() as *mut c_char, N, fmt.as_ptr(), v) };
    let s = CStr::from_bytes_until_nul(&b).unwrap().to_str().unwrap().to_string();
    (rc, s)
}

/// Bounded-magnitude values: safe for the full format set incl %f.
fn moderate_values() -> Vec<f128> {
    let mut v: Vec<f128> = vec![
        0.0, -0.0f128, 1.0, -1.0, 2.0, 0.5, 0.25, 3.0, 10.0, 100.0, 1024.0, 0.1, -0.1, 2.5, -2.5,
        123456.789f128, 1.0f128 / 3.0, 2.0f128 / 3.0, 9.99999f128, 99999.5f128, 0.0009765625f128,
        1e10f128, 1e-10f128, 1234.5678f128, 0.000123f128, 999999.5f128, 0.5e-5f128,
    ];
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..24 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let hi = state;
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let lo = state;
        let mantissa = (((hi as u128) << 64) | lo as u128) & ((1u128 << 112) - 1);
        let ef = 0x3fc0u128 + (hi as u128 % 0x80);
        let sign = (lo >> 7) as u128 & 1;
        v.push(f128::from_bits((sign << 127) | (ef << 112) | mantissa));
    }
    v
}

/// Extreme values: only formats with bounded output length (%e/%g/%a).
fn extreme_values() -> Vec<f128> {
    vec![
        f128::from_bits(1),                                     // smallest subnormal 2^-16494
        f128::from_bits(0x1234),                                // small subnormal
        f128::from_bits(1u128 << 112),                          // smallest normal 2^-16382
        f128::from_bits(0x7ffe_u128 << 112),                    // near-largest finite
        f128::from_bits(0x7fff_u128 << 112),                    // +inf
        f128::from_bits(0xffff_u128 << 112),                    // -inf
        f128::from_bits((0x7fff_u128 << 112) | (1u128 << 111)), // qNaN
        f128::from_bits((0x7fff_u128 << 112) | 1),              // sNaN
    ]
}

fn check(values: &[f128], fmts: &[&CStr], mism: &mut Vec<String>) {
    for &v in values {
        for fmt in fmts {
            let g = glibc(v, fmt);
            let f = frank(v, fmt);
            if g != f {
                mism.push(format!(
                    "fmt={:?} bits={:#034x}: glibc=({},{:?}) fl=({},{:?})",
                    fmt.to_str().unwrap(),
                    v.to_bits(),
                    g.0,
                    g.1,
                    f.0,
                    f.1
                ));
                if mism.len() > 60 {
                    return;
                }
            }
        }
    }
}

#[test]
fn strfromf128_matches_glibc() {
    // strfrom grammar: %[.precision]CONV only.
    let full: &[&CStr] = &[
        c"%a", c"%A", c"%.0a", c"%.1a", c"%.5a", c"%.13a", c"%.28a", c"%.40a", c"%e", c"%E",
        c"%.0e", c"%.1e", c"%.15e", c"%.33e", c"%.40e", c"%f", c"%F", c"%.0f", c"%.2f", c"%.20f",
        c"%g", c"%G", c"%.0g", c"%.1g", c"%.6g", c"%.17g", c"%.33g", c"%.40g",
    ];
    let bounded: &[&CStr] = &[
        c"%a", c"%A", c"%.10a", c"%e", c"%.0e", c"%.20e", c"%.40e", c"%g", c"%.30g", c"%.0g",
    ];
    let mut mism = Vec::new();
    check(&moderate_values(), full, &mut mism);
    check(&extreme_values(), bounded, &mut mism);
    assert!(mism.is_empty(), "strfromf128 diverged ({}):\n{}", mism.len(), mism.join("\n"));
}
