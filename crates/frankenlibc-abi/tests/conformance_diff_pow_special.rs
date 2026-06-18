#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pow oracle

//! Differential gate for the C99 (Annex F.10.4.4) pow special cases where an
//! exact result OVERRIDES a NaN/inf operand (bd-fw8koo). The pole cases
//! (0^neg -> DIVBYZERO) are already covered by conformance_diff_fp_exceptions;
//! the identity cases below were not in any committed gate. These are the
//! classic naive-impl trap: a from-scratch pow that does exp(y*log(x)) returns
//! NaN for pow(1,NaN) / pow(NaN,0) instead of the standard-mandated 1.0.
//!
//!   pow(+1, y)   == 1  for ANY y, including NaN and +/-inf
//!   pow(x, +/-0) == 1  for ANY x, including NaN and +/-inf
//!   pow(-1, +/-inf) == 1
//!   pow(+/-inf, 0) == 1
//! plus the contrast cases that DO propagate NaN (pow(2,NaN), pow(NaN,2)).
//! fl must match host glibc bit-for-bit (NaN-aware). No mocks.

use std::ffi::c_double;

unsafe extern "C" {
    fn pow(x: c_double, y: c_double) -> c_double;
    fn powf(x: f32, y: f32) -> f32;
}

fn same64(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

const N: f64 = f64::NAN;
const I: f64 = f64::INFINITY;

// (x, y) pairs spanning the identity-overrides and NaN-propagation rules.
const CASES: &[(f64, f64)] = &[
    // pow(1, y) == 1 for any y
    (1.0, N),
    (1.0, I),
    (1.0, -I),
    (1.0, 0.0),
    (1.0, 42.0),
    // pow(x, 0) == 1 for any x
    (N, 0.0),
    (N, -0.0),
    (I, 0.0),
    (-I, -0.0),
    (0.0, 0.0),
    (-0.0, 0.0),
    (-5.0, 0.0),
    (123.0, -0.0),
    // pow(-1, +/-inf) == 1
    (-1.0, I),
    (-1.0, -I),
    // pow(+/-inf, y)
    (I, 2.0),
    (I, -2.0),
    (-I, 3.0),
    // NaN propagation (NOT overridden)
    (2.0, N),
    (N, 2.0),
    (N, N),
    // a few finite sanity points
    (2.0, 10.0),
    (-2.0, 3.0),
    (4.0, 0.5),
];

#[test]
fn pow_special_cases_match_glibc() {
    for &(x, y) in CASES {
        let g = unsafe { pow(x, y) };
        let f = unsafe { frankenlibc_abi::math_abi::pow(x, y) };
        assert!(same64(f, g), "pow({x:?},{y:?}): fl={f:?} (bits {:#018x}) glibc={g:?} (bits {:#018x})", f.to_bits(), g.to_bits());
    }
}

#[test]
fn powf_special_cases_match_glibc() {
    for &(x, y) in CASES {
        let (xf, yf) = (x as f32, y as f32);
        let g = unsafe { powf(xf, yf) };
        let f = unsafe { frankenlibc_abi::math_abi::powf(xf, yf) };
        assert!(same32(f, g), "powf({xf:?},{yf:?}): fl={f:?} glibc={g:?}");
    }
}
