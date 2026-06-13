#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc classification oracle

//! IEEE-754 classification helper parity vs host glibc (bd-2g7oyh.NEW —
//! coverage). `__fpclassify`/`__fpclassifyf`, `__isinf` (signed +1/-1/0),
//! `__isnan`, `__finite` and `__issignaling` had no vs-glibc differential.
//! This gate compares them across every special class — signed zero, signed
//! infinity, quiet/signalling NaN (both signs), the smallest subnormal, and
//! normals — against the live host.
//!
//! `__signbit` is intentionally compared only for BOOLEAN agreement: the C
//! `signbit` macro a program actually uses expands to `__builtin_signbit`
//! (0/1), while glibc's `__signbit` *function* returns an unspecified internal
//! value (128 for double, 8 for float); fl returns 1, matching the builtin. The
//! exact nonzero value is unspecified, so only "negative <=> nonzero" is pinned.

use frankenlibc_abi::math_abi as fl;

unsafe extern "C" {
    fn __fpclassify(x: f64) -> i32;
    fn __fpclassifyf(x: f32) -> i32;
    fn __isinf(x: f64) -> i32;
    fn __isnan(x: f64) -> i32;
    fn __finite(x: f64) -> i32;
    fn __issignaling(x: f64) -> i32;
    fn __signbit(x: f64) -> i32;
}

#[test]
fn fpclassify_family_matches_glibc() {
    let qnan = f64::from_bits(0x7FF8_0000_0000_0000);
    let snan = f64::from_bits(0x7FF0_0000_0000_0001);
    let nqnan = f64::from_bits(0xFFF8_0000_0000_0000);
    let nsnan = f64::from_bits(0xFFF0_0000_0000_0001);
    let subn = f64::from_bits(1);
    let nsubn = f64::from_bits(0x8000_0000_0000_0001);

    let vals: &[(&str, f64)] = &[
        ("+0", 0.0),
        ("-0", -0.0),
        ("1", 1.0),
        ("-1", -1.0),
        ("inf", f64::INFINITY),
        ("-inf", f64::NEG_INFINITY),
        ("qnan", qnan),
        ("snan", snan),
        ("-qnan", nqnan),
        ("-snan", nsnan),
        ("subn", subn),
        ("-subn", nsubn),
        ("max", f64::MAX),
        ("min_norm", f64::MIN_POSITIVE),
    ];

    for (nm, v) in vals {
        assert_eq!(
            unsafe { fl::__fpclassify(*v) },
            unsafe { __fpclassify(*v) },
            "__fpclassify {nm}"
        );
        assert_eq!(
            unsafe { fl::__fpclassifyf(*v as f32) },
            unsafe { __fpclassifyf(*v as f32) },
            "__fpclassifyf {nm}"
        );
        assert_eq!(
            unsafe { fl::__isinf(*v) },
            unsafe { __isinf(*v) },
            "__isinf {nm}"
        );
        assert_eq!(
            unsafe { fl::__isnan(*v) },
            unsafe { __isnan(*v) },
            "__isnan {nm}"
        );
        assert_eq!(
            unsafe { fl::__finite(*v) },
            unsafe { __finite(*v) },
            "__finite {nm}"
        );
        assert_eq!(
            unsafe { fl::__issignaling(*v) },
            unsafe { __issignaling(*v) },
            "__issignaling {nm}"
        );
        // signbit: boolean agreement only (exact nonzero value is unspecified).
        let fl_sb = unsafe { fl::__signbit(*v) } != 0;
        let gl_sb = unsafe { __signbit(*v) } != 0;
        assert_eq!(fl_sb, gl_sb, "__signbit (sign) {nm}");
    }
}
