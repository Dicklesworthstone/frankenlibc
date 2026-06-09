#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc gcvt/ecvt/fcvt oracle

//! `gcvt`/`ecvt`/`fcvt` special-value parity vs host glibc (bd-2g7oyh.NEW).
//!
//! gcvt's NaN branch dropped the sign bit (returned "nan" for a negative NaN),
//! diverging from glibc's `%g`, which renders "-nan". This gate compares the
//! rendered string (and ecvt/fcvt's decpt/sign out-params) for NaN/-NaN/±inf
//! and signed zero, across a few precisions — the inputs the gcvt/ecvt fuzzers
//! never randomly generate.

use std::ffi::{CStr, CString, c_char, c_int};
use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn gcvt(v: f64, n: c_int, b: *mut c_char) -> *mut c_char;
    fn ecvt(v: f64, n: c_int, dp: *mut c_int, sg: *mut c_int) -> *mut c_char;
    fn fcvt(v: f64, n: c_int, dp: *mut c_int, sg: *mut c_int) -> *mut c_char;
}

fn gcvt_str(eng: u8, v: f64, n: c_int) -> String {
    let mut b = [0i8; 64];
    let r = if eng == 0 {
        unsafe { fl::gcvt(v, n, b.as_mut_ptr()) }
    } else {
        unsafe { gcvt(v, n, b.as_mut_ptr()) }
    };
    if r.is_null() {
        "<null>".into()
    } else {
        unsafe { CStr::from_ptr(b.as_ptr()) }.to_string_lossy().into_owned()
    }
}

fn ecvt_tuple(eng: u8, v: f64, n: c_int, fcvt_kind: bool) -> (String, c_int, c_int) {
    let mut dp: c_int = -99;
    let mut sg: c_int = -99;
    let r = match (eng, fcvt_kind) {
        (0, false) => unsafe { fl::ecvt(v, n, &mut dp, &mut sg) },
        (0, true) => unsafe { fl::fcvt(v, n, &mut dp, &mut sg) },
        (_, false) => unsafe { ecvt(v, n, &mut dp, &mut sg) },
        (_, true) => unsafe { fcvt(v, n, &mut dp, &mut sg) },
    };
    let s = if r.is_null() {
        "<null>".into()
    } else {
        unsafe { CStr::from_ptr(r) }.to_string_lossy().into_owned()
    };
    (s, dp, sg)
}

#[test]
fn cvt_special_values_match_glibc() {
    let vals: &[(&str, f64)] = &[
        ("nan", f64::NAN),
        ("-nan", -f64::NAN),
        ("inf", f64::INFINITY),
        ("-inf", f64::NEG_INFINITY),
        ("-0", -0.0),
        ("0", 0.0),
    ];

    for (nm, v) in vals {
        for n in [6, 17, 1, 0] {
            assert_eq!(
                gcvt_str(0, *v, n),
                gcvt_str(1, *v, n),
                "gcvt({nm}, {n})"
            );
        }
        for n in [5, 1] {
            assert_eq!(
                ecvt_tuple(0, *v, n, false),
                ecvt_tuple(1, *v, n, false),
                "ecvt({nm}, {n})"
            );
        }
        for n in [3, 0] {
            assert_eq!(
                ecvt_tuple(0, *v, n, true),
                ecvt_tuple(1, *v, n, true),
                "fcvt({nm}, {n})"
            );
        }
    }
}
