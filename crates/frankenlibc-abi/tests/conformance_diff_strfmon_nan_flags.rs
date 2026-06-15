//! Differential gate for strfmon NaN rendering and duplicate +/( flag rejection.
//!
//! Two bugs this pins (confirmed vs host glibc 2.42, C locale):
//!  1. NaN rendered as Rust's "NaN" and dropped its sign; glibc renders "nan"
//!     with a leading '-' iff the NaN's sign bit is set ("%n" of -nan -> "-nan",
//!     "%(n" of -nan -> "-nan", never parenthesised). Field width still applies.
//!  2. A repeated '+' or '(' flag must make strfmon fail (-1 / EINVAL); fl
//!     accepted them. Duplicate '=', '^', '!', '-' are allowed by glibc.
//!
//! fl is called via its Rust path; glibc via dlsym on libc.so.6 (bypassing fl's
//! no_mangle interposition). Note: glibc's left/right-precision interaction with
//! NaN uses an internal numeric-width computation not mirrored by fl, so those
//! combos (e.g. "%#8n", "%.4n") are intentionally NOT compared here.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}
type StrfmonFn =
    unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> isize;

fn sym(h: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing libc symbol {name:?}");
    p
}

fn fl_call(fmt: &CStr, v: f64) -> (isize, String) {
    let mut buf = [0 as c_char; 128];
    let n = unsafe { fl::strfmon(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), v) };
    let s = if n < 0 {
        String::new()
    } else {
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
    };
    (n, s)
}
fn g_call(g: StrfmonFn, fmt: &CStr, v: f64) -> (isize, String) {
    let mut buf = [0 as c_char; 128];
    let n = unsafe { g(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), v) };
    let s = if n < 0 {
        String::new()
    } else {
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
    };
    (n, s)
}

#[test]
fn strfmon_nan_and_dup_flags_match_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C".as_ptr()) };
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let g: StrfmonFn = unsafe { core::mem::transmute(sym(h, c"strfmon")) };

    let pnan = f64::NAN;
    let nnan = -f64::NAN;
    let cases: &[(&CStr, f64)] = &[
        // NaN rendering (no precision flags)
        (c"%n", pnan),
        (c"%n", nnan),
        (c"%(n", pnan),
        (c"%(n", nnan),
        (c"%10n", pnan),
        (c"%10n", nnan),
        (c"%-10n", nnan),
        (c"%011n", nnan),
        // inf (already correct — regression guard)
        (c"%n", f64::INFINITY),
        (c"%n", f64::NEG_INFINITY),
        (c"%(n", f64::NEG_INFINITY),
        // duplicate-flag rejection
        (c"%((n", -5.0),
        (c"%++n", -5.0),
        (c"%(+n", -5.0),
        // duplicates that glibc ALLOWS (must NOT start failing)
        (c"%--n", -5.0),
        (c"%^^n", 5.0),
        (c"%!!n", 5.0),
        // sanity: ordinary values still match
        (c"%n", 1234.5),
        (c"%(n", -1234.5),
    ];

    let mut div = Vec::new();
    for (fmt, v) in cases {
        let (fn_, fs) = fl_call(fmt, *v);
        let (gn, gs) = g_call(g, fmt, *v);
        let f_ok = fn_ >= 0;
        let g_ok = gn >= 0;
        if f_ok != g_ok || (g_ok && fs != gs) {
            div.push(format!(
                "{:?}({v}): fl=({fn_},{fs:?}) glibc=({gn},{gs:?})",
                fmt.to_str().unwrap()
            ));
        }
    }
    assert!(div.is_empty(), "strfmon divergences ({}):\n  {}", div.len(), div.join("\n  "));
}
