#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strfmon_l oracle

//! Differential gate for strfmon_l (bd-a6kkvc) — previously fl-internal only.
//! strfmon_l(s, max, locale, fmt, ...) inserts a locale_t before the format,
//! then formats monetary values. fl is C-locale-only (it accepts and ignores
//! the locale_t), so this gate uses a "C" locale_t — where glibc's output also
//! follows the C monetary convention — and asserts byte-for-byte equality. This
//! pins the locale_t ABI (correct argument order / varargs after the locale)
//! and the C-locale formatting/return value. No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn newlocale(mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
        pub fn freelocale(loc: *mut c_void);
        pub fn strfmon_l(
            s: *mut c_char,
            max: usize,
            loc: *mut c_void,
            fmt: *const c_char,
            ...
        ) -> isize;
    }
}
use frankenlibc_abi::{locale_abi as fll, unistd_abi as flu};

fn run_glibc(fmt: &str, v: f64) -> (isize, Vec<u8>) {
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0u8; 128];
    unsafe {
        let loc = g::newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut());
        let n = g::strfmon_l(buf.as_mut_ptr() as *mut c_char, 128, loc, cf.as_ptr(), v);
        g::freelocale(loc);
        let bytes = if n >= 0 {
            buf[..n as usize].to_vec()
        } else {
            Vec::new()
        };
        (n, bytes)
    }
}

fn run_fl(fmt: &str, v: f64) -> (isize, Vec<u8>) {
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0u8; 128];
    unsafe {
        let loc = fll::newlocale(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut());
        let n = flu::strfmon_l(
            buf.as_mut_ptr() as *mut c_char,
            128,
            loc as *mut c_void,
            cf.as_ptr(),
            v,
        );
        fll::freelocale(loc);
        let bytes = if n >= 0 {
            buf[..n as usize].to_vec()
        } else {
            Vec::new()
        };
        (n, bytes)
    }
}

#[test]
fn strfmon_l_c_locale_matches_glibc() {
    let cases: &[(&str, f64)] = &[
        ("%n", 1234.567),
        ("%i", 1234.567),
        ("%n", -1234.567),
        ("%.2n", 9.999),
        ("%.0n", 12.5),
        ("%#6n", 5.0),
        ("%=*#6n", 12.34),
        ("%^n", 1000000.0),
        ("%(n", -42.0),
        ("%!n", 7.5),
        ("cost: %n done", 3.0),
    ];
    for &(fmt, v) in cases {
        let g = run_glibc(fmt, v);
        let f = run_fl(fmt, v);
        assert_eq!(
            f,
            g,
            "strfmon_l({fmt:?}, {v}): fl=({}, {:?}) glibc=({}, {:?})",
            f.0,
            String::from_utf8_lossy(&f.1),
            g.0,
            String::from_utf8_lossy(&g.1),
        );
    }
}
