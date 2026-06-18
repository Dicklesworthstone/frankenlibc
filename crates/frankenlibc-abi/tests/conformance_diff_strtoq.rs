#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strtoq/strtouq oracle

//! Differential gate for the BSD quad parsers strtoq/strtouq (bd-rhvi3w) —
//! previously uncovered. They are quad_t/u_quad_t aliases of strtoll/strtoull.
//! For each (input, base) fl must match host glibc on the value, the endptr
//! consumed-length, AND errno (ERANGE on overflow). No mocks.

use std::ffi::{c_char, c_int, c_long, c_ulong, CString};

unsafe extern "C" {
    fn strtoq(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_long;
    fn strtouq(nptr: *const c_char, endptr: *mut *mut c_char, base: c_int) -> c_ulong;
    fn __errno_location() -> *mut c_int;
}

fn consumed(end: *mut c_char, base: *const c_char) -> isize {
    (end as isize) - (base as isize)
}

#[test]
fn strtoq_matches_glibc() {
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("  -42xyz", 10),
        ("0x1F", 16),
        ("777", 8),
        ("0", 0),
        ("0x7fffffffffffffff", 0),
        ("abc", 10),
        ("9223372036854775808", 10),  // LLONG_MAX + 1 -> ERANGE
        ("-9223372036854775809", 10), // LLONG_MIN - 1 -> ERANGE
        ("+100", 10),
        ("z", 36),
    ];
    for &(s, base) in cases {
        let c = CString::new(s).unwrap();
        let mut ge: *mut c_char = std::ptr::null_mut();
        let mut fe: *mut c_char = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { strtoq(c.as_ptr(), &mut ge, base) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe { frankenlibc_abi::stdlib_abi::strtoq(c.as_ptr(), &mut fe, base) };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "strtoq({s:?},{base}) value");
        assert_eq!(consumed(fe, c.as_ptr()), consumed(ge, c.as_ptr()), "strtoq({s:?}) endptr");
        assert_eq!(ferr, gerr, "strtoq({s:?}) errno: fl={ferr} glibc={gerr}");
    }
}

#[test]
fn strtouq_matches_glibc() {
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("0xFFFFFFFFFFFFFFFF", 0),
        ("-1", 10), // strtoul wraparound semantics
        ("18446744073709551616", 10), // ULLONG_MAX + 1 -> ERANGE
        ("  99", 10),
        ("zz", 36),
        ("abc", 16),
    ];
    for &(s, base) in cases {
        let c = CString::new(s).unwrap();
        let mut ge: *mut c_char = std::ptr::null_mut();
        let mut fe: *mut c_char = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { strtouq(c.as_ptr(), &mut ge, base) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe { frankenlibc_abi::stdlib_abi::strtouq(c.as_ptr(), &mut fe, base) };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "strtouq({s:?},{base}) value");
        assert_eq!(consumed(fe, c.as_ptr()), consumed(ge, c.as_ptr()), "strtouq({s:?}) endptr");
        assert_eq!(ferr, gerr, "strtouq({s:?}) errno: fl={ferr} glibc={gerr}");
    }
}
