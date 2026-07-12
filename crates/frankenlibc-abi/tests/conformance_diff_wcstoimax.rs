#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstoimax/wcstoumax oracle

//! Differential gate for wide intmax parsers wcstoimax/wcstoumax (bd-sc6pfb) —
//! previously uncovered (the wcstol-family fuzz covers wcstol/ll/ul/ull but not
//! these). For each wide input + base, fl must match host glibc on the value,
//! the endptr consumed-length (in wide chars), and errno (ERANGE on overflow).
//! No mocks.

use std::ffi::c_int;

use libc::wchar_t;

unsafe extern "C" {
    fn wcstoimax(nptr: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> i64;
    fn wcstoumax(nptr: *const wchar_t, endptr: *mut *mut wchar_t, base: c_int) -> u64;
    fn __errno_location() -> *mut c_int;
}

fn wide(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

fn consumed(end: *mut wchar_t, base: *const wchar_t) -> isize {
    (end as isize - base as isize) / std::mem::size_of::<wchar_t>() as isize
}

#[test]
fn wcstoimax_matches_glibc() {
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("  -42xy", 10),
        ("0x1F", 16),
        ("777", 8),
        ("0", 0),
        ("abc", 10),
        ("9223372036854775808", 10),  // overflow -> ERANGE
        ("-9223372036854775809", 10), // underflow -> ERANGE
        ("+7", 10),
    ];
    for &(s, base) in cases {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstoimax(w.as_ptr(), &mut ge, base) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstoimax(
                w.as_ptr() as *const u32,
                &mut fe as *mut *mut wchar_t as *mut *mut u32,
                base,
            )
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstoimax({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstoimax({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstoimax({s:?}) errno: fl={ferr} glibc={gerr}");
    }
}

#[test]
fn wcstoumax_matches_glibc() {
    let cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("0xFFFFFFFFFFFFFFFF", 0),
        ("-1", 10),                   // wraparound
        ("18446744073709551616", 10), // overflow -> ERANGE
        ("zz", 36),
    ];
    for &(s, base) in cases {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstoumax(w.as_ptr(), &mut ge, base) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstoumax(
                w.as_ptr() as *const u32,
                &mut fe as *mut *mut wchar_t as *mut *mut u32,
                base,
            )
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstoumax({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstoumax({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstoumax({s:?}) errno: fl={ferr} glibc={gerr}");
    }
}
