#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsto*_l oracle

//! Differential gate for the wide-parser locale variants wcstol_l/wcstoul_l/
//! wcstoll_l/wcstoull_l (bd-j21cpb) — previously uncovered. With a "C" locale
//! they parse exactly like wcstol/etc. fl delegates to the base parsers; for
//! each wide input + base fl must match host glibc on value, endptr consumed-
//! length (in wide chars), and errno. No mocks.

use std::ffi::{CString, c_char, c_int, c_long, c_ulong, c_void};

use libc::wchar_t;

unsafe extern "C" {
    fn wcstol_l(p: *const wchar_t, e: *mut *mut wchar_t, b: c_int, l: *mut c_void) -> c_long;
    fn wcstoul_l(p: *const wchar_t, e: *mut *mut wchar_t, b: c_int, l: *mut c_void) -> c_ulong;
    fn wcstoll_l(p: *const wchar_t, e: *mut *mut wchar_t, b: c_int, l: *mut c_void) -> i64;
    fn wcstoull_l(p: *const wchar_t, e: *mut *mut wchar_t, b: c_int, l: *mut c_void) -> u64;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
    fn __errno_location() -> *mut c_int;
}

fn wide(s: &str) -> Vec<wchar_t> {
    s.chars()
        .map(|c| c as wchar_t)
        .chain(std::iter::once(0))
        .collect()
}
fn consumed(end: *mut wchar_t, base: *const wchar_t) -> isize {
    (end as isize - base as isize) / std::mem::size_of::<wchar_t>() as isize
}

const SIGNED_CASES: &[(&str, c_int)] = &[
    ("123", 10),
    ("  -42xy", 10),
    ("0x1F", 16),
    ("777", 8),
    ("0", 0),
    ("abc", 10),
    ("9223372036854775808", 10), // overflow
    ("-9223372036854775809", 10),
];
const UNSIGNED_CASES: &[(&str, c_int)] = &[
    ("123", 10),
    ("0xFFFFFFFFFFFFFFFF", 0),
    ("-1", 10),
    ("18446744073709551616", 10), // overflow
    ("zz", 36),
];

#[test]
fn wcstol_l_family_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());

    for &(s, base) in SIGNED_CASES {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstol_l(w.as_ptr(), &mut ge, base, loc) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstol_l(w.as_ptr(), &mut fe, base, loc as *mut c_void)
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstol_l({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstol_l({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstol_l({s:?}) errno");

        // wcstoll_l (i64) — same i64 width on x86-64.
        let mut ge2: *mut wchar_t = std::ptr::null_mut();
        let mut fe2: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g2 = unsafe { wcstoll_l(w.as_ptr(), &mut ge2, base, loc) };
        let _ = unsafe { *__errno_location() };
        let f2 = unsafe {
            frankenlibc_abi::wchar_abi::wcstoll_l(w.as_ptr(), &mut fe2, base, loc as *mut c_void)
        };
        assert_eq!(f2, g2, "wcstoll_l({s:?},{base}) value");
    }

    for &(s, base) in UNSIGNED_CASES {
        let w = wide(s);
        let mut ge: *mut wchar_t = std::ptr::null_mut();
        let mut fe: *mut wchar_t = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { wcstoul_l(w.as_ptr(), &mut ge, base, loc) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::wchar_abi::wcstoul_l(w.as_ptr(), &mut fe, base, loc as *mut c_void)
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "wcstoul_l({s:?},{base}) value");
        assert_eq!(
            consumed(fe, w.as_ptr()),
            consumed(ge, w.as_ptr()),
            "wcstoul_l({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "wcstoul_l({s:?}) errno");

        let mut ge2: *mut wchar_t = std::ptr::null_mut();
        let mut fe2: *mut wchar_t = std::ptr::null_mut();
        let g2 = unsafe { wcstoull_l(w.as_ptr(), &mut ge2, base, loc) };
        let f2 = unsafe {
            frankenlibc_abi::wchar_abi::wcstoull_l(w.as_ptr(), &mut fe2, base, loc as *mut c_void)
        };
        assert_eq!(f2, g2, "wcstoull_l({s:?},{base}) value");
    }
    unsafe { freelocale(loc) };
}
