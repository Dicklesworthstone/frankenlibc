#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strto*_l oracle

//! Differential gate for the narrow locale-variant parsers strtoul_l/strtoll_l/
//! strtoull_l/strtof_l (bd-5tfsva). conformance_diff_locale_l_variants covers
//! strtol_l + strtod_l; these four were uncovered. With a "C" locale_t they
//! parse like the base functions; fl must match host glibc on value, endptr
//! consumed-length, and errno (ERANGE on overflow; fl mirrors errno to the host
//! slot in non-standalone builds). strtof_l compared bit-for-bit (NaN-aware).
//! No mocks.

use std::ffi::{CString, c_char, c_int, c_long, c_longlong, c_ulong, c_ulonglong, c_void};

unsafe extern "C" {
    fn strtoul_l(p: *const c_char, e: *mut *mut c_char, b: c_int, l: *mut c_void) -> c_ulong;
    fn strtoll_l(p: *const c_char, e: *mut *mut c_char, b: c_int, l: *mut c_void) -> c_longlong;
    fn strtoull_l(p: *const c_char, e: *mut *mut c_char, b: c_int, l: *mut c_void) -> c_ulonglong;
    fn strtof_l(p: *const c_char, e: *mut *mut c_char, l: *mut c_void) -> f32;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
    fn __errno_location() -> *mut c_int;
}

fn consumed(end: *mut c_char, base: *const c_char) -> c_long {
    (end as isize - base as isize) as c_long
}
fn same32(a: f32, b: f32) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

#[test]
fn narrow_strto_l_family_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());

    let int_cases: &[(&str, c_int)] = &[
        ("123", 10),
        ("  -7xy", 10),
        ("0xFF", 16),
        ("777", 8),
        ("0", 0),
        ("abc", 10),
        ("18446744073709551616", 10), // u64 overflow
        ("-1", 10),                   // unsigned wraparound
        ("9223372036854775808", 10),  // i64 overflow (for ll)
    ];

    for &(s, base) in int_cases {
        let c = CString::new(s).unwrap();
        // strtoul_l
        let mut ge: *mut c_char = std::ptr::null_mut();
        let mut fe: *mut c_char = std::ptr::null_mut();
        unsafe { *__errno_location() = 0 };
        let g = unsafe { strtoul_l(c.as_ptr(), &mut ge, base, loc) };
        let gerr = unsafe { *__errno_location() };
        unsafe { *__errno_location() = 0 };
        let f = unsafe {
            frankenlibc_abi::stdlib_abi::strtoul_l(c.as_ptr(), &mut fe, base, loc as *mut c_void)
        };
        let ferr = unsafe { *__errno_location() };
        assert_eq!(f, g, "strtoul_l({s:?},{base}) value");
        assert_eq!(
            consumed(fe, c.as_ptr()),
            consumed(ge, c.as_ptr()),
            "strtoul_l({s:?}) endptr"
        );
        assert_eq!(ferr, gerr, "strtoul_l({s:?}) errno");

        // strtoll_l (i64)
        let mut ge2: *mut c_char = std::ptr::null_mut();
        let mut fe2: *mut c_char = std::ptr::null_mut();
        let g2 = unsafe { strtoll_l(c.as_ptr(), &mut ge2, base, loc) };
        let f2 = unsafe {
            frankenlibc_abi::stdlib_abi::strtoll_l(c.as_ptr(), &mut fe2, base, loc as *mut c_void)
        };
        assert_eq!(f2, g2, "strtoll_l({s:?},{base}) value");

        // strtoull_l (u64)
        let mut ge3: *mut c_char = std::ptr::null_mut();
        let mut fe3: *mut c_char = std::ptr::null_mut();
        let g3 = unsafe { strtoull_l(c.as_ptr(), &mut ge3, base, loc) };
        let f3 = unsafe {
            frankenlibc_abi::stdlib_abi::strtoull_l(c.as_ptr(), &mut fe3, base, loc as *mut c_void)
        };
        assert_eq!(f3, g3, "strtoull_l({s:?},{base}) value");
    }

    // strtof_l: value parity bit-for-bit
    for s in [
        "1.5",
        "  -3.25xy",
        "0x1.8p1",
        "inf",
        "-inf",
        "nan",
        "1e38",
        "1e40",
        "abc",
    ] {
        let c = CString::new(s).unwrap();
        let mut ge: *mut c_char = std::ptr::null_mut();
        let mut fe: *mut c_char = std::ptr::null_mut();
        let g = unsafe { strtof_l(c.as_ptr(), &mut ge, loc) };
        let f = unsafe {
            frankenlibc_abi::stdlib_abi::strtof_l(c.as_ptr(), &mut fe, loc as *mut c_void)
        };
        assert!(same32(f, g), "strtof_l({s:?}): fl={f:?} glibc={g:?}");
        assert_eq!(
            consumed(fe, c.as_ptr()),
            consumed(ge, c.as_ptr()),
            "strtof_l({s:?}) endptr"
        );
    }

    unsafe { freelocale(loc) };
}
