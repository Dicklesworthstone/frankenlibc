#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strcoll_l/wcscoll_l oracle

//! Differential gate for the collation _l variants strcoll_l/wcscoll_l
//! (bd-2bjxh3) — previously uncovered. With a "C" locale these collate by byte
//! value; fl ignores the locale and delegates to strcoll/wcscoll, which matches
//! glibc for the C locale. Asserts fl's result sign matches host glibc across
//! equal/ordered/prefix pairs, using a real C locale_t. No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

use libc::wchar_t;

unsafe extern "C" {
    fn strcoll_l(a: *const c_char, b: *const c_char, loc: *mut c_void) -> c_int;
    fn wcscoll_l(a: *const wchar_t, b: *const wchar_t, loc: *mut c_void) -> c_int;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
}

const PAIRS: &[(&str, &str)] = &[
    ("abc", "abc"),
    ("abc", "abd"),
    ("abd", "abc"),
    ("Z", "a"),
    ("a", "Z"),
    ("", ""),
    ("x", ""),
    ("foo", "foobar"),
    ("9", "10"),
];

fn wide(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

#[test]
fn strcoll_l_wcscoll_l_match_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "newlocale(C) failed");

    for &(sa, sb) in PAIRS {
        let a = CString::new(sa).unwrap();
        let b = CString::new(sb).unwrap();
        let g = unsafe { strcoll_l(a.as_ptr(), b.as_ptr(), loc) };
        let f = unsafe {
            frankenlibc_abi::unistd_abi::strcoll_l(a.as_ptr(), b.as_ptr(), loc as *mut c_void)
        };
        assert_eq!(
            f.signum(),
            g.signum(),
            "strcoll_l({sa:?},{sb:?}): fl={f} glibc={g}"
        );

        let wa = wide(sa);
        let wb = wide(sb);
        let gw = unsafe { wcscoll_l(wa.as_ptr(), wb.as_ptr(), loc) };
        let fw = unsafe {
            frankenlibc_abi::wchar_abi::wcscoll_l(wa.as_ptr(), wb.as_ptr(), loc as *mut c_void)
        };
        assert_eq!(
            fw.signum(),
            gw.signum(),
            "wcscoll_l({sa:?},{sb:?}): fl={fw} glibc={gw}"
        );
    }

    unsafe { freelocale(loc) };
}
