#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setlocale oracle

//! Differential gate for setlocale error paths (bd-f0m51k), validating cod's
//! fixes (bd-j0buhp invalid category -> EINVAL, bd-271rqa unavailable locale ->
//! ENOENT) against runtime glibc. For an out-of-range category and a
//! definitely-missing locale, fl's setlocale must return NULL with the same
//! errno as host glibc; for "C" it must succeed. Only failing/query cases are
//! exercised so the global locale is left unchanged. No mocks.

use std::ffi::{c_char, c_int, CString};

unsafe extern "C" {
    fn setlocale(category: c_int, locale: *const c_char) -> *const c_char;
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

fn glibc_setlocale(cat: c_int, name: *const c_char) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe { setlocale(cat, name) };
    (r.is_null(), errno())
}

fn fl_setlocale(cat: c_int, name: *const c_char) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe { frankenlibc_abi::locale_abi::setlocale(cat, name) };
    (r.is_null(), errno())
}

#[test]
fn setlocale_invalid_category_matches_glibc() {
    // 99 is well outside the LC_* range (LC_ALL is the max defined value).
    let (gnull, ge) = glibc_setlocale(99, std::ptr::null());
    let (fnull, fe) = fl_setlocale(99, std::ptr::null());
    assert!(gnull, "glibc setlocale(99, NULL) should return NULL");
    assert_eq!(fnull, gnull, "setlocale(invalid cat) NULL-ness: fl={fnull} glibc={gnull}");
    assert_eq!(fe, ge, "setlocale(invalid cat) errno: fl={fe} glibc={ge}");
}

#[test]
fn setlocale_unavailable_locale_matches_glibc() {
    let bogus = CString::new("fl_no_such_locale_zzqq.UTF-8").unwrap();
    let (gnull, ge) = glibc_setlocale(libc::LC_ALL, bogus.as_ptr());
    let (fnull, fe) = fl_setlocale(libc::LC_ALL, bogus.as_ptr());
    assert!(gnull, "glibc setlocale(LC_ALL, bogus) should return NULL");
    assert_eq!(fnull, gnull, "setlocale(bogus) NULL-ness: fl={fnull} glibc={gnull}");
    assert_eq!(fe, ge, "setlocale(bogus) errno: fl={fe} glibc={ge}");
}

#[test]
fn setlocale_c_succeeds_both() {
    let c = CString::new("C").unwrap();
    let (gnull, _) = glibc_setlocale(libc::LC_ALL, c.as_ptr());
    let (fnull, _) = fl_setlocale(libc::LC_ALL, c.as_ptr());
    assert!(!gnull, "glibc setlocale(LC_ALL, \"C\") should succeed");
    assert!(!fnull, "fl setlocale(LC_ALL, \"C\") should succeed");
}
