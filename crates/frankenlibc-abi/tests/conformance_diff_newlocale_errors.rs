#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc newlocale oracle

//! Differential gate for newlocale error errno (bd-h7oh9f), validating cod's
//! strict-error-path fix (bd-id0azv) against runtime glibc. For an invalid
//! category mask and an unsupported locale name, fl's newlocale must return
//! NULL with the same errno as host glibc; for "C" it must succeed (a non-NULL
//! locale_t, which is then freed). newlocale builds a fresh locale object and
//! does not touch the global locale, so this is side-effect-free. No mocks.

use std::ffi::{c_char, c_int, c_void, CString};

unsafe extern "C" {
    fn newlocale(category_mask: c_int, locale: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

fn glibc_new(mask: c_int, name: &CString) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe { newlocale(mask, name.as_ptr(), std::ptr::null_mut()) };
    let e = errno();
    if !r.is_null() {
        unsafe { freelocale(r) };
    }
    (r.is_null(), e)
}

fn fl_new(mask: c_int, name: &CString) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe {
        frankenlibc_abi::locale_abi::newlocale(mask, name.as_ptr(), std::ptr::null_mut())
    };
    let e = errno();
    if !r.is_null() {
        unsafe { frankenlibc_abi::locale_abi::freelocale(r) };
    }
    (r.is_null(), e)
}

#[test]
fn newlocale_invalid_mask_matches_glibc() {
    // A category-mask bit far outside the valid LC_*_MASK range.
    let bad_mask: c_int = 1 << 28;
    let c = CString::new("C").unwrap();
    let (gnull, ge) = glibc_new(bad_mask, &c);
    let (fnull, fe) = fl_new(bad_mask, &c);
    assert!(gnull, "glibc newlocale(invalid mask) should return NULL");
    assert_eq!(fnull, gnull, "newlocale(invalid mask) NULL-ness: fl={fnull} glibc={gnull}");
    assert_eq!(fe, ge, "newlocale(invalid mask) errno: fl={fe} glibc={ge}");
}

#[test]
fn newlocale_unsupported_locale_matches_glibc() {
    let bogus = CString::new("fl_no_such_locale_zzqq.UTF-8").unwrap();
    let (gnull, ge) = glibc_new(libc::LC_ALL_MASK, &bogus);
    let (fnull, fe) = fl_new(libc::LC_ALL_MASK, &bogus);
    assert!(gnull, "glibc newlocale(LC_ALL_MASK, bogus) should return NULL");
    assert_eq!(fnull, gnull, "newlocale(bogus) NULL-ness: fl={fnull} glibc={gnull}");
    assert_eq!(fe, ge, "newlocale(bogus) errno: fl={fe} glibc={ge}");
}

#[test]
fn newlocale_c_succeeds_both() {
    let c = CString::new("C").unwrap();
    let (gnull, _) = glibc_new(libc::LC_ALL_MASK, &c);
    let (fnull, _) = fl_new(libc::LC_ALL_MASK, &c);
    assert!(!gnull, "glibc newlocale(LC_ALL_MASK, \"C\") should succeed");
    assert!(!fnull, "fl newlocale(LC_ALL_MASK, \"C\") should succeed");
}
