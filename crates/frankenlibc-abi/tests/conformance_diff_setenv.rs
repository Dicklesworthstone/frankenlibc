#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setenv/unsetenv oracle; mutates this process's environ

//! Differential gate for the setenv/unsetenv name-validation contract
//! (bd-55zii9) — no dedicated gate existed. glibc rejects a NULL, empty, or
//! '='-containing name with -1/EINVAL (and setenv rejects a NULL value); a valid
//! name succeeds with 0. The return value + errno are environ-independent for
//! these validation outcomes, so they are compared exactly with glibc. Distinct
//! valid names are used to minimise interference on the shared process environ.
//! No mocks.

use std::ffi::{CString, c_char, c_int};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
        pub fn unsetenv(name: *const c_char) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::stdlib_abi as fl;

fn errno() -> c_int {
    unsafe { *g::__errno_location() }
}

fn g_setenv(name: *const c_char, val: *const c_char, ow: c_int) -> (c_int, c_int) {
    unsafe { *g::__errno_location() = 0 };
    let rc = unsafe { g::setenv(name, val, ow) };
    (rc, if rc != 0 { errno() } else { 0 })
}
fn f_setenv(name: *const c_char, val: *const c_char, ow: c_int) -> (c_int, c_int) {
    unsafe { *g::__errno_location() = 0 };
    let rc = unsafe { fl::setenv(name, val, ow) };
    (rc, if rc != 0 { errno() } else { 0 })
}

#[test]
fn setenv_validation_matches_glibc() {
    let val = CString::new("value").unwrap();
    // (name, expect-via-distinct-vars). Each invalid case is environ-independent.
    let bad_empty = CString::new("").unwrap();
    let bad_eq = CString::new("HAS=EQUALS").unwrap();

    // NULL name
    assert_eq!(
        f_setenv(std::ptr::null(), val.as_ptr(), 1),
        g_setenv(std::ptr::null(), val.as_ptr(), 1),
        "setenv(NULL name)"
    );
    // empty name
    assert_eq!(
        f_setenv(bad_empty.as_ptr(), val.as_ptr(), 1),
        g_setenv(bad_empty.as_ptr(), val.as_ptr(), 1),
        "setenv(empty name)"
    );
    // name containing '='
    assert_eq!(
        f_setenv(bad_eq.as_ptr(), val.as_ptr(), 1),
        g_setenv(bad_eq.as_ptr(), val.as_ptr(), 1),
        "setenv(name with '=')"
    );
    // valid names (distinct so the two impls don't fight over one var)
    let fn_ok = CString::new("FL_SETENV_OK").unwrap();
    let gn_ok = CString::new("G_SETENV_OK").unwrap();
    assert_eq!(
        f_setenv(fn_ok.as_ptr(), val.as_ptr(), 1).0,
        0,
        "fl setenv valid"
    );
    assert_eq!(
        g_setenv(gn_ok.as_ptr(), val.as_ptr(), 1).0,
        0,
        "glibc setenv valid"
    );
}

#[test]
fn unsetenv_validation_matches_glibc() {
    let bad_empty = CString::new("").unwrap();
    let bad_eq = CString::new("HAS=EQ").unwrap();
    for name in [std::ptr::null(), bad_empty.as_ptr(), bad_eq.as_ptr()] {
        unsafe { *g::__errno_location() = 0 };
        let fr = unsafe { fl::unsetenv(name) };
        let fe = if fr != 0 { errno() } else { 0 };
        unsafe { *g::__errno_location() = 0 };
        let gr = unsafe { g::unsetenv(name) };
        let ge = if gr != 0 { errno() } else { 0 };
        assert_eq!((fr, fe), (gr, ge), "unsetenv invalid name");
    }
    // valid unsetenv (a name not necessarily present) returns 0 on both
    let ok = CString::new("FL_UNSET_OK").unwrap();
    assert_eq!(unsafe { fl::unsetenv(ok.as_ptr()) }, 0, "fl unsetenv valid");
    assert_eq!(
        unsafe { g::unsetenv(ok.as_ptr()) },
        0,
        "glibc unsetenv valid"
    );
}
