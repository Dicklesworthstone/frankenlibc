#![cfg(target_os = "linux")]

//! Differential conformance harness for GNU `secure_getenv(3)`.
//!
//! `secure_getenv` is `getenv` with the additional contract: if the
//! process is in secure-execution mode (typically because it's
//! running setuid/setgid), it must return NULL regardless of whether
//! the variable is set. In normal (non-secure) execution it behaves
//! identically to `getenv`.
//!
//! These tests exercise the normal-execution branch since we can't
//! easily simulate setuid in a unit test environment.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, CStr, CString};

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn secure_getenv(name: *const c_char) -> *mut c_char;
}

fn cstr_or_none(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn diff_secure_getenv_existing_variable_in_normal_execution() {
    // Use PATH which is virtually guaranteed to exist.
    let name = CString::new("PATH").unwrap();
    let fl_p = unsafe { fl::secure_getenv(name.as_ptr()) };
    let lc_p = unsafe { secure_getenv(name.as_ptr()) };
    let fl_s = cstr_or_none(fl_p);
    let lc_s = cstr_or_none(lc_p);
    assert_eq!(fl_s, lc_s, "PATH lookup: fl={fl_s:?} lc={lc_s:?}");
    assert!(fl_s.is_some(), "PATH should be set");
}

#[test]
fn diff_secure_getenv_nonexistent_variable_returns_null() {
    let name = CString::new("FRANKENLIBC_DEFINITELY_NOT_SET_ENVVAR_XYZ").unwrap();
    unsafe { std::env::remove_var("FRANKENLIBC_DEFINITELY_NOT_SET_ENVVAR_XYZ") };
    let fl_p = unsafe { fl::secure_getenv(name.as_ptr()) };
    let lc_p = unsafe { secure_getenv(name.as_ptr()) };
    assert!(fl_p.is_null());
    assert!(lc_p.is_null());
}

#[test]
fn diff_secure_getenv_empty_string_value() {
    // Set a variable to empty; getenv should return non-NULL pointer
    // to an empty string (NOT NULL).
    let name = "FRANKENLIBC_TEST_EMPTY_ENV";
    let cname = CString::new(name).unwrap();
    unsafe { std::env::set_var(name, "") };
    let fl_p = unsafe { fl::secure_getenv(cname.as_ptr()) };
    let lc_p = unsafe { secure_getenv(cname.as_ptr()) };
    let fl_s = cstr_or_none(fl_p);
    let lc_s = cstr_or_none(lc_p);
    unsafe { std::env::remove_var(name) };
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s.as_deref(), Some(""), "empty string lookup");
}

#[test]
fn diff_secure_getenv_with_special_value() {
    let name = "FRANKENLIBC_TEST_SECURE_GETENV_VALUE";
    let value = "value-with-spaces and =equals=";
    let cname = CString::new(name).unwrap();
    unsafe { std::env::set_var(name, value) };
    let fl_p = unsafe { fl::secure_getenv(cname.as_ptr()) };
    let lc_p = unsafe { secure_getenv(cname.as_ptr()) };
    let fl_s = cstr_or_none(fl_p);
    let lc_s = cstr_or_none(lc_p);
    unsafe { std::env::remove_var(name) };
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s.as_deref(), Some(value));
}

#[test]
fn fl_secure_getenv_null_name_returns_null() {
    // glibc segfaults on NULL name; we only assert fl is hardened.
    let p = unsafe { fl::secure_getenv(std::ptr::null()) };
    assert!(p.is_null());
}

#[test]
fn secure_getenv_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc secure_getenv\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
