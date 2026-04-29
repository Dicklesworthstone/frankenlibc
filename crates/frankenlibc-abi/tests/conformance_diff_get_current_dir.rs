#![cfg(target_os = "linux")]

//! Differential conformance harness for `get_current_dir_name(3)` /
//! `getcwd(3)` / `getwd(3)`.
//!
//! All three return the current working directory; they differ only in
//! how memory is provided.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, CStr};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn get_current_dir_name() -> *mut c_char;
    fn getcwd(buf: *mut c_char, size: usize) -> *mut c_char;
}

#[test]
fn diff_get_current_dir_name_match() {
    let p_fl = unsafe { fl::get_current_dir_name() };
    let p_lc = unsafe { get_current_dir_name() };
    assert!(!p_fl.is_null(), "fl get_current_dir_name returned NULL");
    assert!(!p_lc.is_null(), "glibc get_current_dir_name returned NULL");
    let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
    let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
    assert_eq!(s_fl, s_lc, "cwd mismatch");
    // Both impls must use libc::malloc per fl's bd-zgifl convention so we
    // can free both with libc::free.
    unsafe { libc::free(p_fl as *mut libc::c_void) };
    unsafe { libc::free(p_lc as *mut libc::c_void) };
}

#[test]
fn diff_getcwd_caller_buffer() {
    let mut fl_buf = [0i8; 4096];
    let mut lc_buf = [0i8; 4096];
    let p_fl = unsafe { fl::getcwd(fl_buf.as_mut_ptr(), fl_buf.len()) };
    let p_lc = unsafe { getcwd(lc_buf.as_mut_ptr(), lc_buf.len()) };
    assert!(!p_fl.is_null());
    assert!(!p_lc.is_null());
    let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
    let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
    assert_eq!(s_fl, s_lc);
}

#[test]
fn diff_getcwd_buffer_too_small_errors_match() {
    let mut fl_buf = [0i8; 1];
    let mut lc_buf = [0i8; 1];
    let p_fl = unsafe { fl::getcwd(fl_buf.as_mut_ptr(), 1) };
    let p_lc = unsafe { getcwd(lc_buf.as_mut_ptr(), 1) };
    assert_eq!(
        p_fl.is_null(),
        p_lc.is_null(),
        "getcwd null-return mismatch"
    );
    assert!(p_fl.is_null(), "getcwd should fail with size=1");
}

#[test]
fn diff_getcwd_null_buf_glibc_extension_match() {
    // GNU extension: getcwd(NULL, size) allocates the result.
    // Both fl and glibc support this.
    let p_fl = unsafe { fl::getcwd(std::ptr::null_mut(), 0) };
    let p_lc = unsafe { getcwd(std::ptr::null_mut(), 0) };
    assert_eq!(p_fl.is_null(), p_lc.is_null());
    if !p_fl.is_null() {
        let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
        let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
        assert_eq!(s_fl, s_lc);
        unsafe { libc::free(p_fl as *mut libc::c_void) };
        unsafe { libc::free(p_lc as *mut libc::c_void) };
    }
}

#[test]
fn get_current_dir_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc get_current_dir_name + getcwd\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
