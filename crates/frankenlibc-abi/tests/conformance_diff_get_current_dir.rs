#![cfg(target_os = "linux")]

//! Differential conformance harness for `get_current_dir_name(3)` /
//! `getcwd(3)` / `getwd(3)`.
//!
//! All three return the current working directory; they differ only in
//! how memory is provided.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CStr, c_char, c_int};

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::glibc_internal_abi as fl_internal;
use frankenlibc_abi::unistd_abi as fl;

// The host arms are resolved with `dlsym`, not declared at link time. fl
// exports its own getcwd/getwd/get_current_dir_name into this binary, and a
// link-time reference can bind to those instead of libc's — making both arms fl
// so every assertion passes while proving nothing. That is measured, not
// theoretical: conformance_diff_catopen was passing exactly this way in a plain
// debug build and was concealing a live errno defect (bd-rp1e32, bd-v0388t).
// dlsym on an explicit libc.so.6 handle is correct in every build profile, and
// the assert_ne! makes the remaining doubt a failing test.
type GetCurrentDirNameFn = unsafe extern "C" fn() -> *mut c_char;
type GetcwdFn = unsafe extern "C" fn(*mut c_char, usize) -> *mut c_char;
type GetwdFn = unsafe extern "C" fn(*mut c_char) -> *mut c_char;

union GcdnSym {
    raw: *mut std::ffi::c_void,
    function: GetCurrentDirNameFn,
}
union GetcwdSym {
    raw: *mut std::ffi::c_void,
    function: GetcwdFn,
}
union GetwdSym {
    raw: *mut std::ffi::c_void,
    function: GetwdFn,
}

fn libc_handle() -> *mut std::ffi::c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    handle
}

fn host_get_current_dir_name() -> GetCurrentDirNameFn {
    // SAFETY: the handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(libc_handle(), c"get_current_dir_name".as_ptr()) };
    assert!(!raw.is_null(), "dlsym get_current_dir_name");
    assert_ne!(
        raw as usize,
        fl::get_current_dir_name as usize,
        "the resolved oracle IS fl's get_current_dir_name — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has glibc's documented signature.
    unsafe { GcdnSym { raw }.function }
}

fn host_getcwd() -> GetcwdFn {
    // SAFETY: as above, for getcwd.
    let raw = unsafe { libc::dlsym(libc_handle(), c"getcwd".as_ptr()) };
    assert!(!raw.is_null(), "dlsym getcwd");
    assert_ne!(
        raw as usize,
        fl::getcwd as usize,
        "the resolved oracle IS fl's getcwd — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has POSIX's documented getcwd signature.
    unsafe { GetcwdSym { raw }.function }
}

fn host_getwd() -> GetwdFn {
    // SAFETY: as above, for the legacy getwd.
    let raw = unsafe { libc::dlsym(libc_handle(), c"getwd".as_ptr()) };
    assert!(!raw.is_null(), "dlsym getwd");
    // Compared against `fl_internal::getwd` specifically, because that is the
    // entry point the tests below actually call. Asserting against a different
    // fl symbol would prove nothing about this gate's fl arm.
    assert_ne!(
        raw as usize,
        fl_internal::getwd as usize,
        "the resolved oracle IS fl's getwd — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has the documented legacy getwd signature.
    unsafe { GetwdSym { raw }.function }
}

fn clear_fl_errno() {
    unsafe { *fl_errno_location() = 0 };
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn clear_host_errno() {
    unsafe { *libc::__errno_location() = 0 };
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[test]
fn diff_get_current_dir_name_match() {
    let get_current_dir_name = host_get_current_dir_name();
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
    let getcwd = host_getcwd();
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
    let getcwd = host_getcwd();
    let mut fl_buf = [0i8; 1];
    let mut lc_buf = [0i8; 1];

    // The name says "errors_match", so compare the ERRNO and not just the NULL.
    // Two implementations can agree on failing and still disagree on why, which
    // is the whole class of defect this suite exists to catch — catopen("")
    // differed only in errno and passed for months (bd-rp1e32).
    clear_fl_errno();
    let p_fl = unsafe { fl::getcwd(fl_buf.as_mut_ptr(), 1) };
    let e_fl = fl_errno();

    clear_host_errno();
    let p_lc = unsafe { getcwd(lc_buf.as_mut_ptr(), 1) };
    let e_lc = host_errno();

    assert_eq!(
        p_fl.is_null(),
        p_lc.is_null(),
        "getcwd null-return mismatch"
    );
    assert!(p_fl.is_null(), "getcwd should fail with size=1");
    assert_eq!(e_fl, e_lc, "getcwd size=1 errno: fl={e_fl} glibc={e_lc}");
    // POSIX: a buffer too small for the pathname is ERANGE.
    assert_eq!(e_lc, libc::ERANGE, "glibc should report ERANGE for size=1");
}

#[test]
fn diff_getcwd_null_buf_glibc_extension_match() {
    let getcwd = host_getcwd();
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
fn diff_getwd_caller_buffer() {
    let getwd = host_getwd();
    let mut fl_buf = [0i8; 4096];
    let mut lc_buf = [0i8; 4096];
    let p_fl = unsafe { fl_internal::getwd(fl_buf.as_mut_ptr()) };
    let p_lc = unsafe { getwd(lc_buf.as_mut_ptr()) };
    assert!(!p_fl.is_null());
    assert!(!p_lc.is_null());
    assert_eq!(p_fl, fl_buf.as_mut_ptr());
    assert_eq!(p_lc, lc_buf.as_mut_ptr());
    let s_fl = unsafe { CStr::from_ptr(p_fl).to_bytes() };
    let s_lc = unsafe { CStr::from_ptr(p_lc).to_bytes() };
    assert_eq!(s_fl, s_lc);
}

#[test]
fn diff_getwd_null_buf_errors_match() {
    let getwd = host_getwd();
    clear_fl_errno();
    let p_fl = unsafe { fl_internal::getwd(std::ptr::null_mut()) };
    let e_fl = fl_errno();

    clear_host_errno();
    let p_lc = unsafe { getwd(std::ptr::null_mut()) };
    let e_lc = host_errno();

    assert!(p_fl.is_null());
    assert!(p_lc.is_null());
    assert_eq!(e_fl, libc::EINVAL);
    assert_eq!(e_lc, libc::EINVAL);
    assert_eq!(e_fl, e_lc);
}

#[test]
fn get_current_dir_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc get_current_dir_name + getcwd + getwd\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
