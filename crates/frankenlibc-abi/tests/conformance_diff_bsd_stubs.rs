#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Live host-glibc differential coverage for BSD compatibility stubs.

use frankenlibc_abi::{errno_abi, glibc_internal_abi as fl};
use std::ffi::{CString, c_char, c_int, c_ulong};

unsafe extern "C" {
    fn chflags(path: *const c_char, flags: c_ulong) -> c_int;
    fn revoke(path: *const c_char) -> c_int;
    fn setlogin(name: *const c_char) -> c_int;
}

fn clear_errnos() {
    unsafe {
        *errno_abi::__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

fn fl_errno() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[test]
fn bsd_stubs_match_host_enosys_contract() {
    let path = CString::new("/nonexistent/frankenlibc-chflags").unwrap();
    clear_errnos();
    let host_chflags = unsafe { chflags(path.as_ptr(), 0) };
    let host_chflags_errno = host_errno();
    clear_errnos();
    let fl_chflags = unsafe { fl::chflags(path.as_ptr(), 0) };
    assert_eq!(
        (fl_chflags, fl_errno()),
        (host_chflags, host_chflags_errno),
        "chflags ENOSYS contract"
    );

    let login = CString::new("frankenlibc").unwrap();
    clear_errnos();
    let host_setlogin = unsafe { setlogin(login.as_ptr()) };
    let host_setlogin_errno = host_errno();
    clear_errnos();
    let fl_setlogin = unsafe { fl::setlogin(login.as_ptr()) };
    assert_eq!(
        (fl_setlogin, fl_errno()),
        (host_setlogin, host_setlogin_errno),
        "setlogin ENOSYS contract"
    );
}

#[test]
fn revoke_matches_host_enosys_contract() {
    let path = CString::new("/nonexistent/frankenlibc-revoke").unwrap();
    clear_errnos();
    let host_result = unsafe { revoke(path.as_ptr()) };
    let host_result_errno = host_errno();
    clear_errnos();
    let fl_result = unsafe { fl::revoke(path.as_ptr()) };
    assert_eq!(
        (fl_result, fl_errno()),
        (host_result, host_result_errno),
        "revoke ENOSYS contract"
    );
}
