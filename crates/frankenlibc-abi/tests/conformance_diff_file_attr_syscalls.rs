#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux 6.16 file attribute syscall exports.
//!
//! Invalid descriptor paths fail before reading or changing file attributes.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void};
use std::ptr;

const SYS_FILE_GETATTR: c_long = 468;
const SYS_FILE_SETATTR: c_long = 469;

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn set_host_errno(value: c_int) {
    unsafe { *libc::__errno_location() = value };
}

fn fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

fn set_fl_errno(value: c_int) {
    unsafe { *fl_errno_location() = value };
}

fn host_file_getattr(
    dirfd: c_int,
    path: *const c_char,
    attr: *mut c_void,
    size: usize,
    at_flags: c_uint,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_FILE_GETATTR, dirfd, path, attr, size, at_flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_file_getattr(
    dirfd: c_int,
    path: *const c_char,
    attr: *mut c_void,
    size: usize,
    at_flags: c_uint,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::file_getattr(dirfd, path, attr, size, at_flags) };
    (rc, fl_errno())
}

fn host_file_setattr(
    dirfd: c_int,
    path: *const c_char,
    attr: *const c_void,
    size: usize,
    at_flags: c_uint,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_FILE_SETATTR, dirfd, path, attr, size, at_flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_file_setattr(
    dirfd: c_int,
    path: *const c_char,
    attr: *const c_void,
    size: usize,
    at_flags: c_uint,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::file_setattr(dirfd, path, attr, size, at_flags) };
    (rc, fl_errno())
}

#[test]
fn file_attr_invalid_fd_failures_match_host_syscall() {
    let host = host_file_getattr(-1, c".".as_ptr(), ptr::null_mut(), 0, 0);
    let fl = fl_file_getattr(-1, c".".as_ptr(), ptr::null_mut(), 0, 0);
    assert_eq!(fl, host, "file_getattr(invalid fd): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_file_setattr(-1, c".".as_ptr(), ptr::null(), 0, 0);
    let fl = fl_file_setattr(-1, c".".as_ptr(), ptr::null(), 0, 0);
    assert_eq!(fl, host, "file_setattr(invalid fd): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);
}
