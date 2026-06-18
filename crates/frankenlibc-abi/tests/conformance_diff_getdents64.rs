#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `getdents64`.
//!
//! The invalid-fd path fails before any directory buffer can be populated.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_void};

#[cfg(target_arch = "x86_64")]
const SYS_GETDENTS64: c_long = 217;
#[cfg(target_arch = "aarch64")]
const SYS_GETDENTS64: c_long = 61;

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

fn host_getdents64(fd: c_int, buffer: *mut c_void, count: usize) -> (c_long, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_GETDENTS64, fd, buffer, count) as c_long };
    (rc, host_errno())
}

fn fl_getdents64(fd: c_int, buffer: *mut c_void, count: usize) -> (c_long, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::getdents64(fd, buffer, count) };
    (rc, fl_errno())
}

#[test]
fn getdents64_invalid_fd_matches_host_syscall() {
    let mut buffer = [0u8; 256];
    let host = host_getdents64(-1, buffer.as_mut_ptr().cast(), buffer.len());
    let fl = fl_getdents64(-1, buffer.as_mut_ptr().cast(), buffer.len());

    assert_eq!(fl, host, "getdents64(-1): fl={fl:?} host={host:?}");
    assert_eq!(fl, (-1, libc::EBADF));
}
