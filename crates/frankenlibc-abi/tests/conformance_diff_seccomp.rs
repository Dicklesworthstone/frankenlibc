#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `seccomp`.
//!
//! Invalid operations fail without installing filters or changing process mode.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_uint, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_SECCOMP: c_long = 317;
#[cfg(target_arch = "aarch64")]
const SYS_SECCOMP: c_long = 277;

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

fn host_seccomp(operation: c_uint, flags: c_uint, args: *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_SECCOMP, operation, flags, args) as c_long };
    (rc as c_int, host_errno())
}

fn fl_seccomp(operation: c_uint, flags: c_uint, args: *mut c_void) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::seccomp(operation, flags, args) };
    (rc, fl_errno())
}

#[test]
fn seccomp_invalid_operation_matches_host_syscall() {
    let host = host_seccomp(c_uint::MAX, 0, ptr::null_mut());
    let fl = fl_seccomp(c_uint::MAX, 0, ptr::null_mut());

    assert_eq!(
        fl, host,
        "seccomp(invalid operation): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
