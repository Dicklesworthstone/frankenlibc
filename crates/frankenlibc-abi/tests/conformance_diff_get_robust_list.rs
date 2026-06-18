#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `get_robust_list`.
//!
//! Null output pointers fail without changing the caller's robust-list
//! registration.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_GET_ROBUST_LIST: c_long = 274;
#[cfg(target_arch = "aarch64")]
const SYS_GET_ROBUST_LIST: c_long = 100;

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

fn host_get_robust_list(
    pid: c_int,
    head_ptr: *mut *mut c_void,
    len_ptr: *mut usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_GET_ROBUST_LIST, pid, head_ptr, len_ptr) as c_long };
    (rc as c_int, host_errno())
}

fn fl_get_robust_list(
    pid: c_int,
    head_ptr: *mut *mut c_void,
    len_ptr: *mut usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::get_robust_list(pid, head_ptr, len_ptr) };
    (rc, fl_errno())
}

#[test]
fn get_robust_list_null_outputs_match_host_syscall() {
    let host = host_get_robust_list(0, ptr::null_mut(), ptr::null_mut());
    let fl = fl_get_robust_list(0, ptr::null_mut(), ptr::null_mut());

    assert_eq!(
        fl, host,
        "get_robust_list(0,null,null): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl, (-1, libc::EFAULT));
}
