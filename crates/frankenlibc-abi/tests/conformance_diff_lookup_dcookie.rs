#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `lookup_dcookie`.
//!
//! Invalid cookies fail without depending on audit cookie availability or
//! mutating filesystem state.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_LOOKUP_DCOOKIE: c_long = 212;
#[cfg(target_arch = "aarch64")]
const SYS_LOOKUP_DCOOKIE: c_long = 18;

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

fn host_lookup_dcookie(cookie: u64, buffer: *mut c_char, len: usize) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_LOOKUP_DCOOKIE, cookie, buffer, len) as c_long };
    (rc as c_int, host_errno())
}

fn fl_lookup_dcookie(cookie: u64, buffer: *mut c_char, len: usize) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::lookup_dcookie(cookie, buffer, len) };
    (rc, fl_errno())
}

#[test]
fn lookup_dcookie_invalid_cookie_matches_host_syscall() {
    let null_host = host_lookup_dcookie(0, ptr::null_mut(), 0);
    let null_fl = fl_lookup_dcookie(0, ptr::null_mut(), 0);

    assert_eq!(
        null_fl, null_host,
        "lookup_dcookie(0,null,0): fl={null_fl:?} host={null_host:?}"
    );
    assert_eq!(null_fl.0, -1);

    let mut buffer = [0u8; 64];
    let host = host_lookup_dcookie(0, buffer.as_mut_ptr() as *mut c_char, buffer.len());
    let fl = fl_lookup_dcookie(0, buffer.as_mut_ptr() as *mut c_char, buffer.len());

    assert_eq!(
        fl, host,
        "lookup_dcookie(0,buffer,len): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
