#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `userfaultfd`.
//!
//! Invalid all-bits flags fail before a userfaultfd descriptor can be created.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long};

#[cfg(target_arch = "x86_64")]
const SYS_USERFAULTFD: c_long = 323;
#[cfg(target_arch = "aarch64")]
const SYS_USERFAULTFD: c_long = 282;

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

fn host_userfaultfd(flags: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_USERFAULTFD, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_userfaultfd(flags: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::userfaultfd(flags) };
    (rc, fl_errno())
}

#[test]
fn userfaultfd_invalid_flags_match_host_syscall() {
    let host = host_userfaultfd(-1);
    let fl = fl_userfaultfd(-1);

    assert_eq!(
        fl, host,
        "userfaultfd(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl, (-1, libc::EINVAL));
}
