#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux fanotify raw syscall exports.
//!
//! These failure paths do not create fanotify groups or install marks.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_uint};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_FANOTIFY_INIT: c_long = 300;
#[cfg(target_arch = "aarch64")]
const SYS_FANOTIFY_INIT: c_long = 262;

#[cfg(target_arch = "x86_64")]
const SYS_FANOTIFY_MARK: c_long = 301;
#[cfg(target_arch = "aarch64")]
const SYS_FANOTIFY_MARK: c_long = 263;

const FAN_MARK_ADD: c_uint = 0x0000_0001;
const FAN_ACCESS: u64 = 0x0000_0001;

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

fn host_fanotify_init(flags: c_uint, event_f_flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_FANOTIFY_INIT, flags, event_f_flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_fanotify_init(flags: c_uint, event_f_flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::fanotify_init(flags, event_f_flags) };
    (rc, fl_errno())
}

fn host_fanotify_mark(
    fanotify_fd: c_int,
    flags: c_uint,
    mask: u64,
    dirfd: c_int,
    pathname: *const c_char,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        libc::syscall(SYS_FANOTIFY_MARK, fanotify_fd, flags, mask, dirfd, pathname) as c_long
    };
    (rc as c_int, host_errno())
}

fn fl_fanotify_mark(
    fanotify_fd: c_int,
    flags: c_uint,
    mask: u64,
    dirfd: c_int,
    pathname: *const c_char,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::fanotify_mark(fanotify_fd, flags, mask, dirfd, pathname) };
    (rc, fl_errno())
}

#[test]
fn fanotify_invalid_failures_match_host_syscall() {
    let host = host_fanotify_init(c_uint::MAX, 0);
    let fl = fl_fanotify_init(c_uint::MAX, 0);

    assert_eq!(
        fl, host,
        "fanotify_init(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_fanotify_mark(-1, FAN_MARK_ADD, FAN_ACCESS, libc::AT_FDCWD, ptr::null());
    let fl = fl_fanotify_mark(-1, FAN_MARK_ADD, FAN_ACCESS, libc::AT_FDCWD, ptr::null());

    assert_eq!(
        fl, host,
        "fanotify_mark(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
