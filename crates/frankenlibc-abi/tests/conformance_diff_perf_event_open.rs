#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `perf_event_open`.
//!
//! These invalid calls do not open a perf event. They pin the raw syscall
//! wrapper's return/errno behavior for permission/null-attribute failure and
//! invalid flag rejection.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_ulong, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: c_long = 298;
#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: c_long = 241;

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

fn host_perf_event_open(
    attr: *mut c_void,
    pid: libc::pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_PERF_EVENT_OPEN, attr, pid, cpu, group_fd, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_perf_event_open(
    attr: *mut c_void,
    pid: libc::pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::perf_event_open(attr, pid, cpu, group_fd, flags) };
    (rc, fl_errno())
}

#[test]
fn perf_event_open_null_attr_failure_matches_host_syscall() {
    let host = host_perf_event_open(ptr::null_mut(), 0, -1, -1, 0);
    let fl = fl_perf_event_open(ptr::null_mut(), 0, -1, -1, 0);

    assert_eq!(
        fl, host,
        "perf_event_open(null attr): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}

#[test]
fn perf_event_open_invalid_flags_match_host_syscall() {
    let host = host_perf_event_open(ptr::null_mut(), 0, -1, -1, c_ulong::MAX);
    let fl = fl_perf_event_open(ptr::null_mut(), 0, -1, -1, c_ulong::MAX);

    assert_eq!(
        fl, host,
        "perf_event_open(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl, (-1, libc::EINVAL));
}
