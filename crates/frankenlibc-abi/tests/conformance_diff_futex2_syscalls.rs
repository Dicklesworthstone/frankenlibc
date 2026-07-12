#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux futex2 raw syscall exports.
//!
//! Invalid pointer/flag paths return immediately and cannot block or wake real
//! waiters.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use std::ptr;

const SYS_FUTEX_WAKE: c_long = 454;
const SYS_FUTEX_WAIT: c_long = 455;
const SYS_FUTEX_REQUEUE: c_long = 456;

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

fn host_futex_wake(uaddr: *mut c_void, mask: c_ulong, nr: c_int, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_FUTEX_WAKE, uaddr, mask, nr, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_futex_wake(uaddr: *mut c_void, mask: c_ulong, nr: c_int, flags: c_uint) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::futex_wake(uaddr, mask, nr, flags) };
    (rc, fl_errno())
}

fn host_futex_wait(
    uaddr: *mut c_void,
    val: c_ulong,
    mask: c_ulong,
    flags: c_uint,
    timeout: *const libc::timespec,
    clockid: libc::clockid_t,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_FUTEX_WAIT, uaddr, val, mask, flags, timeout, clockid) };
    (rc as c_int, host_errno())
}

fn fl_futex_wait(
    uaddr: *mut c_void,
    val: c_ulong,
    mask: c_ulong,
    flags: c_uint,
    timeout: *const libc::timespec,
    clockid: libc::clockid_t,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::futex_wait(uaddr, val, mask, flags, timeout, clockid) };
    (rc, fl_errno())
}

fn host_futex_requeue(
    waiters: *const c_void,
    flags: c_uint,
    nr_wake: c_int,
    nr_requeue: c_int,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_FUTEX_REQUEUE, waiters, flags, nr_wake, nr_requeue) };
    (rc as c_int, host_errno())
}

fn fl_futex_requeue(
    waiters: *const c_void,
    flags: c_uint,
    nr_wake: c_int,
    nr_requeue: c_int,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::futex_requeue(waiters, flags, nr_wake, nr_requeue) };
    (rc, fl_errno())
}

#[test]
fn futex2_invalid_failures_match_host_syscall() {
    let host = host_futex_wake(ptr::null_mut(), 0, 0, c_uint::MAX);
    let fl = fl_futex_wake(ptr::null_mut(), 0, 0, c_uint::MAX);
    assert_eq!(
        fl, host,
        "futex_wake(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_futex_wait(
        ptr::null_mut(),
        0,
        0,
        c_uint::MAX,
        ptr::null(),
        libc::CLOCK_MONOTONIC,
    );
    let fl = fl_futex_wait(
        ptr::null_mut(),
        0,
        0,
        c_uint::MAX,
        ptr::null(),
        libc::CLOCK_MONOTONIC,
    );
    assert_eq!(
        fl, host,
        "futex_wait(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_futex_requeue(ptr::null(), c_uint::MAX, 0, 0);
    let fl = fl_futex_requeue(ptr::null(), c_uint::MAX, 0, 0);
    assert_eq!(
        fl, host,
        "futex_requeue(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
