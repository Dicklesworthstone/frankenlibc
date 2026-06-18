#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for the Linux `clock_adjtime` ABI export.
//!
//! These cases fail before any clock adjustment can occur, so they are safe to
//! compare against the host syscall without privileges.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long};
use std::ptr;

const SYS_CLOCK_ADJTIME: c_long = libc::SYS_clock_adjtime as c_long;

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

fn zero_timex() -> libc::timex {
    unsafe { std::mem::zeroed() }
}

fn host_clock_adjtime(clock_id: libc::clockid_t, buf: *mut libc::timex) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_CLOCK_ADJTIME, clock_id, buf) as c_long };
    (rc as c_int, host_errno())
}

fn fl_clock_adjtime(clock_id: libc::clockid_t, buf: *mut libc::timex) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::clock_adjtime(clock_id, buf) };
    (rc, fl_errno())
}

#[test]
fn clock_adjtime_invalid_failures_match_host_syscall() {
    let host = host_clock_adjtime(libc::CLOCK_REALTIME, ptr::null_mut());
    let fl = fl_clock_adjtime(libc::CLOCK_REALTIME, ptr::null_mut());
    assert_eq!(
        fl, host,
        "clock_adjtime(CLOCK_REALTIME, NULL): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let mut host_timex = zero_timex();
    let mut fl_timex = zero_timex();
    let invalid_clock = c_int::MAX;
    let host = host_clock_adjtime(invalid_clock, &mut host_timex);
    let fl = fl_clock_adjtime(invalid_clock, &mut fl_timex);
    assert_eq!(
        fl, host,
        "clock_adjtime(invalid clock): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
