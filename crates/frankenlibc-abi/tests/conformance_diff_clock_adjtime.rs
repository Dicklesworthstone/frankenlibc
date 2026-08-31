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

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr;

/// `long syscall(long number, ...)`, matching glibc's declaration.
type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// `int *__errno_location(void)`.
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

/// Host glibc's raw-syscall and errno accessors, resolved out of libc.so.6 and
/// proven not to be fl's own exports.
///
/// This gate's host arm was two LINK-TIME references: the raw syscall entry and
/// the errno accessor. fl defines both under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. Confirmed on the
/// built artifact rather than assumed: `nm -D --defined-only` on a release
/// `libfrankenlibc_abi.so` lists `T __errno_location` and `T syscall` and lists
/// neither as undefined, so in a RELEASE test binary the linker prefers fl's
/// definitions and this "host" arm would call fl's own syscall wrapper and read
/// fl's errno slot — the gate comparing fl against itself and passing
/// unconditionally. Debug keeps the symbols mangled, which is why it has been
/// honest in the profile CI runs.
///
/// A collapsed SYSCALL arm cannot be caught by running the gate: unlike the
/// errno collapse, which made three gates fail `--release` with the host arm
/// reading errno 0 (bd-g1sjty), fl-vs-fl simply passes. `host_addr` aborts when
/// the resolved address equals fl's own definition, which is the only thing that
/// distinguishes it. See bd-0q7ba9.
fn host_syscall() -> SyscallFn {
    // SAFETY: resolved address is glibc's raw syscall entry, `long(long, ...)`.
    unsafe {
        let addr = host_addr(c"syscall", fl::syscall as SyscallFn as *const ());
        std::mem::transmute::<*mut std::ffi::c_void, SyscallFn>(addr)
    }
}

fn host_errno_ptr() -> *mut c_int {
    // SAFETY: resolved address is glibc's errno accessor, `int *(void)`.
    unsafe {
        let addr = host_addr(
            c"__errno_location",
            fl_errno_location as ErrnoLocationFn as *const (),
        );
        std::mem::transmute::<*mut std::ffi::c_void, ErrnoLocationFn>(addr)()
    }
}

use std::ffi::{c_int, c_long};
use std::ptr;

const SYS_CLOCK_ADJTIME: c_long = libc::SYS_clock_adjtime as c_long;

fn host_errno() -> c_int {
    unsafe { *host_errno_ptr() }
}

fn set_host_errno(value: c_int) {
    unsafe { *host_errno_ptr() = value };
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
    let rc = unsafe { host_syscall()(SYS_CLOCK_ADJTIME, clock_id, buf) };
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
