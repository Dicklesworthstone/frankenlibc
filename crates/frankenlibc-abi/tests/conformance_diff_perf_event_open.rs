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

use std::ffi::{c_int, c_long, c_ulong, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: c_long = 298;
#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: c_long = 241;

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

fn host_perf_event_open(
    attr: *mut c_void,
    pid: libc::pid_t,
    cpu: c_int,
    group_fd: c_int,
    flags: c_ulong,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { host_syscall()(SYS_PERF_EVENT_OPEN, attr, pid, cpu, group_fd, flags) };
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
