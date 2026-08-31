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
/// This gate's host arm was LINK-TIME. fl defines both the raw syscall entry and
/// the errno accessor under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. Confirmed on the
/// built artifact rather than argued from source: `nm -D --defined-only` on a
/// release `libfrankenlibc_abi.so` lists `T __errno_location` and `T syscall`
/// and lists neither as undefined, so in a RELEASE test binary the linker
/// prefers fl's definitions and this "host" arm would call fl's own syscall
/// wrapper and read fl's errno slot — the gate comparing fl against itself and
/// passing unconditionally. Debug keeps the symbols mangled, which is why it has
/// been honest in the profile CI runs.
///
/// A collapsed SYSCALL arm cannot be caught by running the gate: unlike the
/// errno collapse, which made three gates fail `--release` with the host arm
/// reading errno 0 (bd-g1sjty), fl-vs-fl simply passes. `host_addr` aborts when
/// the resolved address equals fl's own definition, which is the only thing that
/// distinguishes the two. See bd-0q7ba9.
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

use std::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use std::ptr;

const SYS_FUTEX_WAKE: c_long = 454;
const SYS_FUTEX_WAIT: c_long = 455;
const SYS_FUTEX_REQUEUE: c_long = 456;

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

fn host_futex_wake(uaddr: *mut c_void, mask: c_ulong, nr: c_int, flags: c_uint) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_FUTEX_WAKE, uaddr, mask, nr, flags) };
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
    let rc = unsafe { host_syscall()(SYS_FUTEX_WAIT, uaddr, val, mask, flags, timeout, clockid) };
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
    let rc = unsafe { host_syscall()(SYS_FUTEX_REQUEUE, waiters, flags, nr_wake, nr_requeue) };
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
