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

#[cfg(target_arch = "x86_64")]
const SYS_USERFAULTFD: c_long = 323;
#[cfg(target_arch = "aarch64")]
const SYS_USERFAULTFD: c_long = 282;

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

fn host_userfaultfd(flags: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_USERFAULTFD, flags) };
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
    assert_eq!(fl.0, -1, "invalid userfaultfd flags must fail");
}
