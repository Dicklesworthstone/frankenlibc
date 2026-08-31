#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `membarrier`.
//!
//! `MEMBARRIER_CMD_QUERY` is read-only; the invalid command case fails without
//! issuing a process-wide barrier.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr;

/// `long syscall(long number, ...)`, matching glibc's declaration.
type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// `int *__errno_location(void)`.
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut std::ffi::c_void;

/// Host glibc's raw-syscall and errno accessors, resolved out of libc.so.6 and
/// proven not to be fl's own exports.
///
/// This gate's host arm was two LINK-TIME references: the raw syscall entry and
/// the errno accessor. fl defines both under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`. Confirmed on the
/// built artifact rather than assumed: `nm -D --defined-only` on a release
/// `libfrankenlibc_abi.so` lists `T __errno_location` and `T syscall`, and lists
/// neither as undefined. So in a RELEASE test binary the linker prefers fl's
/// definitions for both halves, and this "host" arm would call fl's own syscall
/// wrapper and read fl's errno slot — the gate comparing fl against itself and
/// passing unconditionally. Debug keeps the symbols mangled, which is why the
/// gate has been honest in the profile CI runs.
///
/// The same collapse through the errno accessor was not hypothetical: it made
/// `bsd_stubs`, `c_locale_codec` and `locale_categories` fail `--release` with
/// the host arm reading errno 0 (bd-g1sjty). A collapsed SYSCALL arm cannot fail
/// that way — it passes silently — which is why it needs an assertion rather
/// than a test run to catch it. `host_addr` aborts if the resolved address
/// equals fl's own definition.
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
        let f = std::mem::transmute::<*mut std::ffi::c_void, ErrnoLocationFn>(addr);
        f().cast::<c_int>()
    }
}

use std::ffi::{c_int, c_long, c_uint};

#[cfg(target_arch = "x86_64")]
const SYS_MEMBARRIER: c_long = 324;
#[cfg(target_arch = "aarch64")]
const SYS_MEMBARRIER: c_long = 283;

const MEMBARRIER_CMD_QUERY: c_int = 0;

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

fn host_membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_MEMBARRIER, cmd, flags, cpu_id) };
    (rc as c_int, host_errno())
}

fn fl_membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::membarrier(cmd, flags, cpu_id) };
    (rc, fl_errno())
}

#[test]
fn membarrier_query_and_invalid_command_match_host_syscall() {
    let host = host_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    let fl = fl_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    assert_eq!(
        fl, host,
        "membarrier(MEMBARRIER_CMD_QUERY): fl={fl:?} host={host:?}"
    );

    let host = host_membarrier(c_int::MAX, 0, 0);
    let fl = fl_membarrier(c_int::MAX, 0, 0);
    assert_eq!(
        fl, host,
        "membarrier(invalid command): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
