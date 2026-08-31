#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux I/O priority syscalls.
//!
//! glibc does not expose stable high-level wrappers here on all targets, so the
//! oracle is the host kernel reached through `libc::syscall`. Invalid `which`
//! values fail before mutating any process I/O priority state.

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

use std::ffi::{c_int, c_long};

const IOPRIO_WHO_PROCESS: c_int = 1;

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

fn host_ioprio_get(which: c_int, who: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(libc::SYS_ioprio_get, which, who) };
    (rc as c_int, host_errno())
}

fn host_ioprio_set(which: c_int, who: c_int, ioprio: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(libc::SYS_ioprio_set, which, who, ioprio) };
    (rc as c_int, host_errno())
}

#[test]
fn ioprio_invalid_which_matches_host_syscall() {
    // Cover both signed boundary directions. A wrapper that only special-cases
    // negative selectors must not accept an arbitrary large positive one.
    for which in [-1, c_int::MAX] {
        let host_get = host_ioprio_get(which, 0);
        set_fl_errno(0);
        let fl_get = (unsafe { fl::ioprio_get(which, 0) }, fl_errno());
        assert_eq!(
            fl_get, host_get,
            "ioprio_get({which}): fl={fl_get:?} host={host_get:?}"
        );
        assert_eq!(host_get, (-1, libc::EINVAL));

        let host_set = host_ioprio_set(which, 0, 0);
        set_fl_errno(0);
        let fl_set = (unsafe { fl::ioprio_set(which, 0, 0) }, fl_errno());
        assert_eq!(
            fl_set, host_set,
            "ioprio_set({which}): fl={fl_set:?} host={host_set:?}"
        );
        assert_eq!(host_set, (-1, libc::EINVAL));
    }
}

#[test]
fn ioprio_get_current_process_matches_host_without_changing_errno() {
    // This is a query only: `who = 0` selects the current process and does
    // not change the process I/O priority.
    set_host_errno(libc::EAGAIN);
    let host_rc =
        unsafe { host_syscall()(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0) } as c_int;
    let host = (host_rc, host_errno());

    set_fl_errno(libc::EAGAIN);
    let fl_result = (unsafe { fl::ioprio_get(IOPRIO_WHO_PROCESS, 0) }, fl_errno());

    assert_eq!(
        fl_result, host,
        "ioprio_get(current): fl={fl_result:?} host={host:?}"
    );
    assert!(
        host.0 >= 0,
        "host ioprio_get(current) must succeed: {host:?}"
    );
    assert_eq!(host.1, libc::EAGAIN);
}
