#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `io_uring` raw syscall exports.
//!
//! The cases below fail before creating an io_uring fd or registering any
//! resources.

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

use std::ffi::{c_int, c_long, c_uint, c_void};
use std::ptr;

const SYS_IO_URING_SETUP: c_long = 425;
const SYS_IO_URING_ENTER: c_long = 426;
const SYS_IO_URING_REGISTER: c_long = 427;

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

fn host_io_uring_setup(entries: c_uint, params: *mut c_void) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_IO_URING_SETUP, entries, params) };
    (rc as c_int, host_errno())
}

fn fl_io_uring_setup(entries: c_uint, params: *mut c_void) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_uring_setup(entries, params) };
    (rc, fl_errno())
}

fn host_io_uring_enter(
    fd: c_uint,
    to_submit: c_uint,
    min_complete: c_uint,
    flags: c_uint,
    sig: *const libc::sigset_t,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        host_syscall()(
            SYS_IO_URING_ENTER,
            fd,
            to_submit,
            min_complete,
            flags,
            sig,
            std::mem::size_of::<libc::c_ulong>(),
        )
    };
    (rc as c_int, host_errno())
}

fn fl_io_uring_enter(
    fd: c_uint,
    to_submit: c_uint,
    min_complete: c_uint,
    flags: c_uint,
    sig: *const libc::sigset_t,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_uring_enter(fd, to_submit, min_complete, flags, sig) };
    (rc, fl_errno())
}

fn host_io_uring_register(
    fd: c_uint,
    opcode: c_uint,
    arg: *mut c_void,
    nr_args: c_uint,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_IO_URING_REGISTER, fd, opcode, arg, nr_args) };
    (rc as c_int, host_errno())
}

fn fl_io_uring_register(
    fd: c_uint,
    opcode: c_uint,
    arg: *mut c_void,
    nr_args: c_uint,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::io_uring_register(fd, opcode, arg, nr_args) };
    (rc, fl_errno())
}

#[test]
fn io_uring_invalid_failures_match_host_syscall() {
    let host = host_io_uring_setup(0, ptr::null_mut());
    let fl = fl_io_uring_setup(0, ptr::null_mut());
    assert_eq!(
        fl, host,
        "io_uring_setup(zero entries): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let invalid_fd = c_uint::MAX;
    let host = host_io_uring_enter(invalid_fd, 0, 0, 0, ptr::null());
    let fl = fl_io_uring_enter(invalid_fd, 0, 0, 0, ptr::null());
    assert_eq!(
        fl, host,
        "io_uring_enter(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_io_uring_register(invalid_fd, 0, ptr::null_mut(), 0);
    let fl = fl_io_uring_register(invalid_fd, 0, ptr::null_mut(), 0);
    assert_eq!(
        fl, host,
        "io_uring_register(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
