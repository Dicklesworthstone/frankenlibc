#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux file-handle raw syscall exports.
//!
//! The cases below fail before requiring filesystem handle support or elevated
//! capabilities.

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

use std::ffi::{c_char, c_int, c_long, c_uint, c_void};
use std::ptr;

#[cfg(target_arch = "x86_64")]
const SYS_NAME_TO_HANDLE_AT: c_long = 303;
#[cfg(target_arch = "aarch64")]
const SYS_NAME_TO_HANDLE_AT: c_long = 264;

#[cfg(target_arch = "x86_64")]
const SYS_OPEN_BY_HANDLE_AT: c_long = 304;
#[cfg(target_arch = "aarch64")]
const SYS_OPEN_BY_HANDLE_AT: c_long = 265;

#[repr(C)]
struct MinimalFileHandle {
    handle_bytes: c_uint,
    handle_type: c_int,
}

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

fn host_name_to_handle_at(
    dirfd: c_int,
    path: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        host_syscall()(SYS_NAME_TO_HANDLE_AT, dirfd, path, handle, mount_id, flags)
    };
    (rc as c_int, host_errno())
}

fn fl_name_to_handle_at(
    dirfd: c_int,
    path: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::name_to_handle_at(dirfd, path, handle, mount_id, flags) };
    (rc, fl_errno())
}

fn host_open_by_handle_at(mount_fd: c_int, handle: *mut c_void, flags: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { host_syscall()(SYS_OPEN_BY_HANDLE_AT, mount_fd, handle, flags) };
    (rc as c_int, host_errno())
}

fn fl_open_by_handle_at(mount_fd: c_int, handle: *mut c_void, flags: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::open_by_handle_at(mount_fd, handle, flags) };
    (rc, fl_errno())
}

#[test]
fn file_handle_invalid_failures_match_host_syscall() {
    let mut mount_id = 0;
    let host = host_name_to_handle_at(
        libc::AT_FDCWD,
        c".".as_ptr(),
        ptr::null_mut(),
        &mut mount_id,
        0,
    );
    let fl = fl_name_to_handle_at(
        libc::AT_FDCWD,
        c".".as_ptr(),
        ptr::null_mut(),
        &mut mount_id,
        0,
    );

    assert_eq!(
        fl, host,
        "name_to_handle_at(null handle): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let mut handle = MinimalFileHandle {
        handle_bytes: 0,
        handle_type: 0,
    };
    let handle_ptr = (&mut handle as *mut MinimalFileHandle).cast::<c_void>();
    let host = host_open_by_handle_at(-1, handle_ptr, 0);
    let fl = fl_open_by_handle_at(-1, handle_ptr, 0);

    assert_eq!(
        fl, host,
        "open_by_handle_at(invalid mount fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
