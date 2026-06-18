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

fn host_name_to_handle_at(
    dirfd: c_int,
    path: *const c_char,
    handle: *mut c_void,
    mount_id: *mut c_int,
    flags: c_int,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe {
        libc::syscall(SYS_NAME_TO_HANDLE_AT, dirfd, path, handle, mount_id, flags) as c_long
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
    let rc = unsafe { libc::syscall(SYS_OPEN_BY_HANDLE_AT, mount_fd, handle, flags) as c_long };
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
