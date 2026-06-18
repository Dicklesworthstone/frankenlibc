#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for `openat2` and `futex_waitv` raw syscall exports.
//!
//! The exercised paths fail before opening a file or blocking on a futex.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_uint, c_void};
use std::ptr;

const SYS_OPENAT2: c_long = 437;
const SYS_FUTEX_WAITV: c_long = 449;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
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

fn host_openat2(
    dirfd: c_int,
    pathname: *const libc::c_char,
    how: *const c_void,
    size: usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_OPENAT2, dirfd, pathname, how, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_openat2(
    dirfd: c_int,
    pathname: *const libc::c_char,
    how: *const c_void,
    size: usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::openat2(dirfd, pathname, how, size) };
    (rc, fl_errno())
}

fn host_futex_waitv(
    waiters: *const c_void,
    nr_futexes: c_uint,
    flags: c_uint,
    timeout: *const libc::timespec,
    clockid: libc::clockid_t,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_FUTEX_WAITV, waiters, nr_futexes, flags, timeout, clockid) };
    (rc as c_int, host_errno())
}

fn fl_futex_waitv(
    waiters: *const c_void,
    nr_futexes: c_uint,
    flags: c_uint,
    timeout: *const libc::timespec,
    clockid: libc::clockid_t,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::futex_waitv(waiters, nr_futexes, flags, timeout, clockid) };
    (rc, fl_errno())
}

#[test]
fn openat2_and_futex_waitv_invalid_failures_match_host_syscall() {
    let how = OpenHow {
        flags: 0,
        mode: 0,
        resolve: 0,
    };
    let how_ptr = (&how as *const OpenHow).cast::<c_void>();
    let host = host_openat2(libc::AT_FDCWD, c"/tmp".as_ptr(), how_ptr, 1);
    let fl = fl_openat2(libc::AT_FDCWD, c"/tmp".as_ptr(), how_ptr, 1);
    assert_eq!(
        fl, host,
        "openat2(wrong struct size): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_futex_waitv(
        ptr::null(),
        0,
        0,
        ptr::null(),
        libc::CLOCK_MONOTONIC,
    );
    let fl = fl_futex_waitv(
        ptr::null(),
        0,
        0,
        ptr::null(),
        libc::CLOCK_MONOTONIC,
    );
    assert_eq!(
        fl, host,
        "futex_waitv(zero waiters): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
