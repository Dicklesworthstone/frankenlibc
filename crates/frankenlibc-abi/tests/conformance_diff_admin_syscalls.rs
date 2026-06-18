#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for administrative syscall ABI exports.
//!
//! All cases use invalid/null arguments, so they fail before changing system
//! state while still pinning kernel errno precedence.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_void};
use std::ptr;

const SYS_PIVOT_ROOT: c_long = libc::SYS_pivot_root as c_long;
const SYS_SWAPON: c_long = libc::SYS_swapon as c_long;
const SYS_SWAPOFF: c_long = libc::SYS_swapoff as c_long;
const SYS_QUOTACTL: c_long = libc::SYS_quotactl as c_long;

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

fn host_pivot_root(new_root: *const c_char, put_old: *const c_char) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_PIVOT_ROOT, new_root, put_old) as c_long };
    (rc as c_int, host_errno())
}

fn fl_pivot_root(new_root: *const c_char, put_old: *const c_char) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::pivot_root(new_root, put_old) };
    (rc, fl_errno())
}

fn host_swapon(path: *const c_char, swapflags: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_SWAPON, path, swapflags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_swapon(path: *const c_char, swapflags: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::swapon(path, swapflags) };
    (rc, fl_errno())
}

fn host_swapoff(path: *const c_char) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_SWAPOFF, path) as c_long };
    (rc as c_int, host_errno())
}

fn fl_swapoff(path: *const c_char) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::swapoff(path) };
    (rc, fl_errno())
}

fn host_quotactl(
    cmd: c_int,
    special: *const c_char,
    id: c_int,
    addr: *mut c_void,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_QUOTACTL, cmd, special, id, addr) as c_long };
    (rc as c_int, host_errno())
}

fn fl_quotactl(
    cmd: c_int,
    special: *const c_char,
    id: c_int,
    addr: *mut c_void,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::quotactl(cmd, special, id, addr) };
    (rc, fl_errno())
}

#[test]
fn admin_syscall_invalid_failures_match_host_syscall() {
    let host = host_pivot_root(ptr::null(), ptr::null());
    let fl = fl_pivot_root(ptr::null(), ptr::null());
    assert_eq!(fl, host, "pivot_root(NULL, NULL): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_swapon(ptr::null(), 0);
    let fl = fl_swapon(ptr::null(), 0);
    assert_eq!(fl, host, "swapon(NULL, 0): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_swapoff(ptr::null());
    let fl = fl_swapoff(ptr::null());
    assert_eq!(fl, host, "swapoff(NULL): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_quotactl(0, ptr::null(), 0, ptr::null_mut());
    let fl = fl_quotactl(0, ptr::null(), 0, ptr::null_mut());
    assert_eq!(
        fl, host,
        "quotactl(0, NULL, 0, NULL): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
