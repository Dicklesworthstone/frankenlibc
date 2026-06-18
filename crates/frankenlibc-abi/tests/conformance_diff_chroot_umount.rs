#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for `chroot` and `umount2` ABI exports.
//!
//! NULL path cases fail before changing process root or mount state.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long};
use std::ptr;

const SYS_CHROOT: c_long = libc::SYS_chroot as c_long;
const SYS_UMOUNT2: c_long = libc::SYS_umount2 as c_long;

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

fn host_chroot(path: *const c_char) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_CHROOT, path) as c_long };
    (rc as c_int, host_errno())
}

fn fl_chroot(path: *const c_char) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::chroot(path) };
    (rc, fl_errno())
}

fn host_umount2(target: *const c_char, flags: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_UMOUNT2, target, flags) as c_long };
    (rc as c_int, host_errno())
}

fn fl_umount2(target: *const c_char, flags: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::umount2(target, flags) };
    (rc, fl_errno())
}

#[test]
fn chroot_umount_null_path_failures_match_host_syscall() {
    let host = host_chroot(ptr::null());
    let fl = fl_chroot(ptr::null());
    assert_eq!(fl, host, "chroot(NULL): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_umount2(ptr::null(), 0);
    let fl = fl_umount2(ptr::null(), 0);
    assert_eq!(fl, host, "umount2(NULL, 0): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);
}
