#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux 6.13+ xattr-at syscalls and open_tree_attr.
//!
//! Invalid fd/flag paths fail before changing extended attributes or opening a
//! mount tree. Older kernels naturally exercise ENOSYS parity.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int, c_long, c_uint, c_void};
use std::ptr;

const SYS_SETXATTRAT: c_long = 463;
const SYS_GETXATTRAT: c_long = 464;
const SYS_LISTXATTRAT: c_long = 465;
const SYS_REMOVEXATTRAT: c_long = 466;
const SYS_OPEN_TREE_ATTR: c_long = 467;

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

fn host_setxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
    uargs: *const c_void,
    size: usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_SETXATTRAT, dirfd, path, at_flags, name, uargs, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_setxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
    uargs: *const c_void,
    size: usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::setxattrat(dirfd, path, at_flags, name, uargs, size) };
    (rc, fl_errno())
}

fn host_getxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
    uargs: *mut c_void,
    size: usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_GETXATTRAT, dirfd, path, at_flags, name, uargs, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_getxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
    uargs: *mut c_void,
    size: usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::getxattrat(dirfd, path, at_flags, name, uargs, size) };
    (rc, fl_errno())
}

fn host_listxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    list: *mut c_char,
    size: usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_LISTXATTRAT, dirfd, path, at_flags, list, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_listxattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    list: *mut c_char,
    size: usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::listxattrat(dirfd, path, at_flags, list, size) };
    (rc, fl_errno())
}

fn host_removexattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_REMOVEXATTRAT, dirfd, path, at_flags, name) as c_long };
    (rc as c_int, host_errno())
}

fn fl_removexattrat(
    dirfd: c_int,
    path: *const c_char,
    at_flags: c_uint,
    name: *const c_char,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::removexattrat(dirfd, path, at_flags, name) };
    (rc, fl_errno())
}

fn host_open_tree_attr(
    dirfd: c_int,
    path: *const c_char,
    flags: c_uint,
    attr: *mut c_void,
    size: usize,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc =
        unsafe { libc::syscall(SYS_OPEN_TREE_ATTR, dirfd, path, flags, attr, size) as c_long };
    (rc as c_int, host_errno())
}

fn fl_open_tree_attr(
    dirfd: c_int,
    path: *const c_char,
    flags: c_uint,
    attr: *mut c_void,
    size: usize,
) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::open_tree_attr(dirfd, path, flags, attr, size) };
    (rc, fl_errno())
}

#[test]
fn xattrat_and_open_tree_attr_invalid_failures_match_host_syscall() {
    let path = c".";
    let name = c"user.frankenlibc.invalid";

    let host = host_setxattrat(-1, path.as_ptr(), 0, name.as_ptr(), ptr::null(), 0);
    let fl = fl_setxattrat(-1, path.as_ptr(), 0, name.as_ptr(), ptr::null(), 0);
    assert_eq!(fl, host, "setxattrat(invalid fd): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_getxattrat(
        -1,
        path.as_ptr(),
        0,
        name.as_ptr(),
        ptr::null_mut(),
        0,
    );
    let fl = fl_getxattrat(
        -1,
        path.as_ptr(),
        0,
        name.as_ptr(),
        ptr::null_mut(),
        0,
    );
    assert_eq!(fl, host, "getxattrat(invalid fd): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_listxattrat(-1, path.as_ptr(), 0, ptr::null_mut(), 0);
    let fl = fl_listxattrat(-1, path.as_ptr(), 0, ptr::null_mut(), 0);
    assert_eq!(fl, host, "listxattrat(invalid fd): fl={fl:?} host={host:?}");
    assert_eq!(fl.0, -1);

    let host = host_removexattrat(-1, path.as_ptr(), 0, name.as_ptr());
    let fl = fl_removexattrat(-1, path.as_ptr(), 0, name.as_ptr());
    assert_eq!(
        fl, host,
        "removexattrat(invalid fd): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);

    let host = host_open_tree_attr(
        libc::AT_FDCWD,
        c"/".as_ptr(),
        c_uint::MAX,
        ptr::null_mut(),
        0,
    );
    let fl = fl_open_tree_attr(
        libc::AT_FDCWD,
        c"/".as_ptr(),
        c_uint::MAX,
        ptr::null_mut(),
        0,
    );
    assert_eq!(
        fl, host,
        "open_tree_attr(invalid flags): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
