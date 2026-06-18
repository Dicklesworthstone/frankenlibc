#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux I/O priority syscalls.
//!
//! glibc does not expose stable high-level wrappers here on all targets, so the
//! oracle is the host kernel reached through `libc::syscall`. Invalid `which`
//! values fail before mutating any process I/O priority state.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long};

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

fn host_ioprio_get(which: c_int, who: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(libc::SYS_ioprio_get, which, who) as c_long };
    (rc as c_int, host_errno())
}

fn host_ioprio_set(which: c_int, who: c_int, ioprio: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(libc::SYS_ioprio_set, which, who, ioprio) as c_long };
    (rc as c_int, host_errno())
}

#[test]
fn ioprio_invalid_which_matches_host_syscall() {
    let (host_get_rc, host_get_err) = host_ioprio_get(-1, 0);
    set_fl_errno(0);
    let fl_get_rc = unsafe { fl::ioprio_get(-1, 0) };
    let fl_get_err = fl_errno();
    assert_eq!(
        (fl_get_rc, fl_get_err),
        (host_get_rc, host_get_err),
        "ioprio_get(invalid which): fl=({fl_get_rc}, {fl_get_err}) \
         host=({host_get_rc}, {host_get_err})"
    );
    assert_eq!((fl_get_rc, fl_get_err), (-1, libc::EINVAL));

    let (host_set_rc, host_set_err) = host_ioprio_set(-1, 0, 0);
    set_fl_errno(0);
    let fl_set_rc = unsafe { fl::ioprio_set(-1, 0, 0) };
    let fl_set_err = fl_errno();
    assert_eq!(
        (fl_set_rc, fl_set_err),
        (host_set_rc, host_set_err),
        "ioprio_set(invalid which): fl=({fl_set_rc}, {fl_set_err}) \
         host=({host_set_rc}, {host_set_err})"
    );
    assert_eq!((fl_set_rc, fl_set_err), (-1, libc::EINVAL));
}
