#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `kcmp`.
//!
//! Invalid resource types fail before permission-sensitive comparison paths and
//! do not mutate kernel state, making them stable host-syscall oracle cases.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_ulong};

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

fn host_kcmp(
    pid1: libc::pid_t,
    pid2: libc::pid_t,
    type_: c_int,
    idx1: c_ulong,
    idx2: c_ulong,
) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(libc::SYS_kcmp, pid1, pid2, type_, idx1, idx2) as c_long };
    (rc as c_int, host_errno())
}

#[test]
fn kcmp_invalid_resource_type_matches_host_syscall() {
    let pid = unsafe { libc::getpid() };

    for type_ in [-1, 999] {
        let (host_rc, host_err) = host_kcmp(pid, pid, type_, 0, 0);
        set_fl_errno(0);
        let fl_rc = unsafe { fl::kcmp(pid, pid, type_, 0, 0) };
        let fl_err = fl_errno();

        assert_eq!(
            (fl_rc, fl_err),
            (host_rc, host_err),
            "kcmp(invalid type {type_}): fl=({fl_rc}, {fl_err}) \
             host=({host_rc}, {host_err})"
        );
        assert_eq!(
            (fl_rc, fl_err),
            (-1, libc::EINVAL),
            "kcmp(invalid type {type_}) should fail with EINVAL"
        );
    }
}
