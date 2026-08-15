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
