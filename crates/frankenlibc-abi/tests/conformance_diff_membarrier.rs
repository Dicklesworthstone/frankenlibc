#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for Linux `membarrier`.
//!
//! `MEMBARRIER_CMD_QUERY` is read-only; the invalid command case fails without
//! issuing a process-wide barrier.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_uint};

#[cfg(target_arch = "x86_64")]
const SYS_MEMBARRIER: c_long = 324;
#[cfg(target_arch = "aarch64")]
const SYS_MEMBARRIER: c_long = 283;

const MEMBARRIER_CMD_QUERY: c_int = 0;

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

fn host_membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_MEMBARRIER, cmd, flags, cpu_id) as c_long };
    (rc as c_int, host_errno())
}

fn fl_membarrier(cmd: c_int, flags: c_uint, cpu_id: c_int) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::membarrier(cmd, flags, cpu_id) };
    (rc, fl_errno())
}

#[test]
fn membarrier_query_and_invalid_command_match_host_syscall() {
    let host = host_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    let fl = fl_membarrier(MEMBARRIER_CMD_QUERY, 0, 0);
    assert_eq!(
        fl, host,
        "membarrier(MEMBARRIER_CMD_QUERY): fl={fl:?} host={host:?}"
    );

    let host = host_membarrier(c_int::MAX, 0, 0);
    let fl = fl_membarrier(c_int::MAX, 0, 0);
    assert_eq!(
        fl, host,
        "membarrier(invalid command): fl={fl:?} host={host:?}"
    );
    assert_eq!(fl.0, -1);
}
