#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#![allow(unsafe_code)] // live host-kernel syscall oracle

//! Differential coverage for the Linux `personality` ABI export.
//!
//! `0xffffffff` is the query sentinel, so this test reads the current
//! execution domain without changing it.

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_ulong};

const SYS_PERSONALITY: c_long = libc::SYS_personality as c_long;
const PERSONALITY_QUERY: c_ulong = 0xffff_ffff;

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

fn host_personality(persona: c_ulong) -> (c_int, c_int) {
    set_host_errno(0);
    let rc = unsafe { libc::syscall(SYS_PERSONALITY, persona) as c_long };
    (rc as c_int, host_errno())
}

fn fl_personality(persona: c_ulong) -> (c_int, c_int) {
    set_fl_errno(0);
    let rc = unsafe { fl::personality(persona) };
    (rc, fl_errno())
}

#[test]
fn personality_query_matches_host_syscall() {
    let host = host_personality(PERSONALITY_QUERY);
    let fl = fl_personality(PERSONALITY_QUERY);
    assert_eq!(
        fl, host,
        "personality(0xffffffff query): fl={fl:?} host={host:?}"
    );
    assert!(fl.0 >= 0, "query should return current persona, got {fl:?}");
}
