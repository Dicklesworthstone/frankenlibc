#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread_attr_setscope oracle

//! Differential gate for pthread_attr_setscope return codes (bd-9bmtq2).
//! glibc distinguishes three cases: PTHREAD_SCOPE_SYSTEM -> 0, PTHREAD_SCOPE_
//! PROCESS -> ENOTSUP (a valid value unsupported on Linux/NPTL), and any other
//! value -> EINVAL. fl previously returned ENOTSUP for everything non-SYSTEM,
//! including invalid values. fl must return the same code as glibc for each
//! scope value. No mocks.

use std::ffi::c_int;

const PTHREAD_SCOPE_SYSTEM: c_int = 0;
const PTHREAD_SCOPE_PROCESS: c_int = 1;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn pthread_attr_init(a: *mut libc::pthread_attr_t) -> c_int;
        pub fn pthread_attr_destroy(a: *mut libc::pthread_attr_t) -> c_int;
        pub fn pthread_attr_setscope(a: *mut libc::pthread_attr_t, scope: c_int) -> c_int;
    }
}
use frankenlibc_abi::pthread_abi as fl;

fn glibc_setscope(scope: c_int) -> c_int {
    let mut a: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    unsafe { g::pthread_attr_init(&mut a) };
    let rc = unsafe { g::pthread_attr_setscope(&mut a, scope) };
    unsafe { g::pthread_attr_destroy(&mut a) };
    rc
}

fn fl_setscope(scope: c_int) -> c_int {
    let mut a: libc::pthread_attr_t = unsafe { std::mem::zeroed() };
    unsafe { fl::pthread_attr_init(&mut a) };
    let rc = unsafe { fl::pthread_attr_setscope(&mut a, scope) };
    unsafe { fl::pthread_attr_destroy(&mut a) };
    rc
}

#[test]
fn pthread_attr_setscope_matches_glibc() {
    for scope in [
        PTHREAD_SCOPE_SYSTEM,
        PTHREAD_SCOPE_PROCESS,
        2,
        3,
        -1,
        99,
        c_int::MAX,
    ] {
        let g = glibc_setscope(scope);
        let f = fl_setscope(scope);
        assert_eq!(f, g, "pthread_attr_setscope({scope}): fl={f} glibc={g}");
    }
    // sanity: the three documented outcomes
    assert_eq!(glibc_setscope(PTHREAD_SCOPE_SYSTEM), 0);
    assert_eq!(glibc_setscope(PTHREAD_SCOPE_PROCESS), libc::ENOTSUP);
    assert_eq!(glibc_setscope(99), libc::EINVAL);
}
