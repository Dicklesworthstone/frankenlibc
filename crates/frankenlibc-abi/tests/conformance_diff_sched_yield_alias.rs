#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc __sched_yield oracle
//! Differential gate for glibc's internal `__sched_yield` alias (bd-ml4ynz).
//!
//! `sched_yield` cannot fail on Linux — the syscall always succeeds — so the
//! whole observable contract is "returns 0 and does not disturb errno". That
//! makes it exactly the kind of surface where a wrapper can quietly go wrong
//! (returning the raw syscall result, or writing errno on success) and no test
//! notices, so both observables are compared here against the live host.
//!
//! `__sched_yield` is an internal alias, so it is resolved from the host with
//! `dlsym` on an explicit `libc.so.6` handle rather than declared at link time.

use frankenlibc_abi::{errno_abi, glibc_internal_abi as fl};
use std::ffi::{c_int, c_void};

type YieldFn = unsafe extern "C" fn() -> c_int;

union YieldSymbol {
    raw: *mut c_void,
    function: YieldFn,
}

fn host_sched_yield() -> YieldFn {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(handle, c"__sched_yield".as_ptr()) };
    assert!(
        !raw.is_null(),
        "dlsym __sched_yield — the internal alias should exist in host glibc"
    );
    // SAFETY: the resolved symbol has glibc's documented __sched_yield signature.
    unsafe { YieldSymbol { raw }.function }
}

/// errno is seeded so a spurious write on success is visible rather than hidden
/// behind a zero.
const SENTINEL: c_int = 0x5eed;

#[test]
fn sched_yield_alias_matches_glibc_success_and_errno_contract() {
    let host = host_sched_yield();

    // Repeat: yielding is a scheduler interaction, so run it enough times that a
    // wrapper which only misbehaves on a reschedule would be caught.
    for iteration in 0..64 {
        // SAFETY: errno location is always valid; the call takes no arguments.
        let host_out = unsafe {
            *libc::__errno_location() = SENTINEL;
            let rc = host();
            (rc, *libc::__errno_location())
        };
        // SAFETY: as above, against fl's alias and fl's errno slot.
        let fl_out = unsafe {
            errno_abi::set_abi_errno(SENTINEL);
            let rc = fl::__sched_yield();
            (rc, *errno_abi::__errno_location())
        };

        assert_eq!(
            host_out.0, 0,
            "oracle: sched_yield cannot fail on Linux (iteration {iteration}, got {host_out:?})"
        );
        assert_eq!(
            host_out.1, SENTINEL,
            "oracle: a successful sched_yield should leave errno untouched \
             (iteration {iteration}, got {host_out:?})"
        );
        assert_eq!(
            fl_out, host_out,
            "__sched_yield diverged on iteration {iteration}: fl={fl_out:?} glibc={host_out:?}"
        );
    }
}

/// The public `sched_yield` and the internal `__sched_yield` alias must agree
/// with each other as well as with the host — an alias that drifted from its
/// primary would otherwise pass the arm above while breaking callers that use
/// the other name.
#[test]
fn sched_yield_alias_agrees_with_the_public_entry_point() {
    // SAFETY: neither call takes arguments and both are total on Linux.
    let alias = unsafe {
        errno_abi::set_abi_errno(SENTINEL);
        let rc = fl::__sched_yield();
        (rc, *errno_abi::__errno_location())
    };
    // SAFETY: as above.
    let public = unsafe {
        errno_abi::set_abi_errno(SENTINEL);
        let rc = frankenlibc_abi::poll_abi::sched_yield();
        (rc, *errno_abi::__errno_location())
    };
    assert_eq!(
        alias, public,
        "fl's __sched_yield alias and sched_yield disagree: alias={alias:?} public={public:?}"
    );
    assert_eq!(alias.0, 0, "both should report success");
}
