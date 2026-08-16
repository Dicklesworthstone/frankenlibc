#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc profil oracle

//! Differential gate for `profil`'s disable path (bd-ef7c67).
//!
//! `profil(NULL, 0, 0, 0)` turns PC-sample profiling OFF. It is the one call in
//! this family with a deterministic, side-effect-free outcome, which is why it
//! is the arm worth pinning: everything else in `profil` depends on a live
//! sampling timer.
//!
//! fl delegates to the host and only rewrites errno when the host reports
//! failure, so the disable path must agree with glibc on BOTH the return value
//! and on leaving a pre-set errno alone. Both arms run in this process against
//! the real host symbol — no mocks.

use std::ffi::{c_int, c_uint, c_void};

type SizeT = usize;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn profil(buf: *mut c_void, bufsiz: SizeT, offset: SizeT, scale: c_uint) -> c_int;
    }
}

use frankenlibc_abi::glibc_internal_abi::profil as fl_profil;

/// Disable profiling and report (return value, errno-after).
///
/// `errno` is seeded with a sentinel first: a successful call must not touch it,
/// so a spurious errno write is visible rather than hidden behind a zero.
const SENTINEL: c_int = 0x5eed;

fn host_disable() -> (c_int, c_int) {
    // SAFETY: the NULL/0/0/0 form is profil's documented disable call.
    unsafe {
        *libc::__errno_location() = SENTINEL;
        let rc = g::profil(std::ptr::null_mut(), 0, 0, 0);
        (rc, *libc::__errno_location())
    }
}

fn fl_disable() -> (c_int, c_int) {
    // SAFETY: as above, against fl's implementation and fl's errno slot.
    unsafe {
        frankenlibc_abi::errno_abi::set_abi_errno(SENTINEL);
        let rc = fl_profil(std::ptr::null_mut(), 0, 0, 0);
        (rc, *frankenlibc_abi::errno_abi::__errno_location())
    }
}

#[test]
fn profil_disable_matches_glibc_return_and_preserves_errno() {
    // Order matters only in that both arms see the same process state; the
    // disable call is idempotent, so running host-then-fl and again fl-then-host
    // must give the same answers both ways round.
    let host_first = host_disable();
    let fl_first = fl_disable();

    assert_eq!(
        host_first.0, 0,
        "oracle: profil(NULL,0,0,0) should disable profiling and return 0 (got {host_first:?})"
    );
    assert_eq!(
        fl_first.0, host_first.0,
        "return value diverged: fl={fl_first:?} glibc={host_first:?}"
    );

    // The positive fact this arm exists for: a SUCCESSFUL disable must not
    // clobber errno. fl only rewrites errno when the host reports failure, so a
    // regression that always wrote errno would show up right here.
    assert_eq!(
        host_first.1, SENTINEL,
        "oracle: a successful profil disable should leave errno untouched (got {host_first:?})"
    );
    assert_eq!(
        fl_first.1, host_first.1,
        "errno diverged on the disable path: fl={fl_first:?} glibc={host_first:?}"
    );

    // Idempotent: disabling twice is still a clean no-op, in the other order.
    let fl_again = fl_disable();
    let host_again = host_disable();
    assert_eq!(
        fl_again.0, host_again.0,
        "second disable diverged: fl={fl_again:?} glibc={host_again:?}"
    );
    assert_eq!(
        fl_again.1, host_again.1,
        "second disable errno diverged: fl={fl_again:?} glibc={host_again:?}"
    );
    assert_eq!(
        host_again.0, 0,
        "oracle: repeating the disable should still return 0 (got {host_again:?})"
    );
}
