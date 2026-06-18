#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc pthread_mutex_consistent oracle

//! `pthread_mutex_consistent`(`_np`) parity vs host glibc (bd-ssd8j3).
//!
//! glibc returns EINVAL unless the mutex is a robust mutex whose owner is
//! currently marked inconsistent (post-EOWNERDEAD). FrankenLibC's mutexes never
//! enter the owner-died state (`pthread_mutex_lock` never returns EOWNERDEAD,
//! and `pthread_mutex_init` even rejects a robust attribute with EINVAL), so no
//! mutex a caller can construct is ever inconsistent — EINVAL is the correct
//! answer for every reachable case. fl previously returned 0.
//!
//! This gate builds a normal mutex with each implementation and asserts fl
//! agrees with host glibc (EINVAL), for both pthread_mutex_consistent and its
//! GNU alias pthread_mutex_consistent_np. (A robust mutex cannot be constructed
//! under fl — that separate robust-mutex limitation is tracked on the bead —
//! so the robust path is unreachable here.)

use std::ffi::c_int;

unsafe extern "C" {
    fn pthread_mutex_consistent(m: *mut libc::pthread_mutex_t) -> c_int; // host glibc
    // glibc's pthread_mutex_consistent_np exists only as a versioned compat
    // symbol (@GLIBC_2.4) with no default, so it cannot be referenced by the
    // bare name; it is a pure alias of pthread_mutex_consistent (used as the
    // oracle for fl's _np entry point).
}

use frankenlibc_abi::glibc_internal_abi::pthread_mutex_consistent_np as fl_consistent_np;
use frankenlibc_abi::pthread_abi::pthread_mutex_consistent as fl_consistent;

fn new_normal_mutex() -> libc::pthread_mutex_t {
    // PTHREAD_MUTEX_INITIALIZER is all-zero on Linux.
    unsafe { std::mem::zeroed() }
}

#[test]
fn consistent_on_normal_mutex_matches_glibc() {
    let mut gm = new_normal_mutex();
    let mut fm = new_normal_mutex();
    let g = unsafe { pthread_mutex_consistent(&mut gm) };
    let f = unsafe { fl_consistent(&mut fm) };
    assert_eq!(
        g,
        libc::EINVAL,
        "glibc: consistent on a non-inconsistent mutex -> EINVAL"
    );
    assert_eq!(f, g, "fl consistent rc {f} != glibc {g}");
}

#[test]
fn consistent_np_alias_matches_glibc() {
    // The GNU alias delegates to the same core; compare against glibc's
    // canonical pthread_mutex_consistent (the _np form is a pure alias).
    let mut gm = new_normal_mutex();
    let g = unsafe { pthread_mutex_consistent(&mut gm) };
    let mut fm = new_normal_mutex();
    let f_np = unsafe { fl_consistent_np((&mut fm as *mut libc::pthread_mutex_t).cast()) };
    assert_eq!(f_np, g, "fl consistent_np {f_np} != glibc consistent {g}");
}
