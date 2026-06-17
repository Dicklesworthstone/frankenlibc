//! Differential gate: getgrouplist() partial-fills the caller's buffer on
//! overflow, matching glibc.
//!
//! glibc copies MIN(found, *ngroups) group IDs into the buffer unconditionally —
//! including when the buffer is too small and it returns -1 (it sets *ngroups to
//! the needed count). fl previously left the buffer untouched on overflow. We
//! call getgrouplist with a 1-entry buffer for a user who belongs to >= 2 groups
//! and require fl and glibc to agree on rc, *ngroups, and the written prefix.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_char, c_int};

type GglFn = unsafe extern "C" fn(*const c_char, libc::gid_t, *mut libc::gid_t, *mut c_int) -> c_int;

const SENTINEL: libc::gid_t = 0xDEAD_BEEF;

fn current_user() -> *const c_char {
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        assert!(!pw.is_null(), "getpwuid");
        (*pw).pw_name
    }
}

/// Overflow call with a 1-entry buffer; returns (rc, ngroups_after, buf0).
fn overflow_call(f: GglFn, user: *const c_char, gid: libc::gid_t) -> (c_int, c_int, libc::gid_t) {
    let mut buf = [SENTINEL; 8];
    let mut ng: c_int = 1;
    let rc = unsafe { f(user, gid, buf.as_mut_ptr(), &mut ng) };
    (rc, ng, buf[0])
}

#[test]
fn getgrouplist_overflow_partial_fill_matches_glibc() {
    let user = current_user();
    let gid = unsafe { libc::getgid() };

    // Total group count (large buffer) — both engines should agree.
    let mut big = [0 as libc::gid_t; 64];
    let mut ng_big: c_int = 64;
    let total = unsafe { libc::getgrouplist(user, gid, big.as_mut_ptr(), &mut ng_big) };
    if total < 2 {
        eprintln!("user belongs to < 2 groups; cannot exercise overflow partial-fill");
        return;
    }

    let g = overflow_call(libc::getgrouplist, user, gid);
    let f = overflow_call(fl::getgrouplist, user, gid);

    assert_eq!(g.0, -1, "glibc getgrouplist should overflow (rc=-1)");
    assert_eq!(g.1, total, "glibc *ngroups should be the needed count");
    assert_ne!(g.2, SENTINEL, "glibc should partial-fill buf[0]");
    assert_eq!(g.2, gid, "glibc buf[0] should be the primary gid");

    assert_eq!(f.0, g.0, "rc: glibc={} fl={}", g.0, f.0);
    assert_eq!(f.1, g.1, "*ngroups: glibc={} fl={}", g.1, f.1);
    assert_eq!(
        f.2, g.2,
        "buf[0] after overflow: glibc={:#x} fl={:#x} (fl left it untouched before the fix)",
        g.2, f.2
    );
}
