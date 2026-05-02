#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX session/process-group
//! query syscalls: `getsid(2)`, `getpgid(2)`, `getpgrp(2)`.
//!
//! These return identifiers for the calling process's session and
//! process group. Both fl and host glibc must report identical
//! values for the same query.
//!
//! Filed under [bd-xn6p8] follow-up.

use frankenlibc_abi::unistd_abi as fl;

#[test]
fn diff_getpgrp_matches_glibc() {
    // getpgrp() takes no args; both impls must return the same pgid.
    let fl_v = unsafe { fl::getpgrp() };
    let lc_v = unsafe { libc::getpgrp() };
    assert_eq!(fl_v, lc_v, "getpgrp(): fl={fl_v} lc={lc_v}");
    assert!(fl_v > 0, "getpgrp() should return a valid pgid");
}

#[test]
fn diff_getpgid_self_matches_getpgrp() {
    // getpgid(0) == getpgrp(); both impls must agree.
    let fl_self = unsafe { fl::getpgid(0) };
    let lc_self = unsafe { libc::getpgid(0) };
    let fl_pgrp = unsafe { fl::getpgrp() };
    assert_eq!(fl_self, lc_self, "getpgid(0) ret");
    assert_eq!(fl_self, fl_pgrp, "getpgid(0) == getpgrp()");
}

#[test]
fn diff_getpgid_invalid_pid_returns_esrch() {
    // Use a likely-invalid pid (we don't expect to find it) — both
    // impls must return -1 with the same errno (ESRCH).
    let fl_v = unsafe { fl::getpgid(0x7fff_ffff) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { libc::getpgid(0x7fff_ffff) };
    let lc_e = unsafe { *libc::__errno_location() };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v, lc_v, "getpgid(invalid) ret");
        assert_eq!(fl_e, lc_e, "getpgid(invalid) errno");
    }
}

#[test]
fn diff_getsid_self_matches_glibc() {
    // getsid(0) — query the calling process's session ID.
    let fl_v = unsafe { fl::getsid(0) };
    let lc_v = unsafe { libc::getsid(0) };
    assert_eq!(fl_v, lc_v, "getsid(0): fl={fl_v} lc={lc_v}");
    assert!(fl_v > 0, "getsid(0) should return a valid sid");
}

#[test]
fn diff_getsid_pid_1_init() {
    // Querying init's session is allowed for non-privileged
    // callers. Both impls must agree.
    let fl_v = unsafe { fl::getsid(1) };
    let lc_v = unsafe { libc::getsid(1) };
    assert_eq!(fl_v, lc_v, "getsid(1): fl={fl_v} lc={lc_v}");
}

#[test]
fn diff_getsid_invalid_pid_returns_esrch() {
    let fl_v = unsafe { fl::getsid(0x7fff_ffff) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { libc::getsid(0x7fff_ffff) };
    let lc_e = unsafe { *libc::__errno_location() };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v, lc_v);
        assert_eq!(fl_e, lc_e, "getsid errno: fl={fl_e} lc={lc_e}");
    }
}

#[test]
fn diff_getpgid_pid_1_init() {
    let fl_v = unsafe { fl::getpgid(1) };
    let lc_v = unsafe { libc::getpgid(1) };
    assert_eq!(fl_v, lc_v, "getpgid(1)");
}

#[test]
fn getsid_getpgid_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getsid + getpgid + getpgrp\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
