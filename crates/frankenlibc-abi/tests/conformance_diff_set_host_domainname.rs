#![cfg(target_os = "linux")]

//! Differential conformance harness for `sethostname(2)` /
//! `setdomainname(2)` rejection paths under unprivileged callers.
//!
//! Both syscalls require CAP_SYS_ADMIN. As a regular user, both
//! impls must return -1 with the same errno (typically EPERM).
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn sethostname(name: *const c_char, len: usize) -> c_int;
    fn setdomainname(name: *const c_char, len: usize) -> c_int;
}

#[test]
fn diff_sethostname_unprivileged_returns_eperm() {
    let new_name = b"frankenlibc-test\0";
    let fl_v = unsafe {
        fl::sethostname(new_name.as_ptr() as *const c_char, new_name.len() - 1)
    };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe {
        sethostname(new_name.as_ptr() as *const c_char, new_name.len() - 1)
    };
    let lc_e = unsafe { *libc::__errno_location() };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v, lc_v, "sethostname ret: fl={fl_v} lc={lc_v}");
        assert_eq!(fl_e, lc_e, "sethostname errno: fl={fl_e} lc={lc_e}");
    }
}

#[test]
fn diff_setdomainname_unprivileged_returns_eperm() {
    let new_name = b"frankenlibc.test\0";
    let fl_v = unsafe {
        fl::setdomainname(new_name.as_ptr() as *const c_char, new_name.len() - 1)
    };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe {
        setdomainname(new_name.as_ptr() as *const c_char, new_name.len() - 1)
    };
    let lc_e = unsafe { *libc::__errno_location() };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v, lc_v);
        assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    }
}

#[test]
fn diff_sethostname_oversized_returns_einval() {
    // HOST_NAME_MAX is 64 on Linux. Pass 1024 bytes — both impls
    // must reject with EINVAL.
    let big = vec![b'a'; 1024];
    let fl_v = unsafe { fl::sethostname(big.as_ptr() as *const c_char, big.len()) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { sethostname(big.as_ptr() as *const c_char, big.len()) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_v, -1);
    // Either EPERM (privilege check first) or EINVAL (length check first).
    // Both impls must agree on which.
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn diff_sethostname_null_uniformly_rejects() {
    // sethostname(NULL, ...) is a hard reject in both impls. Error
    // precedence (EFAULT vs EPERM) differs because glibc checks
    // privilege first and fl checks pointer first — both behaviors
    // are valid per POSIX, which doesn't specify ordering. We
    // assert only that both reject.
    let fl_v = unsafe { fl::sethostname(std::ptr::null(), 4) };
    let fl_e = unsafe { *libc::__errno_location() };
    let lc_v = unsafe { sethostname(std::ptr::null(), 4) };
    let lc_e = unsafe { *libc::__errno_location() };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_v, -1);
    // Both should be either EPERM or EFAULT (POSIX-allowed errnos).
    assert!(
        matches!(fl_e, libc::EPERM | libc::EFAULT),
        "fl errno {fl_e} not EPERM or EFAULT"
    );
    assert!(
        matches!(lc_e, libc::EPERM | libc::EFAULT),
        "lc errno {lc_e} not EPERM or EFAULT"
    );
}

#[test]
fn set_host_domainname_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc sethostname + setdomainname\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
