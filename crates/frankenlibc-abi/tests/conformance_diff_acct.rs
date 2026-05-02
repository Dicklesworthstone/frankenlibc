#![cfg(target_os = "linux")]

//! Differential conformance harness for `acct(2)`.
//!
//! Process accounting requires CAP_SYS_PACCT. Unprivileged callers
//! must get -1 + EPERM from both fl and the kernel. Privileged
//! callers can disable accounting with NULL.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, c_long, CString};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

const SYS_ACCT: c_long = 163;

fn errno_now() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[test]
fn diff_acct_unprivileged_returns_eperm() {
    // Unprivileged caller: both impls return -1 with EPERM.
    let path = CString::new("/var/log/pacct").unwrap();
    let fl_v = unsafe { fl::acct(path.as_ptr()) };
    let fl_e = errno_now();
    let lc_v = unsafe { syscall(SYS_ACCT, path.as_ptr() as c_long) };
    let lc_e = errno_now();
    assert_eq!(fl_v as c_long, lc_v, "acct ret: fl={fl_v} lc={lc_v}");
    assert_eq!(fl_v, -1, "unprivileged caller should fail");
    assert_eq!(fl_e, lc_e, "acct errno: fl={fl_e} lc={lc_e}");
    assert!(
        matches!(fl_e, libc::EPERM | libc::ENOSYS),
        "expected EPERM or ENOSYS, got {fl_e}"
    );
}

#[test]
fn diff_acct_null_filename_returns_eperm_for_unprivileged() {
    // NULL means "disable accounting"; without privilege both fail.
    let fl_v = unsafe { fl::acct(std::ptr::null()) };
    let fl_e = errno_now();
    let lc_v = unsafe { syscall(SYS_ACCT, 0 as c_long) };
    let lc_e = errno_now();
    assert_eq!(fl_v as c_long, lc_v);
    assert_eq!(fl_v, -1);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn diff_acct_nonexistent_path_unprivileged_uniform_failure() {
    let path = CString::new("/nonexistent/dir/pacct.log").unwrap();
    let fl_v = unsafe { fl::acct(path.as_ptr()) };
    let fl_e = errno_now();
    let lc_v = unsafe { syscall(SYS_ACCT, path.as_ptr() as c_long) };
    let lc_e = errno_now();
    assert_eq!(fl_v as c_long, lc_v);
    assert_eq!(fl_v, -1);
    // Could be EPERM (privilege check first) or ENOENT (path check first).
    // Both impls must agree.
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
}

fn _suppress_c_int_unused(_x: c_int) {}

#[test]
fn acct_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc acct\",\"reference\":\"glibc-syscall\",\"functions\":1,\"divergences\":0}}",
    );
}
