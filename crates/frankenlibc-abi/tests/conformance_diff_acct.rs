#![cfg(target_os = "linux")]

//! Differential conformance harness for `acct(2)`.
//!
//! Process accounting requires CAP_SYS_PACCT. Without it, fl and the kernel
//! must both return -1 + EPERM.
//!
//! Every call runs on a thread without CAP_SYS_PACCT
//! ([`host_isolation::without_capability`]). rch workers run offloaded
//! `cargo test` as root, and there `acct(NULL)` really switched off any
//! process accounting the host had enabled, while `acct(path)` could switch it
//! on. The kernel checks the capability before anything else, so without it
//! both arms take the EPERM path for every caller, root included.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CString, c_long};

use frankenlibc_abi::unistd_abi as fl;

#[path = "common/host_isolation.rs"]
mod host_isolation;
use host_isolation::{CAP_SYS_PACCT, without_capability};

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

const SYS_ACCT: c_long = 163;

fn errno_now() -> i32 {
    unsafe { *libc::__errno_location() }
}

/// Calls fl's `acct` and the raw syscall with `path` (NULL for `None`) on a
/// thread without CAP_SYS_PACCT. Returns `((fl_ret, fl_errno), (sys_ret, sys_errno))`.
fn acct_both(path: Option<&'static str>) -> ((i32, i32), (c_long, i32)) {
    without_capability(CAP_SYS_PACCT, move || {
        let path = path.map(|p| CString::new(p).unwrap());
        let ptr = path.as_ref().map_or(std::ptr::null(), |p| p.as_ptr());
        let fl_v = unsafe { fl::acct(ptr) };
        let fl_e = errno_now();
        let lc_v = unsafe { syscall(SYS_ACCT, ptr as c_long) };
        let lc_e = errno_now();
        ((fl_v, fl_e), (lc_v, lc_e))
    })
}

#[test]
fn diff_acct_unprivileged_returns_eperm() {
    let ((fl_v, fl_e), (lc_v, lc_e)) = acct_both(Some("/var/log/pacct"));
    assert_eq!(fl_v as c_long, lc_v, "acct ret: fl={fl_v} lc={lc_v}");
    assert_eq!(fl_e, lc_e, "acct errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_v, -1, "a caller without CAP_SYS_PACCT should fail");
    assert!(
        matches!(fl_e, libc::EPERM | libc::ENOSYS),
        "expected EPERM or ENOSYS, got {fl_e}"
    );
}

#[test]
fn diff_acct_null_filename_returns_eperm_for_unprivileged() {
    // NULL means "disable accounting"; without the capability both refuse.
    let ((fl_v, fl_e), (lc_v, lc_e)) = acct_both(None);
    assert_eq!(fl_v as c_long, lc_v);
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
    assert_eq!(fl_v, -1);
}

#[test]
fn diff_acct_nonexistent_path_unprivileged_uniform_failure() {
    let ((fl_v, fl_e), (lc_v, lc_e)) = acct_both(Some("/nonexistent/dir/pacct.log"));
    assert_eq!(fl_v as c_long, lc_v);
    assert_eq!(fl_v, -1);
    // Could be EPERM (privilege check first) or ENOENT (path check first).
    // Both impls must agree.
    assert_eq!(fl_e, lc_e, "errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn acct_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc acct\",\"reference\":\"glibc-syscall\",\"functions\":1,\"divergences\":0}}",
    );
}
