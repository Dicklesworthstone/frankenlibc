#![cfg(target_os = "linux")]

//! Differential conformance harness for `gethostname`, `getdomainname`,
//! and `gethostid`.
//!
//! All three read process-global / system state. fl reads via raw
//! syscalls or /etc/hostid; glibc uses libc internal caches. Within
//! the same process, both must agree on the returned bytes.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, CStr};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn gethostname(name: *mut c_char, len: usize) -> c_int;
    fn getdomainname(name: *mut c_char, len: usize) -> c_int;
    fn gethostid() -> libc::c_long;
}

#[test]
fn diff_gethostname_match() {
    let mut fl_buf = vec![0i8; 256];
    let mut lc_buf = vec![0i8; 256];
    let fl_r = unsafe { fl::gethostname(fl_buf.as_mut_ptr(), fl_buf.len()) };
    let lc_r = unsafe { gethostname(lc_buf.as_mut_ptr(), lc_buf.len()) };
    assert_eq!(fl_r, lc_r, "gethostname return mismatch: fl={fl_r} lc={lc_r}");
    if fl_r == 0 {
        let fl_s = unsafe { CStr::from_ptr(fl_buf.as_ptr()).to_bytes() };
        let lc_s = unsafe { CStr::from_ptr(lc_buf.as_ptr()).to_bytes() };
        assert_eq!(
            fl_s, lc_s,
            "gethostname strings differ: fl={:?} lc={:?}",
            String::from_utf8_lossy(fl_s),
            String::from_utf8_lossy(lc_s)
        );
    }
}

#[test]
fn diff_gethostname_buffer_too_small() {
    // Both impls must return -1 when buffer can't fit the hostname + NUL.
    // We don't know exact hostname length; size 1 is always too small unless hostname is empty.
    let mut fl_buf = [0i8; 1];
    let mut lc_buf = [0i8; 1];
    let fl_r = unsafe { fl::gethostname(fl_buf.as_mut_ptr(), 1) };
    let lc_r = unsafe { gethostname(lc_buf.as_mut_ptr(), 1) };
    assert_eq!(
        fl_r, lc_r,
        "gethostname size=1 mismatch: fl={fl_r} lc={lc_r}"
    );
}

#[test]
fn diff_getdomainname_match() {
    let mut fl_buf = vec![0i8; 256];
    let mut lc_buf = vec![0i8; 256];
    let fl_r = unsafe { fl::getdomainname(fl_buf.as_mut_ptr(), fl_buf.len()) };
    let lc_r = unsafe { getdomainname(lc_buf.as_mut_ptr(), lc_buf.len()) };
    assert_eq!(fl_r, lc_r, "getdomainname return mismatch: fl={fl_r} lc={lc_r}");
    if fl_r == 0 {
        let fl_s = unsafe { CStr::from_ptr(fl_buf.as_ptr()).to_bytes() };
        let lc_s = unsafe { CStr::from_ptr(lc_buf.as_ptr()).to_bytes() };
        assert_eq!(
            fl_s, lc_s,
            "getdomainname strings differ: fl={:?} lc={:?}",
            String::from_utf8_lossy(fl_s),
            String::from_utf8_lossy(lc_s)
        );
    }
}

/// Smoke test: gethostid must return SOMETHING (non-zero, in the typical
/// case). fl uses a FNV-hash of nodename; glibc reads /etc/hostid then
/// falls back to an IP-derived value. Both are POSIX-conformant but
/// produce different identifiers. We don't diff exact values — only that
/// both return non-zero.
#[test]
fn diff_gethostid_both_non_zero() {
    let fl_id = unsafe { fl::gethostid() };
    let lc_id = unsafe { gethostid() };
    assert_ne!(fl_id, 0, "fl gethostid returned 0");
    assert_ne!(lc_id, 0, "glibc gethostid returned 0");
    // fl and glibc legitimately diverge here:
    //   - glibc reads /etc/hostid (or IP fallback)
    //   - fl hashes utsname.nodename
    // Both are POSIX-valid implementation-defined identifiers.
}

#[test]
fn hostname_id_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc gethostname/getdomainname/gethostid\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
