#![cfg(target_os = "linux")]

//! Integration tests for `<sys/resource.h>` ABI entrypoints.
//!
//! Covers: getrlimit, setrlimit.

use frankenlibc_abi::resource_abi::{getrlimit, setrlimit};

// ---------------------------------------------------------------------------
// getrlimit
// ---------------------------------------------------------------------------

#[test]
fn getrlimit_nofile() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_NOFILE) should succeed");
    assert!(rlim.rlim_cur > 0, "soft limit should be > 0");
    assert!(
        rlim.rlim_max >= rlim.rlim_cur,
        "hard limit should be >= soft limit"
    );
}

#[test]
fn getrlimit_stack() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_STACK as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_STACK) should succeed");
    assert!(rlim.rlim_cur > 0, "stack soft limit should be > 0");
}

#[test]
fn getrlimit_null_fails() {
    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, std::ptr::null_mut()) };
    assert_eq!(rc, -1, "getrlimit with null ptr should fail");
}

// ---------------------------------------------------------------------------
// setrlimit
// ---------------------------------------------------------------------------

#[test]
fn setrlimit_nofile_same_value() {
    // Get current value, then set it back to the same value
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, &mut rlim) };
    assert_eq!(rc, 0);

    let rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, &rlim) };
    assert_eq!(rc, 0, "setrlimit to current value should succeed");
}

#[test]
fn setrlimit_lower_soft_limit() {
    // Lower the soft limit, then restore it
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, &mut rlim) };
    assert_eq!(rc, 0);

    let original = rlim;
    if rlim.rlim_cur > 64 {
        rlim.rlim_cur = 64;
        let rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, &rlim) };
        assert_eq!(rc, 0, "lowering soft limit should succeed");

        // Verify it took effect
        let mut check: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, &mut check) };
        assert_eq!(rc, 0);
        assert_eq!(check.rlim_cur, 64);

        // Restore
        let rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, &original) };
        assert_eq!(rc, 0);
    }
}

#[test]
fn setrlimit_null_fails() {
    let rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, std::ptr::null()) };
    assert_eq!(rc, -1, "setrlimit with null ptr should fail");
}

// ---------------------------------------------------------------------------
// getrlimit — additional resource types
// ---------------------------------------------------------------------------

#[test]
fn getrlimit_as() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_AS as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_AS) should succeed");
    // Address space limit: either a positive value or RLIM_INFINITY
    assert!(
        rlim.rlim_max >= rlim.rlim_cur,
        "hard limit should be >= soft limit for RLIMIT_AS"
    );
}

#[test]
fn getrlimit_fsize() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_FSIZE as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_FSIZE) should succeed");
}

#[test]
fn getrlimit_data() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_DATA as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_DATA) should succeed");
}

#[test]
fn getrlimit_core() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_CORE as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) should succeed");
    assert!(rlim.rlim_max >= rlim.rlim_cur);
}

#[test]
fn getrlimit_nproc() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NPROC as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_NPROC) should succeed");
    assert!(rlim.rlim_cur > 0, "NPROC soft limit should be > 0");
}

// ---------------------------------------------------------------------------
// setrlimit — restore pattern for different resources
// ---------------------------------------------------------------------------

#[test]
fn setrlimit_core_disable_and_restore() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_CORE as i32, &mut rlim) };
    assert_eq!(rc, 0);
    let original = rlim;

    // Disable core dumps
    rlim.rlim_cur = 0;
    let rc = unsafe { setrlimit(libc::RLIMIT_CORE as i32, &rlim) };
    assert_eq!(rc, 0, "disabling core dumps should succeed");

    // Verify
    let mut check: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_CORE as i32, &mut check) };
    assert_eq!(rc, 0);
    assert_eq!(check.rlim_cur, 0, "core soft limit should be 0");

    // Restore
    let rc = unsafe { setrlimit(libc::RLIMIT_CORE as i32, &original) };
    assert_eq!(rc, 0);
}
