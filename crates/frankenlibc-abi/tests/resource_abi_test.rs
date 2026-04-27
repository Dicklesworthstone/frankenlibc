#![cfg(target_os = "linux")]

//! Integration tests for `<sys/resource.h>` ABI entrypoints.
//!
//! Covers: getrlimit, setrlimit.

use std::ffi::c_void;

use frankenlibc_abi::resource_abi::{getrlimit, setrlimit};

unsafe fn malloc_tracked_zeroed_bytes(len: usize) -> *mut c_void {
    let raw = unsafe { frankenlibc_abi::malloc_abi::malloc(len) }.cast::<u8>();
    assert!(!raw.is_null());
    unsafe { std::ptr::write_bytes(raw, 0, len) };
    raw.cast()
}

fn assert_known_short(raw: *const c_void, required: usize) {
    let remaining =
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(raw).unwrap_or(usize::MAX);
    assert_ne!(
        remaining,
        usize::MAX,
        "test allocation should be tracked by malloc metadata"
    );
    assert!(
        remaining < required,
        "test allocation should expose {remaining} tracked bytes, less than required {required}"
    );
}

fn errno_value() -> i32 {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
}

unsafe fn free_tracked(raw: *mut c_void) {
    unsafe { frankenlibc_abi::malloc_abi::free(raw) };
}

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

#[test]
fn getrlimit_rejects_tracked_short_rlimit() {
    let required = std::mem::size_of::<libc::rlimit>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, raw.cast()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
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

#[test]
fn setrlimit_rejects_tracked_short_rlimit() {
    let required = std::mem::size_of::<libc::rlimit>();
    let raw = unsafe { malloc_tracked_zeroed_bytes(required - 1) };
    assert_known_short(raw, required);

    let rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, raw.cast()) };

    assert_eq!(rc, -1);
    assert_eq!(errno_value(), libc::EFAULT);
    unsafe { free_tracked(raw) };
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
fn getrlimit_invalid_resource_fails() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(9999, &mut rlim) };
    assert_eq!(rc, -1, "getrlimit with invalid resource should fail");
}

#[test]
fn getrlimit_cpu() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_CPU as i32, &mut rlim) };
    assert_eq!(rc, 0, "getrlimit(RLIMIT_CPU) should succeed");
    assert!(rlim.rlim_max >= rlim.rlim_cur);
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

// ---------------------------------------------------------------------------
// getrlimit — more resource types
// ---------------------------------------------------------------------------

#[test]
fn getrlimit_nproc_if_supported() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NPROC as i32, &mut rlim) };
    if rc == 0 {
        assert!(rlim.rlim_max >= rlim.rlim_cur);
    }
    // rc == -1 is acceptable if the resource type isn't supported
}

#[test]
fn getrlimit_memlock_if_supported() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_MEMLOCK as i32, &mut rlim) };
    if rc == 0 {
        assert!(rlim.rlim_max >= rlim.rlim_cur);
    }
}

#[test]
fn getrlimit_rss_if_supported() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_RSS as i32, &mut rlim) };
    // Either succeeds (0) or unsupported (-1)
    assert!(rc == 0 || rc == -1);
}

#[test]
fn getrlimit_locks_if_supported() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_LOCKS as i32, &mut rlim) };
    assert!(rc == 0 || rc == -1);
}

#[test]
fn getrlimit_sigpending_if_supported() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_SIGPENDING as i32, &mut rlim) };
    if rc == 0 {
        assert!(rlim.rlim_max >= rlim.rlim_cur);
    }
}

#[test]
fn getrlimit_msgqueue_if_supported() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_MSGQUEUE as i32, &mut rlim) };
    assert!(rc == 0 || rc == -1);
}

// ---------------------------------------------------------------------------
// setrlimit — error cases
// ---------------------------------------------------------------------------

#[test]
fn setrlimit_invalid_resource_fails() {
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { setrlimit(9999, &rlim) };
    assert_eq!(rc, -1, "setrlimit with invalid resource should fail");
}

#[test]
fn setrlimit_soft_exceeding_hard_fails() {
    // Try to set soft limit above hard limit — should fail
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, &mut rlim) };
    assert_eq!(rc, 0);

    // Only test if hard limit isn't RLIM_INFINITY
    if rlim.rlim_max != libc::RLIM_INFINITY {
        let bad = libc::rlimit {
            rlim_cur: rlim.rlim_max + 1,
            rlim_max: rlim.rlim_max,
        };
        let rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, &bad) };
        assert_eq!(rc, -1, "soft > hard should fail");
    }
}

#[test]
fn setrlimit_preserves_kernel_errno_on_failed_raise() {
    let mut current: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_NOFILE as i32, &mut current) };
    assert_eq!(rc, 0);

    if current.rlim_max == libc::RLIM_INFINITY {
        return;
    }

    let attempted = libc::rlimit {
        rlim_cur: current.rlim_max.saturating_add(1),
        rlim_max: current.rlim_max.saturating_add(1),
    };

    unsafe {
        *libc::__errno_location() = 0;
    }
    let libc_rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &attempted) };
    assert_eq!(
        libc_rc, -1,
        "host libc should reject an unprivileged hard-limit raise"
    );
    let libc_err = unsafe { *libc::__errno_location() };

    let abi_rc = unsafe { setrlimit(libc::RLIMIT_NOFILE as i32, &attempted) };
    assert_eq!(
        abi_rc, -1,
        "ABI setrlimit should also fail for the same request"
    );
    let abi_err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    assert_eq!(
        abi_err, libc_err,
        "ABI errno should preserve the real kernel failure"
    );
}

// ---------------------------------------------------------------------------
// getrlimit/setrlimit round-trip for various resources
// ---------------------------------------------------------------------------

#[test]
fn getrlimit_setrlimit_round_trip_stack() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_STACK as i32, &mut rlim) };
    assert_eq!(rc, 0);

    // Set same value back
    let rc = unsafe { setrlimit(libc::RLIMIT_STACK as i32, &rlim) };
    assert_eq!(rc, 0, "setting stack limit to current value should succeed");

    // Verify unchanged
    let mut check: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_STACK as i32, &mut check) };
    assert_eq!(rc, 0);
    assert_eq!(check.rlim_cur, rlim.rlim_cur);
    assert_eq!(check.rlim_max, rlim.rlim_max);
}

#[test]
fn getrlimit_setrlimit_round_trip_data() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_DATA as i32, &mut rlim) };
    assert_eq!(rc, 0);

    let rc = unsafe { setrlimit(libc::RLIMIT_DATA as i32, &rlim) };
    assert_eq!(rc, 0, "setting data limit to current value should succeed");
}

#[test]
fn getrlimit_setrlimit_round_trip_fsize() {
    let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { getrlimit(libc::RLIMIT_FSIZE as i32, &mut rlim) };
    assert_eq!(rc, 0);

    let rc = unsafe { setrlimit(libc::RLIMIT_FSIZE as i32, &rlim) };
    assert_eq!(rc, 0, "setting fsize limit to current value should succeed");
}

// ---------------------------------------------------------------------------
// Hard limit invariant: hard >= soft for all readable resources
// ---------------------------------------------------------------------------

#[test]
fn all_readable_resources_hard_geq_soft() {
    // Only test resources known to be supported by the implementation
    let resources: &[(i32, &str)] = &[
        (libc::RLIMIT_NOFILE as i32, "NOFILE"),
        (libc::RLIMIT_STACK as i32, "STACK"),
        (libc::RLIMIT_AS as i32, "AS"),
        (libc::RLIMIT_CORE as i32, "CORE"),
        (libc::RLIMIT_CPU as i32, "CPU"),
        (libc::RLIMIT_DATA as i32, "DATA"),
        (libc::RLIMIT_FSIZE as i32, "FSIZE"),
    ];

    for &(res, name) in resources {
        let mut rlim: libc::rlimit = unsafe { std::mem::zeroed() };
        let rc = unsafe { getrlimit(res, &mut rlim) };
        assert_eq!(rc, 0, "getrlimit({name}) should succeed");
        assert!(
            rlim.rlim_max >= rlim.rlim_cur,
            "{name}: hard ({}) should be >= soft ({})",
            rlim.rlim_max,
            rlim.rlim_cur
        );
    }
}
