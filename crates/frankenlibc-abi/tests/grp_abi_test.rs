#![cfg(target_os = "linux")]

//! Integration tests for `<grp.h>` ABI entrypoints.
//!
//! Tests cover: getgrnam, getgrgid, setgrent, endgrent, getgrent,
//! getgrnam_r, getgrgid_r, getgrent_r.
//!
//! Uses the "root" group (gid=0) which exists on all Linux systems.

use std::ffi::{CStr, CString};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::grp_abi::*;
use frankenlibc_core::errno;

static SEQ: AtomicU64 = AtomicU64::new(0);
static GROUP_ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_group_path() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenlibc-grp-test-{}-{seq}.txt",
        std::process::id()
    ))
}

fn with_group_path(path: &std::path::Path, f: impl FnOnce()) {
    let _guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by GROUP_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_GROUP_PATH", path) };
    f();
    // SAFETY: Serialized by GROUP_ENV_LOCK.
    unsafe { std::env::remove_var("FRANKENLIBC_GROUP_PATH") };
}

fn with_group_lock<T>(f: impl FnOnce() -> T) -> T {
    let _guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

// ===========================================================================
// getgrnam / getgrgid
// ===========================================================================

#[test]
fn getgrnam_root() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(!grp.is_null(), "getgrnam(root) should succeed");
        let gr = unsafe { &*grp };
        assert_eq!(gr.gr_gid, 0, "root group should have gid=0");
        let gr_name = unsafe { CStr::from_ptr(gr.gr_name) };
        assert_eq!(gr_name.to_str().unwrap(), "root");
    });
}

#[test]
fn getgrgid_zero() {
    with_group_lock(|| {
        let grp = unsafe { getgrgid(0) };
        assert!(!grp.is_null(), "getgrgid(0) should succeed");
        let gr = unsafe { &*grp };
        assert_eq!(gr.gr_gid, 0);
        let gr_name = unsafe { CStr::from_ptr(gr.gr_name) };
        assert_eq!(gr_name.to_str().unwrap(), "root");
    });
}

#[test]
fn getgrnam_nonexistent() {
    with_group_lock(|| {
        let name = CString::new("nonexistent_group_xyz_99999").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(grp.is_null(), "nonexistent group should return null");
    });
}

#[test]
fn getgrgid_nonexistent() {
    with_group_lock(|| {
        // Use a very high gid unlikely to exist
        let grp = unsafe { getgrgid(99999) };
        assert!(grp.is_null(), "nonexistent gid should return null");
    });
}

#[test]
fn getgrnam_null_returns_null() {
    with_group_lock(|| {
        let grp = unsafe { getgrnam(std::ptr::null()) };
        assert!(grp.is_null());
    });
}

#[test]
fn getgrnam_missing_backend_sets_errno() {
    let missing = temp_group_path();
    with_group_path(&missing, || {
        let name = CString::new("root").unwrap();
        unsafe { *__errno_location() = 0 };
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(grp.is_null());
        assert_eq!(unsafe { *__errno_location() }, errno::ENOENT);
    });
}

// ===========================================================================
// setgrent / getgrent / endgrent
// ===========================================================================

/// All non-reentrant group iteration tests run in a single function
/// because they share thread-local state.
#[test]
fn group_iteration() {
    with_group_lock(|| {
        // --- setgrent + getgrent ---
        unsafe { setgrent() };

        let first = unsafe { getgrent() };
        assert!(!first.is_null(), "first getgrent should return an entry");
        let first_name = unsafe { CStr::from_ptr((*first).gr_name) }
            .to_str()
            .unwrap()
            .to_string();

        // Read a few more
        let mut count = 1;
        loop {
            let ent = unsafe { getgrent() };
            if ent.is_null() {
                break;
            }
            count += 1;
            if count > 100 {
                break; // Safety limit
            }
        }
        assert!(count >= 1, "should enumerate at least 1 group");

        // --- endgrent ---
        unsafe { endgrent() };

        // --- setgrent rewinds ---
        unsafe { setgrent() };
        let rewound = unsafe { getgrent() };
        assert!(!rewound.is_null(), "getgrent after setgrent should work");
        let rewound_name = unsafe { CStr::from_ptr((*rewound).gr_name) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(
            first_name, rewound_name,
            "setgrent should rewind to the first entry"
        );

        unsafe { endgrent() };
    });
}

// ===========================================================================
// getgrnam_r / getgrgid_r (reentrant)
// ===========================================================================

#[test]
fn getgrnam_r_root() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0, "getgrnam_r(root) should succeed");
        assert!(!result.is_null());
        assert_eq!(grp.gr_gid, 0);
    });
}

#[test]
fn getgrgid_r_zero() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc =
            unsafe { getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        assert_eq!(rc, 0, "getgrgid_r(0) should succeed");
        assert!(!result.is_null());
        let name = unsafe { CStr::from_ptr(grp.gr_name) };
        assert_eq!(name.to_str().unwrap(), "root");
    });
}

#[test]
fn getgrnam_r_nonexistent() {
    with_group_lock(|| {
        let name = CString::new("nonexistent_grp_abc_777").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        // Per POSIX: returns 0 and sets result to NULL for not found
        assert_eq!(rc, 0);
        assert!(result.is_null(), "nonexistent group should set result=NULL");
    });
}

#[test]
fn getgrnam_r_small_buffer() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1]; // Intentionally too small
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        // Should return ERANGE when buffer is too small
        assert_eq!(rc, libc::ERANGE, "tiny buffer should return ERANGE");
        assert!(result.is_null());
    });
}

#[test]
fn getgrnam_r_missing_backend_returns_errno() {
    let missing = temp_group_path();
    with_group_path(&missing, || {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, libc::ENOENT);
        assert!(result.is_null());
    });
}

// ===========================================================================
// getgrent_r (reentrant iteration)
// ===========================================================================

#[test]
fn getgrent_r_basic() {
    with_group_lock(|| {
        unsafe { setgrent() };

        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe { getgrent_r(&mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        assert_eq!(rc, 0, "getgrent_r should succeed");
        assert!(!result.is_null());

        let name = unsafe { CStr::from_ptr(grp.gr_name) };
        assert!(
            !name.to_str().unwrap().is_empty(),
            "group name should not be empty"
        );

        unsafe { endgrent() };
    });
}

#[test]
fn getgrent_r_iterates_all() {
    with_group_lock(|| {
        unsafe { setgrent() };

        let mut count = 0;
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 4096];
        let mut result: *mut libc::group = std::ptr::null_mut();

        loop {
            let rc =
                unsafe { getgrent_r(&mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
            if rc != 0 || result.is_null() {
                break;
            }
            count += 1;
            if count > 200 {
                break; // Safety limit
            }
        }
        assert!(
            count >= 1,
            "should enumerate at least 1 group via getgrent_r"
        );

        unsafe { endgrent() };
    });
}

// ===========================================================================
// Additional getgrnam / getgrgid edge cases
// ===========================================================================

#[test]
fn getgrnam_empty_string() {
    with_group_lock(|| {
        let name = CString::new("").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(grp.is_null(), "empty group name should return null");
    });
}

#[test]
fn getgrgid_root_has_passwd_field() {
    with_group_lock(|| {
        let grp = unsafe { getgrgid(0) };
        if !grp.is_null() {
            let gr = unsafe { &*grp };
            // gr_passwd should be a valid pointer (may be empty string or "x")
            assert!(!gr.gr_passwd.is_null(), "gr_passwd should not be null");
        }
    });
}

#[test]
fn getgrgid_root_has_members_field() {
    with_group_lock(|| {
        let grp = unsafe { getgrgid(0) };
        if !grp.is_null() {
            let gr = unsafe { &*grp };
            // gr_mem should be a valid pointer (possibly pointing to NULL terminator)
            assert!(!gr.gr_mem.is_null(), "gr_mem should not be null");
        }
    });
}

#[test]
fn getgrnam_r_null_name_returns_not_found() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                std::ptr::null(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        // Should handle null name gracefully
        assert!(result.is_null() || rc != 0);
    });
}

#[test]
fn getgrgid_r_nonexistent() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1024];
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrgid_r(
                99999,
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(result.is_null(), "nonexistent gid should set result=NULL");
    });
}

#[test]
fn getgrgid_r_small_buffer() {
    with_group_lock(|| {
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 1]; // Intentionally too small
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc =
            unsafe { getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
        assert_eq!(rc, libc::ERANGE, "tiny buffer should return ERANGE");
        assert!(result.is_null());
    });
}

// ===========================================================================
// Consistency checks
// ===========================================================================

#[test]
fn getgrnam_getgrgid_consistent() {
    with_group_lock(|| {
        // Look up "root" by name, then by its gid, verify they match
        let name = CString::new("root").unwrap();
        let by_name = unsafe { getgrnam(name.as_ptr()) };
        if by_name.is_null() {
            return; // Skip if root group not available
        }
        let gid = unsafe { (*by_name).gr_gid };

        let by_gid = unsafe { getgrgid(gid) };
        assert!(!by_gid.is_null());

        let name1 = unsafe { CStr::from_ptr((*by_name).gr_name) }
            .to_str()
            .unwrap();
        let name2 = unsafe { CStr::from_ptr((*by_gid).gr_name) }
            .to_str()
            .unwrap();
        assert_eq!(name1, name2, "name lookup and gid lookup should agree");
    });
}

#[test]
fn getgrnam_r_getgrgid_r_consistent() {
    with_group_lock(|| {
        let name_str = CString::new("root").unwrap();

        let mut grp1: libc::group = unsafe { std::mem::zeroed() };
        let mut buf1 = vec![0u8; 4096];
        let mut result1: *mut libc::group = std::ptr::null_mut();
        let rc1 = unsafe {
            getgrnam_r(
                name_str.as_ptr(),
                &mut grp1,
                buf1.as_mut_ptr().cast(),
                buf1.len(),
                &mut result1,
            )
        };
        if rc1 != 0 || result1.is_null() {
            return; // Skip
        }

        let gid = grp1.gr_gid;

        let mut grp2: libc::group = unsafe { std::mem::zeroed() };
        let mut buf2 = vec![0u8; 4096];
        let mut result2: *mut libc::group = std::ptr::null_mut();
        let rc2 = unsafe {
            getgrgid_r(
                gid,
                &mut grp2,
                buf2.as_mut_ptr().cast(),
                buf2.len(),
                &mut result2,
            )
        };
        assert_eq!(rc2, 0);
        assert!(!result2.is_null());
        assert_eq!(grp1.gr_gid, grp2.gr_gid);
    });
}

// ===========================================================================
// Double setgrent/endgrent
// ===========================================================================

#[test]
fn double_setgrent_safe() {
    with_group_lock(|| unsafe {
        setgrent();
        setgrent(); // Double call should not crash
        endgrent();
    });
}

#[test]
fn double_endgrent_safe() {
    with_group_lock(|| unsafe {
        setgrent();
        endgrent();
        endgrent(); // Double call should not crash
    });
}

#[test]
fn endgrent_without_setgrent() {
    with_group_lock(|| {
        // Should not crash
        unsafe { endgrent() };
    });
}

// ===========================================================================
// Iteration count consistency
// ===========================================================================

#[test]
fn group_iteration_count_consistent() {
    with_group_lock(|| {
        // Two iterations should produce the same count
        unsafe { setgrent() };
        let mut count1 = 0;
        loop {
            let ent = unsafe { getgrent() };
            if ent.is_null() {
                break;
            }
            count1 += 1;
            if count1 > 500 {
                break;
            }
        }
        unsafe { endgrent() };

        unsafe { setgrent() };
        let mut count2 = 0;
        loop {
            let ent = unsafe { getgrent() };
            if ent.is_null() {
                break;
            }
            count2 += 1;
            if count2 > 500 {
                break;
            }
        }
        unsafe { endgrent() };

        assert_eq!(
            count1, count2,
            "two iterations should produce the same count"
        );
    });
}

// ===========================================================================
// Reentrant lookups from multiple threads
// ===========================================================================

#[test]
fn getgrnam_r_concurrent_lookups() {
    with_group_lock(|| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let name = std::ffi::CString::new("root").unwrap();
                    let mut grp: libc::group = unsafe { std::mem::zeroed() };
                    let mut buf = vec![0u8; 4096];
                    let mut result: *mut libc::group = std::ptr::null_mut();

                    let rc = unsafe {
                        getgrnam_r(
                            name.as_ptr(),
                            &mut grp,
                            buf.as_mut_ptr().cast(),
                            buf.len(),
                            &mut result,
                        )
                    };
                    assert_eq!(rc, 0);
                    assert!(!result.is_null());
                    assert_eq!(grp.gr_gid, 0);
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

#[test]
fn getgrgid_r_concurrent_lookups() {
    with_group_lock(|| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                std::thread::spawn(|| {
                    let mut grp: libc::group = unsafe { std::mem::zeroed() };
                    let mut buf = vec![0u8; 4096];
                    let mut result: *mut libc::group = std::ptr::null_mut();

                    let rc = unsafe {
                        getgrgid_r(0, &mut grp, buf.as_mut_ptr().cast(), buf.len(), &mut result)
                    };
                    assert_eq!(rc, 0);
                    assert!(!result.is_null());
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    });
}

// ===========================================================================
// getgrnam_r with adequately large buffer
// ===========================================================================

#[test]
fn getgrnam_r_large_buffer() {
    with_group_lock(|| {
        let name = CString::new("root").unwrap();
        let mut grp: libc::group = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; 65536]; // 64KB — plenty
        let mut result: *mut libc::group = std::ptr::null_mut();

        let rc = unsafe {
            getgrnam_r(
                name.as_ptr(),
                &mut grp,
                buf.as_mut_ptr().cast(),
                buf.len(),
                &mut result,
            )
        };
        assert_eq!(rc, 0);
        assert!(!result.is_null());
        assert_eq!(grp.gr_gid, 0);
    });
}

// ===========================================================================
// Strict/Hardened Mode Tests (bd-x2sq)
// ===========================================================================

/// Static mutex for mode env var manipulation (process-global).
static MODE_ENV_LOCK: Mutex<()> = Mutex::new(());

/// Test fixture for group entries (group_name:password:gid:members).
const GROUP_FIXTURE: &[u8] =
    b"root:x:0:root\nusers:x:100:alice,bob\nadmins:x:999:alice\n";

fn with_mode(mode: &str, f: impl FnOnce()) {
    let _guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: Serialized by MODE_ENV_LOCK.
    unsafe { std::env::set_var("FRANKENLIBC_MODE", mode) };
    f();
    // SAFETY: Same as above.
    unsafe { std::env::remove_var("FRANKENLIBC_MODE") };
}

fn with_mode_and_group(mode: &str, group_content: &[u8], f: impl FnOnce()) {
    let _mode_guard = MODE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _group_guard = GROUP_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let path = temp_group_path();
    std::fs::write(&path, group_content).expect("write temp group");

    // SAFETY: Serialized by both locks.
    unsafe {
        std::env::set_var("FRANKENLIBC_MODE", mode);
        std::env::set_var("FRANKENLIBC_GROUP_PATH", &path);
    }
    f();
    // SAFETY: Same as above.
    unsafe {
        std::env::remove_var("FRANKENLIBC_MODE");
        std::env::remove_var("FRANKENLIBC_GROUP_PATH");
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn strict_mode_getgrnam_returns_null_for_invalid() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let name = CString::new("nonexistent_group_strict_test").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        assert!(
            grp.is_null(),
            "strict mode: getgrnam for nonexistent group should return null"
        );
    });
}

#[test]
fn strict_mode_getgrgid_returns_null_for_invalid_gid() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        let grp = unsafe { getgrgid(99999) };
        assert!(
            grp.is_null(),
            "strict mode: getgrgid for nonexistent gid should return null"
        );
    });
}

#[test]
fn hardened_mode_getgrnam_returns_null_for_invalid() {
    with_mode_and_group("hardened", GROUP_FIXTURE, || {
        let name = CString::new("nonexistent_group_hardened_test").unwrap();
        let grp = unsafe { getgrnam(name.as_ptr()) };
        // In hardened mode, invalid lookups still return null (no healing for missing entries).
        assert!(
            grp.is_null(),
            "hardened mode: getgrnam for nonexistent group should return null"
        );
    });
}

#[test]
fn hardened_mode_getgrgid_returns_null_for_invalid_gid() {
    with_mode_and_group("hardened", GROUP_FIXTURE, || {
        let grp = unsafe { getgrgid(99999) };
        // In hardened mode, invalid lookups still return null.
        assert!(
            grp.is_null(),
            "hardened mode: getgrgid for nonexistent gid should return null"
        );
    });
}

#[test]
fn strict_mode_getgrnam_null_input_returns_null() {
    with_mode("strict", || {
        let grp = unsafe { getgrnam(std::ptr::null()) };
        assert!(
            grp.is_null(),
            "strict mode: getgrnam(null) should return null"
        );
    });
}

#[test]
fn hardened_mode_getgrnam_null_input_returns_null() {
    with_mode("hardened", || {
        let grp = unsafe { getgrnam(std::ptr::null()) };
        assert!(
            grp.is_null(),
            "hardened mode: getgrnam(null) should return null"
        );
    });
}

#[test]
fn strict_mode_grent_iteration_works() {
    with_mode_and_group("strict", GROUP_FIXTURE, || {
        unsafe { setgrent() };
        let mut count = 0;
        loop {
            let grp = unsafe { getgrent() };
            if grp.is_null() {
                break;
            }
            count += 1;
            assert!(count <= 10, "strict mode: grent iteration should not infinite loop");
        }
        unsafe { endgrent() };
        assert_eq!(count, 3, "strict mode: fixture has 3 entries");
    });
}

#[test]
fn hardened_mode_grent_iteration_works() {
    with_mode_and_group("hardened", GROUP_FIXTURE, || {
        unsafe { setgrent() };
        let mut count = 0;
        loop {
            let grp = unsafe { getgrent() };
            if grp.is_null() {
                break;
            }
            count += 1;
            assert!(count <= 10, "hardened mode: grent iteration should not infinite loop");
        }
        unsafe { endgrent() };
        assert_eq!(count, 3, "hardened mode: fixture has 3 entries");
    });
}
