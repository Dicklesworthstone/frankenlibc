#![cfg(target_os = "linux")]

//! Integration tests for `<errno.h>` ABI entrypoints.
//!
//! Covers: __errno_location (thread-local errno storage).

use std::ffi::c_int;

use frankenlibc_abi::errno_abi::__errno_location;

#[test]
fn errno_location_returns_valid_ptr() {
    let p = unsafe { __errno_location() };
    assert!(!p.is_null(), "__errno_location should return non-null");
}

#[test]
fn errno_read_write_roundtrip() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    unsafe { *p = libc::ENOENT };
    assert_eq!(unsafe { *p }, libc::ENOENT);

    unsafe { *p = libc::EINVAL };
    assert_eq!(unsafe { *p }, libc::EINVAL);

    // Restore
    unsafe { *p = original };
}

#[test]
fn errno_location_is_stable() {
    // Multiple calls should return the same pointer (same thread)
    let p1 = unsafe { __errno_location() };
    let p2 = unsafe { __errno_location() };
    assert_eq!(p1, p2, "consecutive calls should return the same pointer");
}

#[test]
fn errno_is_thread_local() {
    // Set errno on main thread
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };
    unsafe { *p = 42 };

    // Spawn a thread and check its errno is independent
    let handle = std::thread::spawn(|| {
        let tp = unsafe { __errno_location() };
        let val = unsafe { *tp };
        // Thread errno should be 0 (freshly initialized), not 42
        assert_ne!(val, 42, "thread errno should be independent");
        // Set thread errno to something else
        unsafe { *tp = 99 };
        unsafe { *tp }
    });

    let thread_errno = handle.join().unwrap();
    assert_eq!(thread_errno, 99);

    // Main thread errno should still be 42
    assert_eq!(unsafe { *p }, 42);

    // Restore
    unsafe { *p = original };
}

#[test]
fn errno_zero_on_init() {
    // Spawn a fresh thread; its errno should start at 0
    let handle = std::thread::spawn(|| {
        let p = unsafe { __errno_location() };
        unsafe { *p }
    });
    let val = handle.join().unwrap();
    assert_eq!(val, 0, "fresh thread errno should be 0");
}

#[test]
fn errno_handles_all_standard_codes() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    let codes: &[c_int] = &[
        libc::EPERM,
        libc::ENOENT,
        libc::ESRCH,
        libc::EINTR,
        libc::EIO,
        libc::ENXIO,
        libc::EACCES,
        libc::EEXIST,
        libc::ENOTDIR,
        libc::EISDIR,
        libc::ENOMEM,
        libc::ERANGE,
    ];

    for &code in codes {
        unsafe { *p = code };
        assert_eq!(unsafe { *p }, code, "errno should hold code {code}");
    }

    // Restore
    unsafe { *p = original };
}
