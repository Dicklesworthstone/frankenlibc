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

// ---------------------------------------------------------------------------
// Extended error code coverage
// ---------------------------------------------------------------------------

#[test]
fn errno_network_codes() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    let codes: &[c_int] = &[
        libc::ECONNREFUSED,
        libc::ECONNRESET,
        libc::ECONNABORTED,
        libc::ETIMEDOUT,
        libc::EHOSTUNREACH,
        libc::ENETUNREACH,
        libc::EADDRINUSE,
        libc::EADDRNOTAVAIL,
        libc::EPIPE,
        libc::ENOTSOCK,
    ];

    for &code in codes {
        unsafe { *p = code };
        assert_eq!(unsafe { *p }, code, "errno should hold network code {code}");
    }

    unsafe { *p = original };
}

#[test]
fn errno_filesystem_codes() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    let codes: &[c_int] = &[
        libc::ENOSPC,
        libc::EROFS,
        libc::EMLINK,
        libc::ELOOP,
        libc::ENAMETOOLONG,
        libc::ENOTEMPTY,
        libc::EXDEV,
        libc::EBADF,
        libc::EFBIG,
        libc::EMFILE,
        libc::ENFILE,
    ];

    for &code in codes {
        unsafe { *p = code };
        assert_eq!(unsafe { *p }, code, "errno should hold fs code {code}");
    }

    unsafe { *p = original };
}

#[test]
fn errno_process_codes() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    let codes: &[c_int] = &[
        libc::EAGAIN,
        libc::ECHILD,
        libc::EDEADLK,
        libc::EBUSY,
        libc::EFAULT,
        libc::ENOSYS,
        libc::ENOPROTOOPT,
    ];

    for &code in codes {
        unsafe { *p = code };
        assert_eq!(unsafe { *p }, code, "errno should hold process code {code}");
    }

    unsafe { *p = original };
}

#[test]
fn errno_negative_value() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    // While POSIX only defines positive errno values, the storage should
    // handle any c_int value
    unsafe { *p = -1 };
    assert_eq!(unsafe { *p }, -1);

    unsafe { *p = c_int::MIN };
    assert_eq!(unsafe { *p }, c_int::MIN);

    unsafe { *p = original };
}

#[test]
fn errno_max_value() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    unsafe { *p = c_int::MAX };
    assert_eq!(unsafe { *p }, c_int::MAX);

    unsafe { *p = original };
}

#[test]
fn errno_zero_value() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    unsafe { *p = 0 };
    assert_eq!(unsafe { *p }, 0, "errno should hold zero");

    unsafe { *p = original };
}

// ---------------------------------------------------------------------------
// Multi-thread isolation stress
// ---------------------------------------------------------------------------

#[test]
fn errno_multi_thread_isolation() {
    // Spawn N threads, each sets its own errno to its thread index,
    // then verifies it's unchanged after a barrier-like sync.
    use std::sync::{Arc, Barrier};

    let n = 8;
    let barrier = Arc::new(Barrier::new(n));

    let handles: Vec<_> = (0..n)
        .map(|i| {
            let b = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let p = unsafe { __errno_location() };
                let val = (i + 1000) as c_int;
                unsafe { *p = val };

                // Wait for all threads to set their errno
                b.wait();

                // Each thread's errno should still be its own value
                assert_eq!(
                    unsafe { *p },
                    val,
                    "thread {i} errno should be {val} after barrier"
                );
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn errno_rapid_write_read() {
    let p = unsafe { __errno_location() };
    let original = unsafe { *p };

    // Rapidly write and read different values
    for i in 0..1000 {
        let val = (i % 256) as c_int;
        unsafe { *p = val };
        assert_eq!(unsafe { *p }, val);
    }

    unsafe { *p = original };
}

#[test]
fn errno_pointer_different_across_threads() {
    // Each thread should have a distinct pointer
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel();

    let main_ptr = unsafe { __errno_location() } as usize;

    let handle = std::thread::spawn(move || {
        let thread_ptr = unsafe { __errno_location() } as usize;
        tx.send(thread_ptr).unwrap();
    });

    let thread_ptr = rx.recv().unwrap();
    handle.join().unwrap();

    assert_ne!(
        main_ptr, thread_ptr,
        "main and child thread should have different errno pointers"
    );
}
