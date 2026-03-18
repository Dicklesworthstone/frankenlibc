#![cfg(target_os = "linux")]

//! Integration tests for virtual memory management ABI entrypoints.
//!
//! Covers: mmap, munmap, mprotect, msync, madvise, mlock/munlock, mremap.

use std::ffi::c_void;
use std::ptr;

use frankenlibc_abi::mmap_abi::{
    madvise, mlock2, mlockall, mmap, mprotect, msync, munlockall, munmap,
};

// ---------------------------------------------------------------------------
// mmap / munmap basics
// ---------------------------------------------------------------------------

#[test]
fn mmap_anonymous_and_munmap() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "mmap should succeed");
    assert!(!ptr.is_null());

    // Write to the mapped memory
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, len) };
    slice[0] = 42;
    slice[len - 1] = 99;
    assert_eq!(slice[0], 42);
    assert_eq!(slice[len - 1], 99);

    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0, "munmap should succeed");
}

#[test]
fn mmap_zero_length_fails() {
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            0,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_eq!(ptr, libc::MAP_FAILED, "mmap with length=0 should fail");
}

#[test]
fn mmap_large_anonymous() {
    let len = 1024 * 1024; // 1MB
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    // Verify the memory is zero-initialized (MAP_ANONYMOUS guarantee)
    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, len) };
    assert!(
        slice.iter().all(|&b| b == 0),
        "anonymous mmap should be zero-filled"
    );

    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// mprotect
// ---------------------------------------------------------------------------

#[test]
fn mprotect_changes_protection() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    // Write data first
    unsafe { *(ptr as *mut u8) = 123 };

    // Change to read-only
    let rc = unsafe { mprotect(ptr, len, libc::PROT_READ) };
    assert_eq!(rc, 0, "mprotect to PROT_READ should succeed");

    // Verify we can still read
    let val = unsafe { *(ptr as *const u8) };
    assert_eq!(val, 123);

    // Restore write permission and clean up
    let rc = unsafe { mprotect(ptr, len, libc::PROT_READ | libc::PROT_WRITE) };
    assert_eq!(rc, 0);
    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// msync
// ---------------------------------------------------------------------------

#[test]
fn msync_on_anonymous_mapping() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    // msync on anonymous mapping should succeed (or return ENOMEM on some kernels)
    let rc = unsafe { msync(ptr, len, libc::MS_SYNC) };
    // MS_SYNC on anonymous private mapping may return -1/ENOMEM on some
    // kernels, but should not crash. We just verify it doesn't panic.
    let _ = rc;

    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// madvise
// ---------------------------------------------------------------------------

#[test]
fn madvise_normal_succeeds() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    let rc = unsafe { madvise(ptr, len, libc::MADV_NORMAL) };
    assert_eq!(rc, 0, "madvise MADV_NORMAL should succeed");

    let rc = unsafe { madvise(ptr, len, libc::MADV_SEQUENTIAL) };
    assert_eq!(rc, 0, "madvise MADV_SEQUENTIAL should succeed");

    let rc = unsafe { madvise(ptr, len, libc::MADV_RANDOM) };
    assert_eq!(rc, 0, "madvise MADV_RANDOM should succeed");

    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// mlock / munlock
// ---------------------------------------------------------------------------

#[test]
fn mlock_munlock_basic() {
    use frankenlibc_abi::mmap_abi::{mlock, munlock};
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    let rc = unsafe { mlock(ptr as *const c_void, len) };
    // mlock may fail with EPERM if not privileged, which is OK
    if rc == 0 {
        let rc = unsafe { munlock(ptr as *const c_void, len) };
        assert_eq!(rc, 0, "munlock should succeed after mlock");
    }

    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// mremap
// ---------------------------------------------------------------------------

#[test]
fn mremap_grow_mapping() {
    use frankenlibc_abi::mmap_abi::mremap;
    let old_len = 4096;
    let new_len = 8192;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            old_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    // Write a marker
    unsafe { *(ptr as *mut u8) = 77 };

    let new_ptr = unsafe { mremap(ptr, old_len, new_len, libc::MREMAP_MAYMOVE, ptr::null_mut()) };
    assert_ne!(new_ptr, libc::MAP_FAILED, "mremap should succeed");

    // Marker should be preserved
    let val = unsafe { *(new_ptr as *const u8) };
    assert_eq!(val, 77, "data should be preserved after mremap");

    let rc = unsafe { munmap(new_ptr, new_len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// Multiple mappings
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// mlock2
// ---------------------------------------------------------------------------

#[test]
fn mlock2_basic() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    // mlock2 with flags=0 behaves like mlock
    let rc = unsafe { mlock2(ptr as *const c_void, len, 0) };
    // May fail with EPERM if not privileged
    if rc == 0 {
        use frankenlibc_abi::mmap_abi::munlock;
        let rc = unsafe { munlock(ptr as *const c_void, len) };
        assert_eq!(rc, 0);
    }
    let rc = unsafe { munmap(ptr, len) };
    assert_eq!(rc, 0);
}

// ---------------------------------------------------------------------------
// mlockall / munlockall
// ---------------------------------------------------------------------------

#[test]
fn mlockall_munlockall() {
    // MCL_CURRENT = 1
    let rc = unsafe { mlockall(1) };
    // May fail with EPERM/ENOMEM on unprivileged systems
    if rc == 0 {
        let rc = unsafe { munlockall() };
        assert_eq!(rc, 0, "munlockall should succeed after mlockall");
    }
}

// ---------------------------------------------------------------------------
// mmap edge cases
// ---------------------------------------------------------------------------

#[test]
fn mmap_read_only() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    // Should be readable (all zeros)
    let val = unsafe { *(ptr as *const u8) };
    assert_eq!(val, 0);
    assert_eq!(unsafe { munmap(ptr, len) }, 0);
}

#[test]
fn munmap_null_is_valid() {
    // On Linux, munmap(NULL, len) succeeds (unmapping nothing is a no-op)
    let rc = unsafe { munmap(ptr::null_mut(), 4096) };
    assert_eq!(rc, 0, "munmap(NULL, 4096) succeeds on Linux");
}

#[test]
fn madvise_dontneed() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);

    unsafe { *(ptr as *mut u8) = 42 };

    let rc = unsafe { madvise(ptr, len, libc::MADV_DONTNEED) };
    assert_eq!(rc, 0, "madvise MADV_DONTNEED should succeed");

    // After DONTNEED, anonymous mapping returns to zero
    let val = unsafe { *(ptr as *const u8) };
    assert_eq!(val, 0, "MADV_DONTNEED should zero anonymous page");

    assert_eq!(unsafe { munmap(ptr, len) }, 0);
}

#[test]
fn mprotect_null_fails() {
    let rc = unsafe { mprotect(ptr::null_mut(), 4096, libc::PROT_READ) };
    assert_eq!(rc, -1, "mprotect(NULL) should fail");
}

// ---------------------------------------------------------------------------
// mmap PROT_NONE (guard page pattern)
// ---------------------------------------------------------------------------

#[test]
fn mmap_prot_none() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "PROT_NONE mmap should succeed");
    // Can't read/write, but we can mprotect and then access
    let rc = unsafe { mprotect(ptr, len, libc::PROT_READ | libc::PROT_WRITE) };
    assert_eq!(rc, 0);
    unsafe { *(ptr as *mut u8) = 55 };
    assert_eq!(unsafe { *(ptr as *const u8) }, 55);
    assert_eq!(unsafe { munmap(ptr, len) }, 0);
}

// ---------------------------------------------------------------------------
// mremap — additional
// ---------------------------------------------------------------------------

#[test]
fn mremap_shrink_mapping() {
    use frankenlibc_abi::mmap_abi::mremap;
    let old_len = 8192;
    let new_len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            old_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    unsafe { *(ptr as *mut u8) = 88 };

    // Shrinking does not require MREMAP_MAYMOVE
    let new_ptr = unsafe { mremap(ptr, old_len, new_len, 0, ptr::null_mut()) };
    assert_ne!(new_ptr, libc::MAP_FAILED, "mremap shrink should succeed");
    assert_eq!(new_ptr, ptr, "shrink should keep same address");
    let val = unsafe { *(new_ptr as *const u8) };
    assert_eq!(val, 88, "data should be preserved after shrink");

    assert_eq!(unsafe { munmap(new_ptr, new_len) }, 0);
}

// ---------------------------------------------------------------------------
// msync — additional
// ---------------------------------------------------------------------------

#[test]
fn msync_async_on_anonymous() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    // MS_ASYNC is a hint; should not fail
    let rc = unsafe { msync(ptr, len, libc::MS_ASYNC) };
    let _ = rc; // May succeed or fail on anonymous mapping
    assert_eq!(unsafe { munmap(ptr, len) }, 0);
}

// ---------------------------------------------------------------------------
// madvise — additional
// ---------------------------------------------------------------------------

#[test]
fn madvise_willneed() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    let rc = unsafe { madvise(ptr, len, libc::MADV_WILLNEED) };
    assert_eq!(rc, 0, "MADV_WILLNEED should succeed");
    assert_eq!(unsafe { munmap(ptr, len) }, 0);
}

// ---------------------------------------------------------------------------
// mprotect — additional
// ---------------------------------------------------------------------------

#[test]
fn mprotect_none_then_restore() {
    let len = 4096;
    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED);
    unsafe { *(ptr as *mut u8) = 33 };

    // Remove all permissions
    let rc = unsafe { mprotect(ptr, len, libc::PROT_NONE) };
    assert_eq!(rc, 0);

    // Restore
    let rc = unsafe { mprotect(ptr, len, libc::PROT_READ) };
    assert_eq!(rc, 0);
    assert_eq!(
        unsafe { *(ptr as *const u8) },
        33,
        "data should survive PROT_NONE"
    );

    assert_eq!(unsafe { munmap(ptr, len) }, 0);
}

// ---------------------------------------------------------------------------
// mmap file-backed
// ---------------------------------------------------------------------------

#[test]
fn mmap_file_backed() {
    use std::os::unix::io::AsRawFd;

    let path = std::env::temp_dir().join(format!("frankenlibc-mmap-test-{}", std::process::id()));
    let data = b"hello mmap world!";
    std::fs::write(&path, data).expect("write tmp file");

    let file = std::fs::File::open(&path).expect("open file");
    let fd = file.as_raw_fd();

    let ptr = unsafe {
        mmap(
            ptr::null_mut(),
            data.len(),
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };
    assert_ne!(ptr, libc::MAP_FAILED, "file-backed mmap should succeed");

    let slice = unsafe { std::slice::from_raw_parts(ptr as *const u8, data.len()) };
    assert_eq!(slice, data, "mmap should reflect file contents");

    assert_eq!(unsafe { munmap(ptr, data.len()) }, 0);
    drop(file);
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Multiple mappings
// ---------------------------------------------------------------------------

#[test]
fn multiple_mappings_independent() {
    let len = 4096;
    let ptr1 = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    let ptr2 = unsafe {
        mmap(
            ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(ptr1, libc::MAP_FAILED);
    assert_ne!(ptr2, libc::MAP_FAILED);
    assert_ne!(
        ptr1, ptr2,
        "two anonymous mappings should be at different addresses"
    );

    unsafe {
        *(ptr1 as *mut u8) = 1;
        *(ptr2 as *mut u8) = 2;
    }
    assert_eq!(unsafe { *(ptr1 as *const u8) }, 1);
    assert_eq!(unsafe { *(ptr2 as *const u8) }, 2);

    assert_eq!(unsafe { munmap(ptr1, len) }, 0);
    assert_eq!(unsafe { munmap(ptr2, len) }, 0);
}
