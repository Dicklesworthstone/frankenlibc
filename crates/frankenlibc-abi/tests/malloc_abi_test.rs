#![cfg(target_os = "linux")]

//! Integration tests for malloc introspection ABI entrypoints.

use frankenlibc_abi::malloc_abi::{
    cfree, free, mallinfo, mallinfo2, malloc, malloc_info, malloc_stats, malloc_trim,
    malloc_usable_size, mallopt, pvalloc, valloc,
};
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------------
// valloc
// ---------------------------------------------------------------------------

#[test]
fn test_valloc_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { valloc(128) };
    assert!(!p.is_null(), "valloc(128) should succeed");
    // Page-aligned: address should be a multiple of page size
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    assert_eq!(
        (p as usize) % page_sz,
        0,
        "valloc result must be page-aligned"
    );
    // Write and read back
    unsafe { *(p as *mut u8) = 0xAA };
    assert_eq!(unsafe { *(p as *const u8) }, 0xAA);
    unsafe { free(p) };
}

#[test]
fn test_valloc_zero() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { valloc(0) };
    // valloc(0) may or may not return null, but if it returns non-null, it must be freeable
    if !p.is_null() {
        unsafe { free(p) };
    }
}

// ---------------------------------------------------------------------------
// pvalloc
// ---------------------------------------------------------------------------

#[test]
fn test_pvalloc_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let p = unsafe { pvalloc(1) };
    assert!(!p.is_null(), "pvalloc(1) should succeed");
    // Should be page-aligned
    assert_eq!(
        (p as usize) % page_sz,
        0,
        "pvalloc result must be page-aligned"
    );
    unsafe { free(p) };
}

#[test]
fn test_pvalloc_rounds_up() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    // Requesting page_sz + 1 should round up to 2 * page_sz
    let p = unsafe { pvalloc(page_sz + 1) };
    assert!(!p.is_null());
    assert_eq!((p as usize) % page_sz, 0);
    // The usable size should be at least 2 * page_sz
    let usable = unsafe { malloc_usable_size(p) };
    assert!(
        usable > page_sz,
        "pvalloc({}) usable {} should be >= {}",
        page_sz + 1,
        usable,
        page_sz + 1
    );
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// cfree
// ---------------------------------------------------------------------------

#[test]
fn test_cfree_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(64) };
    assert!(!p.is_null());
    // cfree should work the same as free
    unsafe { cfree(p) };
}

#[test]
fn test_cfree_null() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // cfree(NULL) should be a no-op, just like free(NULL)
    unsafe { cfree(ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// mallopt
// ---------------------------------------------------------------------------

#[test]
fn test_mallopt_returns_success() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // mallopt should always return 1 (success) for any parameter
    let rc = unsafe { mallopt(1, 64) }; // M_MXFAST = 1
    assert_eq!(rc, 1, "mallopt should return 1");
    let rc = unsafe { mallopt(-1, 0) }; // M_TRIM_THRESHOLD = -1
    assert_eq!(rc, 1, "mallopt should return 1 for any param");
    let rc = unsafe { mallopt(0, 0) };
    assert_eq!(rc, 1);
}

// ---------------------------------------------------------------------------
// malloc_usable_size
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_usable_size_null() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let sz = unsafe { malloc_usable_size(ptr::null_mut()) };
    assert_eq!(sz, 0, "malloc_usable_size(NULL) should return 0");
}

#[test]
fn test_malloc_usable_size_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(100) };
    assert!(!p.is_null());
    let usable = unsafe { malloc_usable_size(p) };
    // Usable size must be at least what was requested
    assert!(
        usable >= 100,
        "malloc_usable_size should be >= requested size, got {}",
        usable
    );
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// malloc_trim
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_trim_returns_success() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let rc = unsafe { malloc_trim(0) };
    assert_eq!(rc, 1, "malloc_trim should return 1");
    let rc = unsafe { malloc_trim(4096) };
    assert_eq!(rc, 1);
}

// ---------------------------------------------------------------------------
// mallinfo / mallinfo2
// ---------------------------------------------------------------------------

#[test]
fn test_mallinfo_returns_valid_struct() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let info = unsafe { mallinfo() };
    // All fields should be non-negative
    assert!(info.arena >= 0, "arena should be non-negative");
    assert!(info.ordblks >= 0, "ordblks should be non-negative");
    assert!(info.uordblks >= 0, "uordblks should be non-negative");
    assert!(info.fordblks >= 0, "fordblks should be non-negative");
}

#[test]
fn test_mallinfo2_returns_valid_struct() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let info = unsafe { mallinfo2() };
    let request = 1024 * 1024;
    let p = unsafe { malloc(request) };
    assert!(!p.is_null(), "malloc should succeed in mallinfo2 test");
    let info_after = unsafe { mallinfo2() };
    assert!(
        info_after.uordblks >= info.uordblks.saturating_add(request),
        "uordblks should include live bytes for allocated block"
    );
    assert!(
        info_after.ordblks >= info.ordblks.saturating_add(1),
        "ordblks should track active allocation count"
    );
    unsafe { free(p) };
}

#[test]
fn test_mallinfo2_balanced_after_concurrent_alloc_free() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let before = unsafe { mallinfo2() };
    let workers = 16usize;
    let iters_per_worker = 4096usize;

    std::thread::scope(|scope| {
        for worker_id in 0..workers {
            scope.spawn(move || {
                for iter in 0..iters_per_worker {
                    let size = ((worker_id * 131 + iter * 17) % 2048) + 1;
                    let ptr = unsafe { malloc(size) };
                    assert!(!ptr.is_null(), "malloc should succeed in stress path");
                    unsafe { free(ptr) };
                }
            });
        }
    });

    let after = unsafe { mallinfo2() };
    assert_eq!(
        after.ordblks, before.ordblks,
        "active allocation count should return to baseline after balanced ops"
    );
    assert_eq!(
        after.uordblks, before.uordblks,
        "live bytes should return to baseline after balanced ops"
    );
}

// ---------------------------------------------------------------------------
// malloc_stats
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_stats_does_not_crash() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // malloc_stats writes to stderr; just verify it doesn't crash
    unsafe { malloc_stats() };
}

// ---------------------------------------------------------------------------
// malloc_info
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_info_null_stream() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let rc = unsafe { malloc_info(0, ptr::null_mut()) };
    assert_eq!(rc, -1, "malloc_info with null stream should return -1");
}

#[test]
fn test_malloc_info_bad_options() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // Create a dummy non-null pointer for stream
    let dummy: i32 = 0;
    let rc = unsafe { malloc_info(1, &dummy as *const i32 as *mut c_void) };
    assert_eq!(rc, -1, "malloc_info with options != 0 should return -1");
}
