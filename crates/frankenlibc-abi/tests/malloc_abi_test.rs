#![cfg(target_os = "linux")]

//! Integration tests for malloc introspection ABI entrypoints.

use frankenlibc_abi::malloc_abi::{
    __libc_freeres, aligned_alloc, calloc, cfree, free, mallinfo, mallinfo2, malloc, malloc_info,
    malloc_stats, malloc_trim, malloc_usable_size, mallopt, memalign, posix_memalign, pvalloc,
    realloc, valloc,
};
use std::ffi::c_void;
use std::ptr;
use std::sync::{Mutex, OnceLock};

fn test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------------
// malloc — basic allocation
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_basic_alloc_and_free() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(256) };
    assert!(!p.is_null(), "malloc(256) should succeed");
    // Write pattern and read back
    unsafe {
        let slice = std::slice::from_raw_parts_mut(p as *mut u8, 256);
        for (i, byte) in slice.iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        for (i, byte) in slice.iter().enumerate() {
            assert_eq!(*byte, (i & 0xFF) as u8);
        }
    }
    unsafe { free(p) };
}

#[test]
fn test_malloc_zero_size() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(0) };
    // malloc(0) may return null or a unique freeable pointer
    if !p.is_null() {
        unsafe { free(p) };
    }
}

#[test]
fn test_free_null_is_noop() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // free(NULL) must be a no-op per POSIX
    unsafe { free(ptr::null_mut()) };
}

// ---------------------------------------------------------------------------
// calloc — zero-initialized allocation
// ---------------------------------------------------------------------------

#[test]
fn test_calloc_zero_initialized() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { calloc(10, 16) };
    assert!(!p.is_null(), "calloc(10, 16) should succeed");
    // All bytes must be zero
    let slice = unsafe { std::slice::from_raw_parts(p as *const u8, 160) };
    for &byte in slice {
        assert_eq!(byte, 0, "calloc memory must be zero-initialized");
    }
    unsafe { free(p) };
}

#[test]
fn test_calloc_zero_count() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { calloc(0, 64) };
    if !p.is_null() {
        unsafe { free(p) };
    }
}

#[test]
fn test_calloc_zero_size() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { calloc(10, 0) };
    if !p.is_null() {
        unsafe { free(p) };
    }
}

// ---------------------------------------------------------------------------
// realloc — resize allocation
// ---------------------------------------------------------------------------

#[test]
fn test_realloc_grow() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(64) };
    assert!(!p.is_null());
    // Write a pattern to the first 64 bytes
    unsafe {
        let slice = std::slice::from_raw_parts_mut(p as *mut u8, 64);
        for (i, byte) in slice.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_add(0xA0);
        }
    }
    let p2 = unsafe { realloc(p, 256) };
    assert!(!p2.is_null(), "realloc should succeed growing to 256");
    // Original data should be preserved
    let slice = unsafe { std::slice::from_raw_parts(p2 as *const u8, 64) };
    for (i, &byte) in slice.iter().enumerate() {
        assert_eq!(
            byte,
            (i as u8).wrapping_add(0xA0),
            "data should be preserved after realloc"
        );
    }
    unsafe { free(p2) };
}

#[test]
fn test_realloc_shrink() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(256) };
    assert!(!p.is_null());
    unsafe { *(p as *mut u8) = 0x42 };
    let p2 = unsafe { realloc(p, 32) };
    assert!(!p2.is_null(), "realloc should succeed shrinking to 32");
    assert_eq!(unsafe { *(p2 as *const u8) }, 0x42, "first byte preserved");
    unsafe { free(p2) };
}

#[test]
fn test_realloc_null_ptr_acts_as_malloc() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { realloc(ptr::null_mut(), 128) };
    assert!(!p.is_null(), "realloc(NULL, 128) should act as malloc(128)");
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// posix_memalign — POSIX aligned allocation
// ---------------------------------------------------------------------------

#[test]
fn test_posix_memalign_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let mut p: *mut c_void = ptr::null_mut();
    let rc = unsafe { posix_memalign(&mut p, 64, 256) };
    assert_eq!(rc, 0, "posix_memalign should succeed");
    assert!(!p.is_null());
    assert_eq!((p as usize) % 64, 0, "must be 64-byte aligned");
    unsafe { free(p) };
}

#[test]
fn test_posix_memalign_page_aligned() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let page_sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mut p: *mut c_void = ptr::null_mut();
    let rc = unsafe { posix_memalign(&mut p, page_sz, 1024) };
    assert_eq!(rc, 0);
    assert!(!p.is_null());
    assert_eq!((p as usize) % page_sz, 0, "must be page-aligned");
    unsafe { free(p) };
}

#[test]
fn test_posix_memalign_bad_alignment() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let mut p: *mut c_void = ptr::null_mut();
    // Alignment must be power of 2 and multiple of sizeof(void*)
    let rc = unsafe { posix_memalign(&mut p, 3, 64) }; // 3 is not power of 2
    assert_eq!(
        rc,
        libc::EINVAL,
        "non-power-of-2 alignment should return EINVAL"
    );
}

#[test]
fn test_posix_memalign_null_memptr() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let rc = unsafe { posix_memalign(ptr::null_mut(), 16, 64) };
    assert_eq!(rc, libc::EINVAL, "null memptr should return EINVAL");
}

// ---------------------------------------------------------------------------
// memalign — legacy aligned allocation
// ---------------------------------------------------------------------------

#[test]
fn test_memalign_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { memalign(128, 512) };
    assert!(!p.is_null(), "memalign(128, 512) should succeed");
    assert_eq!((p as usize) % 128, 0, "must be 128-byte aligned");
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// aligned_alloc — C11 aligned allocation
// ---------------------------------------------------------------------------

#[test]
fn test_aligned_alloc_basic() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { aligned_alloc(32, 256) };
    assert!(!p.is_null(), "aligned_alloc(32, 256) should succeed");
    assert_eq!((p as usize) % 32, 0, "must be 32-byte aligned");
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// __libc_freeres — resource release stub
// ---------------------------------------------------------------------------

#[test]
fn test_libc_freeres_is_noop() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // __libc_freeres is a no-op stub; just verify it doesn't crash
    unsafe { __libc_freeres() };
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

// ---------------------------------------------------------------------------
// realloc — edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_realloc_null_zero_size() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { realloc(ptr::null_mut(), 0) };
    // realloc(NULL, 0) is like malloc(0)
    if !p.is_null() {
        unsafe { free(p) };
    }
}

// ---------------------------------------------------------------------------
// malloc — alloc/free cycling
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_free_cycles() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    for _ in 0..100 {
        let p = unsafe { malloc(128) };
        assert!(!p.is_null(), "malloc should succeed in cycle");
        unsafe { free(p) };
    }
}

#[test]
fn test_malloc_large_allocation() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // Allocate 1MB
    let p = unsafe { malloc(1024 * 1024) };
    assert!(!p.is_null(), "malloc(1MB) should succeed");
    // Write first and last byte
    unsafe {
        *(p as *mut u8) = 0xAA;
        *((p as *mut u8).add(1024 * 1024 - 1)) = 0xBB;
    }
    assert_eq!(unsafe { *(p as *const u8) }, 0xAA);
    assert_eq!(unsafe { *((p as *const u8).add(1024 * 1024 - 1)) }, 0xBB);
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// calloc — data integrity
// ---------------------------------------------------------------------------

#[test]
fn test_calloc_large_zero_initialized() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { calloc(1, 4096) };
    assert!(!p.is_null());
    let slice = unsafe { std::slice::from_raw_parts(p as *const u8, 4096) };
    assert!(slice.iter().all(|&b| b == 0), "calloc 4096 must be zero");
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// aligned_alloc — various alignments
// ---------------------------------------------------------------------------

#[test]
fn test_aligned_alloc_small_alignment() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { aligned_alloc(8, 64) };
    assert!(!p.is_null());
    assert_eq!((p as usize) % 8, 0, "must be 8-byte aligned");
    unsafe { free(p) };
}

#[test]
fn test_aligned_alloc_large_alignment() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { aligned_alloc(4096, 8192) };
    assert!(!p.is_null());
    assert_eq!((p as usize) % 4096, 0, "must be 4096-byte aligned");
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// malloc_usable_size — after realloc
// ---------------------------------------------------------------------------

#[test]
fn test_malloc_usable_size_after_realloc() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(64) };
    assert!(!p.is_null());
    let p2 = unsafe { realloc(p, 512) };
    assert!(!p2.is_null());
    let usable = unsafe { malloc_usable_size(p2) };
    assert!(
        usable >= 512,
        "usable size after realloc to 512 should be >= 512"
    );
    unsafe { free(p2) };
}
