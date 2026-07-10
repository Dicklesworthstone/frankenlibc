#![cfg(target_os = "linux")]

//! Integration tests for malloc introspection ABI entrypoints.

use frankenlibc_abi::htm_fast_path::{
    HtmTestMode, htm_restore_test_mode_for_tests, htm_swap_abort_code_for_tests,
    htm_swap_test_mode_for_tests,
};
use frankenlibc_abi::malloc_abi::{
    __libc_freeres, aligned_alloc, calloc, cfree, free, mallinfo, mallinfo2, malloc,
    malloc_current_reentry_slot_index_for_tests, malloc_fallback_range_for_tests,
    malloc_htm_reset_for_tests, malloc_htm_snapshot_for_tests, malloc_info,
    malloc_known_remaining_for_tests, malloc_reentry_multithreaded_latched_for_tests,
    malloc_restore_reentry_depth_for_tests, malloc_segment_owned_for_tests, malloc_stats,
    malloc_stats_init_for_tests, malloc_swap_reentry_depth_for_tests, malloc_trim,
    malloc_usable_size, mallopt, memalign, posix_memalign, pvalloc, realloc,
    signal_runtime_ready_for_tests, take_last_decision_gate_for_tests, valloc,
};
use frankenlibc_abi::unistd_abi::mprobe;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr;
use std::sync::{Arc, Barrier, Mutex, OnceLock};

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
#[ignore = "requires real hardened mode bounds checking (bd-q3snos)"]
fn test_malloc_records_ffi_pcc_gate_when_runtime_ready() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    signal_runtime_ready_for_tests();
    let _ = take_last_decision_gate_for_tests();

    let p = unsafe { malloc(256) };

    assert!(!p.is_null(), "malloc(256) should succeed");
    assert_eq!(
        take_last_decision_gate_for_tests(),
        Some("runtime_policy.ffi_pcc.decide")
    );
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
fn test_realloc_same_small_size_class_shrink_updates_bounds_in_place() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(256) };
    assert!(!p.is_null());
    unsafe {
        let slice = std::slice::from_raw_parts_mut(p as *mut u8, 240);
        for (i, byte) in slice.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
    }

    let p2 = unsafe { realloc(p, 240) };
    assert_eq!(
        p2, p,
        "same-size-class shrink should stay in place on the strict fallback path"
    );
    assert_eq!(
        malloc_known_remaining_for_tests(p2.cast_const()),
        Some(240),
        "same-size-class shrink must tighten fallback bounds metadata"
    );
    let slice = unsafe { std::slice::from_raw_parts(p2 as *const u8, 240) };
    for (i, &byte) in slice.iter().enumerate() {
        assert_eq!(byte, (i as u8).wrapping_mul(3).wrapping_add(1));
    }

    let p3 = unsafe { realloc(p2, 256) };
    assert!(
        !p3.is_null(),
        "realloc grow after in-place shrink should succeed"
    );
    let grown = unsafe { std::slice::from_raw_parts(p3 as *const u8, 240) };
    for (i, &byte) in grown.iter().enumerate() {
        assert_eq!(byte, (i as u8).wrapping_mul(3).wrapping_add(1));
    }
    unsafe { free(p3) };
}

#[test]
fn test_segment_bounds_reject_rounded_class_slack() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    signal_runtime_ready_for_tests();
    let p = unsafe { malloc(17) };
    assert!(!p.is_null());
    assert_eq!(
        (p as usize) % 16,
        0,
        "segment payloads preserve max_align_t"
    );
    assert!(
        malloc_segment_owned_for_tests(p.cast_const()),
        "runtime-ready strict small malloc must use the address-derived segment heap"
    );
    assert_eq!(malloc_known_remaining_for_tests(p.cast_const()), Some(17));
    assert_eq!(
        malloc_known_remaining_for_tests(unsafe { p.cast::<u8>().add(1).cast_const().cast() }),
        Some(16)
    );
    assert_eq!(
        malloc_known_remaining_for_tests(unsafe { p.cast::<u8>().add(16).cast_const().cast() }),
        Some(1)
    );
    assert_eq!(
        malloc_known_remaining_for_tests(unsafe { p.cast::<u8>().add(17).cast_const().cast() }),
        None,
        "the 15 bytes of rounded 32-byte class slack are not caller-owned"
    );
    unsafe { free(p) };
    assert_eq!(malloc_known_remaining_for_tests(p.cast_const()), None);
}

#[test]
fn test_segment_free_reuse_and_calloc_lifecycle() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    signal_runtime_ready_for_tests();

    let p = unsafe { malloc(17) };
    assert!(!p.is_null());
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), 0xa7, 17) };
    unsafe { free(p) };
    assert_eq!(unsafe { mprobe(p) }, MCHECK_FREE);
    unsafe { free(p) };

    let q = unsafe { calloc(1, 17) };
    assert_eq!(q, p, "same-class free-list head should be reused");
    assert!(
        unsafe { std::slice::from_raw_parts(q.cast::<u8>(), 17) }
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(malloc_known_remaining_for_tests(q.cast_const()), Some(17));

    let interior = unsafe { q.cast::<u8>().add(1).cast::<c_void>() };
    unsafe { free(interior) };
    assert_eq!(
        malloc_known_remaining_for_tests(q.cast_const()),
        Some(17),
        "interior free must not retire the live slot"
    );
    unsafe { free(q) };

    let a = unsafe { malloc(31) };
    let b = unsafe { malloc(31) };
    assert_eq!(a, q, "reused class-32 slot must accept a new exact bound");
    assert_ne!(a, b, "double-free must not enqueue the same slot twice");
    assert_eq!(malloc_known_remaining_for_tests(a.cast_const()), Some(31));
    unsafe {
        free(a);
        free(b);
    }
}

#[test]
fn test_segment_realloc_matrix_preserves_exact_bounds() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    signal_runtime_ready_for_tests();

    let p = unsafe { malloc(17) };
    assert!(!p.is_null());
    unsafe {
        for i in 0..17 {
            p.cast::<u8>().add(i).write((i as u8).wrapping_mul(7));
        }
    }
    let same_class = unsafe { realloc(p, 31) };
    assert_eq!(same_class, p);
    assert_eq!(
        malloc_known_remaining_for_tests(same_class.cast_const()),
        Some(31)
    );

    let next_class = unsafe { realloc(same_class, 64) };
    assert!(!next_class.is_null());
    assert_ne!(next_class, same_class);
    assert_eq!(
        malloc_known_remaining_for_tests(same_class.cast_const()),
        None
    );
    for i in 0..17 {
        assert_eq!(
            unsafe { next_class.cast::<u8>().add(i).read() },
            (i as u8).wrapping_mul(7)
        );
    }

    let old_segment = next_class;
    let host = unsafe { realloc(old_segment, 32 * 1024 + 1) };
    assert!(!host.is_null());
    assert!(!malloc_segment_owned_for_tests(host.cast_const()));
    assert_eq!(
        malloc_known_remaining_for_tests(old_segment.cast_const()),
        None
    );
    for i in 0..17 {
        assert_eq!(
            unsafe { host.cast::<u8>().add(i).read() },
            (i as u8).wrapping_mul(7)
        );
    }
    unsafe { free(host) };

    let preserved = unsafe { malloc(64) };
    assert!(!preserved.is_null());
    unsafe { preserved.cast::<u8>().write(0x6d) };
    let failed = unsafe { realloc(preserved, usize::MAX) };
    assert!(failed.is_null());
    assert_eq!(
        malloc_known_remaining_for_tests(preserved.cast_const()),
        Some(64),
        "failed realloc must leave the original segment slot live"
    );
    assert_eq!(unsafe { preserved.cast::<u8>().read() }, 0x6d);
    unsafe { free(preserved) };
}

#[test]
fn test_segment_concurrent_live_slots_are_unique() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    signal_runtime_ready_for_tests();
    const THREADS: usize = 8;
    const LIVE_PER_THREAD: usize = 128;
    const SIZE: usize = 1536;
    let barrier = Arc::new(Barrier::new(THREADS));
    let live = Arc::new(Mutex::new(std::collections::HashSet::<usize>::new()));
    let mut joins = Vec::new();

    // Publish the class segment before releasing the worker swarm.  A
    // simultaneous first-use loser intentionally fails open to host malloc;
    // this test targets the lock-free live-slot/free-list invariants.
    let warm = unsafe { malloc(SIZE) };
    assert!(malloc_segment_owned_for_tests(warm.cast_const()));
    unsafe { free(warm) };

    for thread_id in 0..THREADS {
        let barrier = Arc::clone(&barrier);
        let live = Arc::clone(&live);
        joins.push(std::thread::spawn(move || {
            let mut pointers = Vec::with_capacity(LIVE_PER_THREAD);
            for _ in 0..LIVE_PER_THREAD {
                let ptr = unsafe { malloc(SIZE) };
                assert!(!ptr.is_null());
                assert!(malloc_segment_owned_for_tests(ptr.cast_const()));
                assert!(live.lock().expect("live set poisoned").insert(ptr as usize));
                unsafe {
                    ptr.cast::<u8>().write(thread_id as u8);
                    ptr.cast::<u8>()
                        .add(SIZE - 1)
                        .write((thread_id as u8) ^ 0xff);
                }
                pointers.push(ptr);
            }
            barrier.wait();
            for ptr in &pointers {
                assert_eq!(unsafe { ptr.cast::<u8>().read() }, thread_id as u8);
                assert_eq!(
                    unsafe { ptr.cast::<u8>().add(SIZE - 1).read() },
                    (thread_id as u8) ^ 0xff
                );
            }
            barrier.wait();
            for ptr in pointers {
                assert!(
                    live.lock()
                        .expect("live set poisoned")
                        .remove(&(ptr as usize))
                );
                unsafe { free(ptr) };
            }
        }));
    }
    for join in joins {
        join.join().expect("segment worker panicked");
    }
    assert!(live.lock().expect("live set poisoned").is_empty());
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
    // The implementation may either report an actual usable size or `0` to
    // indicate that the underlying host-backed allocation is opaque.
    let usable = unsafe { malloc_usable_size(p) };
    assert!(
        usable == 0 || usable > page_sz,
        "pvalloc({}) usable {} should either be unknown (0) or exceed one page",
        page_sz + 1,
        usable
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
    assert!(
        usable == 0 || usable >= 100,
        "malloc_usable_size should either report unknown (0) or a usable size >= requested, got {}",
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
// mprobe
// ---------------------------------------------------------------------------

const MCHECK_OK: i32 = 0;
const MCHECK_FREE: i32 = 1;
const MCHECK_HEAD: i32 = 2;

#[test]
fn test_mprobe_reports_live_malloc_base_ok() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(64) };
    assert!(!p.is_null());
    assert_eq!(unsafe { mprobe(p) }, MCHECK_OK);
    unsafe { free(p) };
}

#[test]
fn test_mprobe_rejects_stack_pointer() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let mut stack_byte = 0u8;
    let ptr = (&mut stack_byte as *mut u8).cast::<c_void>();
    assert_eq!(unsafe { mprobe(ptr) }, MCHECK_HEAD);
}

#[test]
fn test_mprobe_rejects_malloc_interior_pointer() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { malloc(64) };
    assert!(!p.is_null());
    let interior = unsafe { (p.cast::<u8>()).add(1).cast::<c_void>() };
    assert_eq!(unsafe { mprobe(interior) }, MCHECK_HEAD);
    unsafe { free(p) };
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
        info_after.arena >= info_after.uordblks,
        "mallinfo2 should return a structurally valid snapshot"
    );
    assert!(
        info_after.ordblks >= info.ordblks,
        "active block count should not go backwards across a live allocation"
    );
    unsafe { free(p) };
}

#[test]
fn test_mallinfo2_balanced_after_concurrent_alloc_free() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let before = unsafe { mallinfo2() };
    let workers = 2usize;
    let iters_per_worker = 8usize;

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

#[test]
fn test_malloc_stats_htm_fast_path_commits_when_forced() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    malloc_stats_init_for_tests();
    malloc_htm_reset_for_tests();

    let previous_mode = htm_swap_test_mode_for_tests(HtmTestMode::ForceCommit);
    let before = malloc_htm_snapshot_for_tests();

    let p = unsafe { malloc(4096) };
    assert!(!p.is_null(), "malloc should succeed with forced HTM commit");
    unsafe { free(p) };

    let after = malloc_htm_snapshot_for_tests();
    htm_restore_test_mode_for_tests(previous_mode);

    assert!(
        after.commits > before.commits,
        "malloc/free stats path should commit via HTM before={before:?} after={after:?}"
    );
    assert_eq!(
        after.fallbacks, before.fallbacks,
        "forced commit mode should not take the fallback path"
    );
}

#[test]
fn test_malloc_stats_htm_abort_falls_back_without_breaking_alloc_free() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    malloc_stats_init_for_tests();
    malloc_htm_reset_for_tests();

    let previous_mode = htm_swap_test_mode_for_tests(HtmTestMode::ForceAbort);
    let previous_code = htm_swap_abort_code_for_tests(0xABCD);
    let before = malloc_htm_snapshot_for_tests();

    let p = unsafe { malloc(2048) };
    assert!(
        !p.is_null(),
        "malloc should still succeed after HTM fallback"
    );
    unsafe { free(p) };

    let after = malloc_htm_snapshot_for_tests();
    htm_restore_test_mode_for_tests(previous_mode);
    let _ = htm_swap_abort_code_for_tests(previous_code);

    assert!(
        after.aborts > before.aborts,
        "malloc/free stats path should record abort fallbacks before={before:?} after={after:?}"
    );
    assert!(
        after.fallbacks > before.fallbacks,
        "abort mode should route malloc/free bookkeeping through fallback before={before:?} after={after:?}"
    );
    assert_eq!(after.last_abort_code, 0xABCD);
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

#[test]
fn test_realloc_zero_in_reentrant_path_untracks_fallback_allocation() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    struct ReentryDepthGuard(u32);

    impl Drop for ReentryDepthGuard {
        fn drop(&mut self) {
            malloc_restore_reentry_depth_for_tests(self.0);
        }
    }

    let reentry_depth = ReentryDepthGuard(malloc_swap_reentry_depth_for_tests(1));
    let p = unsafe { malloc(64) };
    assert!(
        !p.is_null(),
        "reentrant malloc should produce a fallback allocation"
    );
    assert_eq!(
        malloc_known_remaining_for_tests(p.cast_const()),
        Some(64),
        "fallback allocation should be tracked before realloc(ptr, 0)"
    );

    let out = unsafe { realloc(p, 0) };
    drop(reentry_depth);

    assert!(out.is_null(), "realloc(ptr, 0) should return NULL");
    assert_eq!(
        malloc_known_remaining_for_tests(p.cast_const()),
        None,
        "realloc(ptr, 0) must not leave stale fallback bounds for freed memory"
    );
}

#[test]
fn test_fallback_range_filter_preserves_tracked_bounds_and_skips_out_of_range() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    struct ReentryDepthGuard(u32);

    impl Drop for ReentryDepthGuard {
        fn drop(&mut self) {
            malloc_restore_reentry_depth_for_tests(self.0);
        }
    }

    let reentry_depth = ReentryDepthGuard(malloc_swap_reentry_depth_for_tests(1));
    let p = unsafe { malloc(128) };
    drop(reentry_depth);
    assert!(
        !p.is_null(),
        "reentrant malloc should produce a fallback allocation"
    );

    let addr = p as usize;
    let (min_addr, max_addr) = malloc_fallback_range_for_tests();
    assert!(
        min_addr <= addr && addr.saturating_add(128) <= max_addr,
        "fallback range must conservatively cover the tracked allocation: range={min_addr:#x}..{max_addr:#x}, ptr={addr:#x}"
    );
    assert_eq!(
        malloc_known_remaining_for_tests(p.cast_const()),
        Some(128),
        "range filter must not exclude an exact tracked allocation pointer"
    );

    let out_of_range = if min_addr > 16 {
        (min_addr - 1) as *const c_void
    } else {
        max_addr as *const c_void
    };
    assert_eq!(
        malloc_known_remaining_for_tests(out_of_range),
        None,
        "out-of-range addresses should skip fallback-table lookup and remain unknown"
    );

    let stack_byte = 0u8;
    assert_eq!(
        malloc_known_remaining_for_tests((&stack_byte as *const u8).cast()),
        None,
        "ordinary stack addresses must remain untracked"
    );

    unsafe { free(p) };
    assert_eq!(
        malloc_known_remaining_for_tests(p.cast_const()),
        None,
        "free must still remove the tracked allocation even though the range is monotone"
    );
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
        usable == 0 || usable >= 512,
        "usable size after realloc should either report unknown (0) or a usable size >= requested"
    );
    unsafe { free(p2) };
}

// ---------------------------------------------------------------------------
// calloc — overflow detection
// ---------------------------------------------------------------------------

#[test]
fn test_calloc_overflow_returns_null() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let calloc = std::hint::black_box(calloc as unsafe extern "C" fn(usize, usize) -> *mut c_void);
    let p = unsafe {
        calloc(
            std::hint::black_box(usize::MAX / 2 + 1),
            std::hint::black_box(3),
        )
    };
    assert!(
        p.is_null(),
        "calloc overflow must return NULL on the normal allocation path"
    );
}

#[test]
fn test_calloc_size_max_returns_null() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let calloc = std::hint::black_box(calloc as unsafe extern "C" fn(usize, usize) -> *mut c_void);
    let p = unsafe { calloc(std::hint::black_box(usize::MAX), std::hint::black_box(2)) };
    assert!(
        p.is_null(),
        "calloc overflow at SIZE_MAX must return NULL on the normal allocation path"
    );
}

#[test]
fn test_calloc_overflow_returns_null_in_reentrant_path() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let previous_depth = malloc_swap_reentry_depth_for_tests(1);
    let calloc = std::hint::black_box(calloc as unsafe extern "C" fn(usize, usize) -> *mut c_void);
    let p = unsafe {
        calloc(
            std::hint::black_box(usize::MAX / 2 + 1),
            std::hint::black_box(3),
        )
    };
    malloc_restore_reentry_depth_for_tests(previous_depth);
    assert!(
        p.is_null(),
        "calloc overflow must return NULL when allocator reentry forces the fallback path"
    );
}

#[test]
fn test_allocator_reentry_depth_is_per_kernel_thread() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let previous_depth = malloc_swap_reentry_depth_for_tests(1);
    let child_previous = std::thread::spawn(|| {
        let previous = malloc_swap_reentry_depth_for_tests(0);
        malloc_restore_reentry_depth_for_tests(previous);
        previous
    })
    .join();
    malloc_restore_reentry_depth_for_tests(previous_depth);
    let child_previous = child_previous.expect("child thread should complete");
    assert_eq!(
        child_previous, 0,
        "allocator reentry depth must not leak across kernel threads"
    );
}

#[test]
fn test_calloc_zero_returns_non_null_or_null() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    // POSIX: calloc(0, 0) may return NULL or a unique pointer.
    let p = unsafe { calloc(0, 0) };
    if !p.is_null() {
        unsafe { free(p) };
    }
}

#[test]
fn test_calloc_zeroed_memory() {
    let _guard = test_lock().lock().expect("test lock poisoned");
    let p = unsafe { calloc(256, 1) };
    assert!(!p.is_null());
    let slice = unsafe { std::slice::from_raw_parts(p as *const u8, 256) };
    assert!(
        slice.iter().all(|&b| b == 0),
        "calloc memory must be zero-initialized"
    );
    unsafe { free(p) };
}

// ---------------------------------------------------------------------------
// Allocator reentry-slot soundness (bd-35hjg.3.1)
// ---------------------------------------------------------------------------

/// The reentry slot a live thread resolves must be stable across repeated
/// lookups: nested allocator calls re-derive the slot and must observe the same
/// per-thread reentry/depth accounting.
#[test]
fn reentry_slot_index_is_stable_for_a_live_thread() {
    let first = malloc_current_reentry_slot_index_for_tests()
        .expect("a live thread must resolve a reentry slot");
    for _ in 0..256 {
        let again = malloc_current_reentry_slot_index_for_tests()
            .expect("reentry slot must remain resolvable");
        assert_eq!(
            first, again,
            "a live thread must keep resolving the same reentry-slot index"
        );
    }
}

/// Regression guard for bd-35hjg.3.1: under heavy thread churn — which forces
/// the kernel to recycle tids and glibc to recycle TCB addresses across thread
/// lifecycles — no two concurrently-live threads may resolve the same allocator
/// reentry slot. A shared slot lets one thread mutate another's reentry/depth
/// accounting, which can pin a thread permanently in-reentry.
#[test]
fn reentry_slots_stay_single_owner_under_thread_churn() {
    const WAVE: usize = 8;
    const WAVES: usize = 64;

    for _wave in 0..WAVES {
        let barrier = Arc::new(Barrier::new(WAVE));
        let owners: Arc<Mutex<Vec<(usize, usize)>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::with_capacity(WAVE);

        for worker in 0..WAVE {
            let barrier = Arc::clone(&barrier);
            let owners = Arc::clone(&owners);
            handles.push(std::thread::spawn(move || {
                // Rendezvous so every worker in this wave is concurrently live
                // while it resolves and re-resolves its reentry slot.
                barrier.wait();
                let idx = malloc_current_reentry_slot_index_for_tests()
                    .expect("worker must resolve a reentry slot");
                let idx_again = malloc_current_reentry_slot_index_for_tests()
                    .expect("worker must re-resolve its reentry slot");
                assert_eq!(
                    idx, idx_again,
                    "reentry slot must stay stable within one live worker thread"
                );
                owners.lock().expect("owners lock").push((idx, worker));
            }));
        }
        for handle in handles {
            handle.join().expect("worker thread joined");
        }

        // All WAVE workers were concurrently live between the barrier and the
        // join, so each must own a distinct reentry slot.
        let owners = owners.lock().expect("owners lock");
        let mut seen: HashMap<usize, usize> = HashMap::new();
        for &(idx, worker) in owners.iter() {
            if let Some(&other) = seen.get(&idx) {
                panic!(
                    "reentry slot {idx} shared by concurrently-live workers \
                     {other} and {worker} (bd-35hjg.3.1)"
                );
            }
            seen.insert(idx, worker);
        }
        assert_eq!(owners.len(), WAVE, "every worker must report a slot");
    }

    // Spawning worker threads must have latched the process into multi-threaded
    // mode, which disables the syscall-free thread-key-only fast path so every
    // lookup verifies the live kernel tid.
    assert!(
        malloc_reentry_multithreaded_latched_for_tests(),
        "thread churn must latch the allocator multi-threaded mode"
    );
}

// ---------------------------------------------------------------------------
// PCC certificate double-free detection (bd-06bxm.5)
// ---------------------------------------------------------------------------
// NOTE: PCC gate and double-free healing tests require LD_PRELOAD context for
// proper runtime arming and membrane allocator activation. The cargo test
// binary links against glibc, so malloc() calls here go to glibc's allocator,
// not our membrane arena. Use E2E tests (scripts/check_pcc_double_free_e2e.sh)
// to verify PCC behavior and double-free healing.
