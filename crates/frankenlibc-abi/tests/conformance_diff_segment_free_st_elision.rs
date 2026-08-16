#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // drives the C allocator entry points directly
//! Gate for `segment_free`'s slot-retire path, across the `MULTI_THREADED` latch
//! (bd-dcrhgl, bd-65p87u).
//!
//! WRITTEN FOR A LEVER THAT WAS THEN REJECTED, and kept because the property it
//! checks is independent of it. The lever was to elide the retire's
//! `requested_size.swap(SEGMENT_SLOT_FREE, AcqRel)` — a `lock xchg` on every
//! free — down to a load and a store while `MULTI_THREADED` is unlatched, which
//! is semantically exact because no second thread can interleave. Measured with
//! both arms in one window it was 1.53% SLOWER, with complete separation across
//! eight paired groups, so it was reverted. The branch on the latch costs more
//! than the atomic saves on a line already exclusive in L1.
//!
//! WHAT THIS STILL GUARDS. The retire is what makes a slot reusable, and getting
//! it wrong corrupts the heap silently: a slot retired twice is pushed into a
//! magazine twice and eventually handed to two live callers at the same address,
//! with nothing faulting at the point of the bug and a size-only test passing.
//! The arms below assert the property that violation actually breaks — every
//! LIVE allocation has a distinct address — across free-and-reuse cycles on both
//! sides of the latch. That is worth keeping whether or not the retire is atomic,
//! and it is what any future attempt at this lever has to satisfy.
//!
//! WHY THERE IS NO DOUBLE-FREE ARM, which the first version of this file had.
//! Freeing the same pointer twice through the public entry point is undefined at
//! the API boundary, and it does not reach the code under test: fl's `malloc`
//! routes some requests to the host allocator, so the second free landed in
//! glibc and aborted the process with "free(): double free detected in tcache 2".
//! That abort is CORRECT — glibc defending its own heap — but it means a double
//! free tests whichever allocator happened to own the pointer rather than
//! `segment_free`'s retire ordering.
//!
//! The multi-threaded path is exercised too. `MULTI_THREADED` is a ONE-WAY latch:
//! once a second thread touches the allocator it never unlatches, so the arms
//! that need the un-latched path must run BEFORE any thread is spawned. Test
//! binaries run arms in parallel by default, which would make that ordering
//! luck — so the single-threaded arm and the latching arm live in one `#[test]`
//! in a deliberate order rather than in two that libtest may interleave.

use std::collections::HashSet;
use std::ffi::c_void;

/// Allocate, fill, and hand back the address as an integer.
unsafe fn alloc_filled(size: usize, byte: u8) -> usize {
    // SAFETY: non-zero size.
    let p = unsafe { frankenlibc_abi::malloc_abi::malloc(size) };
    assert!(!p.is_null(), "malloc({size}) returned NULL");
    // SAFETY: `p` is a live allocation of at least `size` bytes.
    unsafe { std::ptr::write_bytes(p.cast::<u8>(), byte, size) };
    p as usize
}

/// Every live allocation must have a distinct address. This is the property a
/// double-retire actually violates, and it is invisible to any test that only
/// checks sizes or return codes.
fn assert_all_distinct(addrs: &[usize], what: &str) {
    let unique: HashSet<usize> = addrs.iter().copied().collect();
    assert_eq!(
        unique.len(),
        addrs.len(),
        "{what}: the allocator handed out the same address twice while all were live \
         — a slot was retired more than once"
    );
}

#[test]
fn slot_retire_is_correct_single_threaded_then_after_the_latch() {
    // ---- PHASE 1: un-latched. No thread has been spawned yet, so this runs on
    // the elided load+store path. Ordering matters and is why this is one test.
    let mut live = Vec::new();
    for i in 0..256usize {
        // SAFETY: sizes are non-zero.
        live.push(unsafe { alloc_filled(16 + (i % 48), (i % 251) as u8) });
    }
    assert_all_distinct(&live, "single-threaded, all live");

    // Free every other one, then reallocate the same count. If a retire were
    // lost or doubled, the reissued addresses would collide with the ones still
    // held.
    let mut held = Vec::new();
    for (i, &a) in live.iter().enumerate() {
        if i % 2 == 0 {
            // SAFETY: freed exactly once here; the odd indices are still live.
            unsafe { frankenlibc_abi::malloc_abi::free(a as *mut c_void) };
        } else {
            held.push(a);
        }
    }
    let mut reissued = Vec::new();
    for i in 0..128usize {
        // SAFETY: non-zero size.
        reissued.push(unsafe { alloc_filled(16 + (i % 48), 0x5A) });
    }
    let mut all = held.clone();
    all.extend_from_slice(&reissued);
    assert_all_distinct(&all, "single-threaded, held plus reissued");

    // A fresh batch after the reuse cycle above: if any retire were doubled, one
    // of these would collide with an address the caller still holds.
    let mut after = Vec::new();
    for _ in 0..64 {
        // SAFETY: non-zero size.
        after.push(unsafe { alloc_filled(24, 0xC3) });
    }
    assert_all_distinct(&after, "after free-and-reuse on the elided path");
    for &a in &held {
        assert!(
            !after.contains(&a),
            "an address still held by the caller was handed out again"
        );
    }

    // ---- PHASE 2: latch MULTI_THREADED and repeat on the atomic path.
    // Spawning a thread that touches the allocator is what sets the one-way
    // latch, so everything after this point exercises the swap.
    let handle = std::thread::spawn(|| {
        let mut v = Vec::new();
        for i in 0..64usize {
            // SAFETY: non-zero size.
            v.push(unsafe { alloc_filled(32 + (i % 16), 0x77) });
        }
        for a in &v {
            // SAFETY: each freed exactly once, on the thread that allocated it.
            unsafe { frankenlibc_abi::malloc_abi::free(*a as *mut c_void) };
        }
        v.len()
    });
    let freed_on_other_thread = handle.join().expect("allocator thread panicked");
    assert_eq!(freed_on_other_thread, 64, "the spawned thread did no work");

    let mut post = Vec::new();
    for i in 0..256usize {
        // SAFETY: non-zero size.
        post.push(unsafe { alloc_filled(16 + (i % 48), (i % 251) as u8) });
    }
    assert_all_distinct(&post, "after the multi-threaded latch");

    let mut after2 = Vec::new();
    for _ in 0..64 {
        // SAFETY: non-zero size.
        after2.push(unsafe { alloc_filled(24, 0x2B) });
    }
    assert_all_distinct(&after2, "after free-and-reuse on the atomic path");

    // Clean up what is still live.
    for a in held.into_iter().chain(after).chain(post.into_iter()).chain(after2) {
        // SAFETY: each of these was allocated above and not yet freed.
        unsafe { frankenlibc_abi::malloc_abi::free(a as *mut c_void) };
    }
}

#[test]
fn contents_survive_a_free_and_reuse_cycle_across_size_classes() {
    // A retire that wrote the wrong value — rather than losing the ordering —
    // would corrupt the recorded size instead of the slot state, which shows up
    // as a short allocation rather than as a duplicate address. Write the full
    // requested length and read it back after a reuse cycle to catch that.
    for size in [16usize, 17, 32, 64, 100, 512, 1000, 4096] {
        let mut round = Vec::new();
        for i in 0..32 {
            // SAFETY: non-zero size.
            let a = unsafe { alloc_filled(size, (i % 251) as u8) };
            round.push((a, (i % 251) as u8));
        }
        for &(a, byte) in &round {
            // SAFETY: live allocation of at least `size` bytes.
            let slice = unsafe { std::slice::from_raw_parts(a as *const u8, size) };
            assert!(
                slice.iter().all(|&b| b == byte),
                "size {size}: contents changed before free"
            );
        }
        for &(a, _) in &round {
            // SAFETY: each freed exactly once.
            unsafe { frankenlibc_abi::malloc_abi::free(a as *mut c_void) };
        }
        // Reuse the same class immediately; the recorded size must still be
        // honoured for the full length.
        for i in 0..32 {
            // SAFETY: non-zero size.
            let a = unsafe { alloc_filled(size, 0xE7) };
            // SAFETY: live allocation of at least `size` bytes.
            let slice = unsafe { std::slice::from_raw_parts(a as *const u8, size) };
            assert!(
                slice.iter().all(|&b| b == 0xE7),
                "size {size}, reuse {i}: write of the full requested length did not stick"
            );
            // SAFETY: freed exactly once.
            unsafe { frankenlibc_abi::malloc_abi::free(a as *mut c_void) };
        }
    }
}
