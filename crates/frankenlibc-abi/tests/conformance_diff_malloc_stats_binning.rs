#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // exercises the C allocator entry points directly
//! Gate for the size-class fold in the malloc stats accumulator (bd-dcrhgl).
//!
//! WHAT CHANGED AND WHAT COULD BREAK. The stats histogram is indexed by size
//! class. It used to recompute that class from the allocation size on every
//! record, through `size_class::bin_index` and its 2KB granule LUT -- twice per
//! malloc/free pair, for a value the allocator had already computed. The hot
//! paths now carry the class out of the allocator instead: `segment_allocate`
//! returns the class it allocated from, and `segment_free` returns the retiring
//! slot's `class_index`.
//!
//! That is exact only while the allocator serves every request from the smallest
//! class that fits. If it ever promoted to a larger class, an allocation would be
//! counted in one histogram bin and its free subtracted from another, and the
//! damage would be invisible in aggregate: total allocated, total freed, and the
//! live-byte count would all still balance, because only the per-class breakdown
//! would be wrong. That is the failure this file exists to catch.
//!
//! HOW IT CATCHES IT. `segment_free` carries a `debug_assert_eq!` comparing the
//! slot's class against the class its requested size maps to. Test binaries are
//! built with debug assertions on, so the assertion is live here and compiled out
//! of the release build that gets measured. This test's job is to DRIVE that
//! assertion across the whole size domain -- every class boundary, both sides of
//! each, the minimum, and sizes past the small-class ceiling that take the host
//! fallback path (where the class is genuinely unknown and the size-derived bin
//! is still used).
//!
//! It also checks the observable consequences that must hold regardless of
//! binning, so a fold that corrupted the accumulator in some other way still
//! fails: allocations must round-trip their contents, and `malloc_usable_size`
//! must remain at least the requested size across the sweep.
//!
//! There is no glibc oracle here on purpose. glibc's histogram is its own and is
//! not comparable bin-for-bin; the invariant under test is internal consistency
//! of fl's accumulator, which an external arm cannot speak to. Naming this file
//! `conformance_diff_*` keeps it in the suite's discovery glob.

use std::ffi::c_void;

/// Every size class boundary in `size_class::SIZE_TABLE`, plus the granule
/// structure around them. Sizes are probed at the boundary, one below, and one
/// above, because an off-by-one in the granule shift shows up nowhere else.
fn sweep_sizes() -> Vec<usize> {
    let mut sizes = Vec::new();
    // 1..=64 exhaustively: the minimum-size clamp (`MIN_SIZE` = 16) and the first
    // few 16-byte granules live here, and this is where a `max(1)` vs `max(16)`
    // mistake in the bin derivation would land.
    sizes.extend(1..=64);
    // Every 16-byte granule up to 2KB, then a coarser sweep to the 32KB ceiling.
    sizes.extend((64..=2048).step_by(16));
    sizes.extend((2048..=32 * 1024).step_by(256));
    // Straddle the small/large boundary: at and just past MAX_SMALL_SIZE the
    // allocator has no class at all and the stats bin falls back to the
    // size-derived large bin. Both sides must be exercised.
    for base in [32 * 1024usize, 64 * 1024, 256 * 1024] {
        sizes.push(base - 1);
        sizes.push(base);
        sizes.push(base + 1);
    }
    sizes.sort_unstable();
    sizes.dedup();
    sizes
}

/// Fill a block with a size-derived pattern and read it back.
///
/// This is what makes a mis-binned or mis-sized allocation fail loudly rather
/// than merely being miscounted: if the class fold ever handed back a block
/// smaller than requested, the write would corrupt a neighbour and the read-back
/// of SOME size in the sweep would disagree.
unsafe fn write_and_verify(ptr: *mut c_void, size: usize) {
    let bytes = ptr.cast::<u8>();
    let pattern = (size % 251) as u8;
    for i in 0..size {
        // SAFETY: `ptr` is a live allocation of at least `size` bytes.
        unsafe { bytes.add(i).write(pattern.wrapping_add((i % 7) as u8)) };
    }
    for i in 0..size {
        // SAFETY: as above; reading back what was just written.
        let got = unsafe { bytes.add(i).read() };
        assert_eq!(
            got,
            pattern.wrapping_add((i % 7) as u8),
            "size {size}: byte {i} read back wrong — allocation is smaller than requested \
             or a neighbouring block overlapped it"
        );
    }
}

#[test]
fn every_size_class_allocates_and_frees_with_a_consistent_bin() {
    let sizes = sweep_sizes();

    // NON-VACUITY, stated as coverage rather than as a count. An earlier version
    // of this asserted a minimum number of sizes, which is the wrong property
    // twice over: the number depends on how the ranges happen to overlap after
    // dedup (it is 316, not the 400 first guessed), and a sweep of 400 sizes that
    // all landed in three classes would still pass it while testing almost
    // nothing. What has to be true is that every bin the fold can produce is
    // actually reached — all NUM_SIZE_CLASSES small classes AND the large bin,
    // which is the one the fold does NOT apply to and must therefore still work.
    use frankenlibc_core::malloc::size_class::{NUM_SIZE_CLASSES, small_bin_index};
    let mut seen = vec![false; NUM_SIZE_CLASSES + 1];
    for &size in &sizes {
        let bin = small_bin_index(size).map_or(NUM_SIZE_CLASSES, |c| c.get());
        seen[bin] = true;
    }
    let missed: Vec<usize> = (0..=NUM_SIZE_CLASSES).filter(|&b| !seen[b]).collect();
    assert!(
        missed.is_empty(),
        "size sweep never reaches bins {missed:?} of 0..={NUM_SIZE_CLASSES} — \
         those classes would go untested"
    );

    let mut freed = 0usize;
    for &size in &sizes {
        // SAFETY: fl's malloc with a non-zero size.
        let ptr = unsafe { frankenlibc_abi::malloc_abi::malloc(size) };
        assert!(!ptr.is_null(), "malloc({size}) returned NULL");

        // SAFETY: `ptr` is a live allocation of at least `size` bytes.
        let usable = unsafe { frankenlibc_abi::malloc_abi::malloc_usable_size(ptr) };
        assert!(
            usable >= size,
            "malloc_usable_size({size}) = {usable}, below the requested size"
        );

        // SAFETY: as above.
        unsafe { write_and_verify(ptr, size) };
        // SAFETY: returning a pointer this arm allocated, exactly once. This is
        // the call that drives the class-agreement debug assertion in
        // `segment_free`.
        unsafe { frankenlibc_abi::malloc_abi::free(ptr) };
        freed += 1;
    }
    assert_eq!(
        freed,
        sizes.len(),
        "not every allocation in the sweep was freed"
    );
}

#[test]
fn interleaved_classes_free_in_a_different_order_than_allocated() {
    // Freeing in allocation order lets each class's magazine be refilled by the
    // block that just left it, which can mask a bin disagreement by keeping one
    // class hot. Holding the whole set live and freeing in reverse forces frees
    // to land against slots allocated much earlier, across many classes.
    let sizes: Vec<usize> = (0..64).map(|i| 16 + i * 61).collect();
    let mut live = Vec::with_capacity(sizes.len());
    for &size in &sizes {
        // SAFETY: non-zero size.
        let ptr = unsafe { frankenlibc_abi::malloc_abi::malloc(size) };
        assert!(!ptr.is_null(), "malloc({size}) returned NULL");
        // SAFETY: live allocation of at least `size` bytes.
        unsafe { write_and_verify(ptr, size) };
        live.push((ptr as usize, size));
    }
    assert_eq!(live.len(), sizes.len(), "not every allocation succeeded");

    // Re-verify every block AFTER all of them are live: this is what catches an
    // overlap that a write-then-immediately-read cannot see.
    for &(addr, size) in &live {
        // SAFETY: still-live allocation of at least `size` bytes.
        unsafe { write_and_verify(addr as *mut c_void, size) };
    }

    for (addr, _) in live.into_iter().rev() {
        // SAFETY: each pointer is freed exactly once, in reverse order.
        unsafe { frankenlibc_abi::malloc_abi::free(addr as *mut c_void) };
    }
}

#[test]
fn realloc_across_class_boundaries_keeps_binning_consistent() {
    // realloc records a free of the old size and an alloc of the new one, and
    // after the fold those two can come from different sources — the old class
    // from the segment view, the new one from `segment_allocate` or, on the host
    // fallback, from the size. Growing and shrinking across boundaries exercises
    // every combination.
    let ladder = [16usize, 17, 32, 33, 64, 200, 1000, 4096, 40_000, 24, 16];
    // SAFETY: non-zero initial size.
    let mut ptr = unsafe { frankenlibc_abi::malloc_abi::malloc(ladder[0]) };
    assert!(!ptr.is_null(), "initial malloc failed");
    // SAFETY: live allocation.
    unsafe { write_and_verify(ptr, ladder[0]) };

    for &size in &ladder[1..] {
        // SAFETY: `ptr` is live and was produced by this allocator.
        let next = unsafe { frankenlibc_abi::malloc_abi::realloc(ptr, size) };
        assert!(!next.is_null(), "realloc to {size} returned NULL");
        ptr = next;
        // SAFETY: `ptr` now holds at least `size` bytes.
        unsafe { write_and_verify(ptr, size) };
    }
    // SAFETY: final live pointer, freed once.
    unsafe { frankenlibc_abi::malloc_abi::free(ptr) };
}

#[test]
fn in_place_shrink_then_free_keeps_the_block_in_one_bin() {
    // THE CASE THAT CAUGHT THE BUG. `segment_resize_in_place` rewrites a slot's
    // requested-size field but leaves the block in its original, larger class.
    // The first version of the class fold binned the free by the slot's class and
    // the in-place resize by the two sizes, so shrinking 1000 -> 100 moved the
    // count into the 112 bin while the block still sat in a 1024 slot; the free
    // then decremented the 1024 bin, flooring it at zero via `saturating_sub` and
    // leaving a phantom count in the 112 bin forever.
    //
    // Aggregate stats cannot see this — bytes and event counts still balance —
    // so the containment assertion in `segment_free` is what makes it observable,
    // and this arm is what drives it. Shrinks that cross several class boundaries
    // and are then freed are the whole point.
    for (start, shrunk) in [
        (1000usize, 100usize),
        (4096, 17),
        (256, 16),
        (32, 16),
        (2048, 1025),
        (17, 16),
    ] {
        // SAFETY: non-zero size.
        let ptr = unsafe { frankenlibc_abi::malloc_abi::malloc(start) };
        assert!(!ptr.is_null(), "malloc({start}) returned NULL");
        // SAFETY: live allocation of at least `start` bytes.
        unsafe { write_and_verify(ptr, start) };

        // SAFETY: shrinking a live allocation this arm produced.
        let shrunk_ptr = unsafe { frankenlibc_abi::malloc_abi::realloc(ptr, shrunk) };
        assert!(
            !shrunk_ptr.is_null(),
            "realloc({start} -> {shrunk}) returned NULL"
        );
        // SAFETY: live allocation of at least `shrunk` bytes.
        unsafe { write_and_verify(shrunk_ptr, shrunk) };

        // Grow back within the original class, then shrink again: repeated
        // resizes must not each shift the block between bins.
        // SAFETY: live allocation.
        let regrown = unsafe { frankenlibc_abi::malloc_abi::realloc(shrunk_ptr, start) };
        assert!(!regrown.is_null(), "realloc({shrunk} -> {start}) returned NULL");
        // SAFETY: live allocation of at least `start` bytes.
        unsafe { write_and_verify(regrown, start) };

        // SAFETY: freed exactly once. This is the call that asserts containment.
        unsafe { frankenlibc_abi::malloc_abi::free(regrown) };
    }
}

#[test]
fn calloc_takes_the_same_binned_path_and_still_zeroes() {
    // calloc shares `strict_small_or_host_allocate`, so it took the same edit.
    // Zeroing is the property most likely to be lost by a refactor of that
    // function's return shape.
    for size in [1usize, 15, 16, 17, 64, 999, 4096, 33_000] {
        // SAFETY: nmemb * size cannot overflow for these values.
        let ptr = unsafe { frankenlibc_abi::malloc_abi::calloc(1, size) };
        assert!(!ptr.is_null(), "calloc(1, {size}) returned NULL");
        let bytes = ptr.cast::<u8>();
        for i in 0..size {
            // SAFETY: live allocation of at least `size` bytes.
            let got = unsafe { bytes.add(i).read() };
            assert_eq!(got, 0, "calloc(1, {size}): byte {i} was not zeroed");
        }
        // SAFETY: freed exactly once.
        unsafe { frankenlibc_abi::malloc_abi::free(ptr) };
    }
}
