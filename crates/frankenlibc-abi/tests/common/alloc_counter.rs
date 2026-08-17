//! A counting global allocator that counts only the ARMING THREAD's allocations.
//!
//! ## Why per-thread and not a lock
//!
//! The obvious design is a process-global `ARMED` flag plus a mutex so only one
//! test measures at a time. That was tried twice and is still not enough:
//!
//! - first the lock covered only the armed window, and each test's warm-up
//!   allocated OUTSIDE it, landing inside a sibling's window;
//! - then the lock covered the whole test body, and it still failed in parallel
//!   mode — `sscanf("7 8 9", "%d %d %d")` read 1 allocation under `cargo test`
//!   and 0 with `--test-threads=1`, on identical code.
//!
//! The residue is not a test body at all. libtest's own harness thread formats
//! and prints results while other tests run, and those allocations are on no
//! test's critical section, so no lock a test can take will exclude them.
//!
//! Counting per-thread removes the whole class: an allocation is counted only if
//! the thread making it is the thread that armed the counter. Sibling tests and
//! the harness thread become invisible rather than merely unlikely.
//!
//! The flag is a `const`-initialised `Cell<bool>`, which is what makes this safe
//! to consult from inside `alloc`: it needs no lazy initialisation and therefore
//! cannot allocate, so the counter never re-enters itself. `try_with` covers the
//! window during thread teardown when the TLS has already been destroyed.

#![allow(dead_code)] // each gate uses only the entry points it needs

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    /// Set only on the thread inside [`count_allocs`].
    static ARMED_HERE: Cell<bool> = const { Cell::new(false) };
}

/// Allocations seen on the armed thread. Single-writer by construction.
static ALLOCS: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn armed() -> bool {
    ARMED_HERE.try_with(Cell::get).unwrap_or(false)
}

pub struct Counting;

// SAFETY: every method forwards to `System` unchanged; the counter observes and
// never changes which pointer is returned or how it is freed.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if armed() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding the caller's layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding the caller's pointer and layout.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if armed() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding the caller's pointer, layout and new size.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if armed() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: forwarding the caller's layout.
        unsafe { System.alloc_zeroed(layout) }
    }
}

/// Run `f` and return how many allocations IT made, on this thread.
///
/// Nesting is rejected rather than silently miscounted: an inner window would
/// reset the outer one's count.
pub fn count_allocs(f: impl FnOnce()) -> usize {
    assert!(!armed(), "count_allocs is not re-entrant");
    ALLOCS.store(0, Ordering::Relaxed);
    ARMED_HERE.with(|a| a.set(true));
    f();
    ARMED_HERE.with(|a| a.set(false));
    ALLOCS.load(Ordering::Relaxed)
}
