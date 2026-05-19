//! Shared internal utilities for ABI adapters.

use std::cell::UnsafeCell;
use std::ffi::{c_char, c_void};
use std::ops::Deref;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

/// Small ABI-internal reentrant mutex that avoids Rust TLS.
///
/// `parking_lot::ReentrantMutex` is excellent for normal Rust code, but its
/// owner tracking emits a thread-local RawThreadId key in the standalone
/// replacement artifact. ABI startup/interpose paths only need same-thread
/// recursion plus mutual exclusion, so this lock tracks ownership with the
/// kernel TID and backs off with `sched_yield` under contention.
pub(crate) struct AbiReentrantMutex<T> {
    owner_tid: AtomicI32,
    recursion_depth: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: the lock serializes mutable access to `value`; sharing the mutex is
// sound when the protected value can move across threads.
unsafe impl<T: Send> Sync for AbiReentrantMutex<T> {}
// SAFETY: ownership transfer preserves the lock/value invariants.
unsafe impl<T: Send> Send for AbiReentrantMutex<T> {}

impl<T> AbiReentrantMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            owner_tid: AtomicI32::new(0),
            recursion_depth: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    #[inline]
    pub(crate) fn lock(&self) -> AbiReentrantMutexGuard<'_, T> {
        let tid = current_tid();
        let mut spins = 0u32;
        loop {
            if self.try_lock_for_tid(tid) {
                return AbiReentrantMutexGuard { lock: self };
            }

            spins = spins.wrapping_add(1);
            if spins & 0x3f == 0 {
                frankenlibc_core::syscall::sys_sched_yield();
            } else {
                std::hint::spin_loop();
            }
        }
    }

    #[inline]
    pub(crate) fn try_lock(&self) -> Option<AbiReentrantMutexGuard<'_, T>> {
        let tid = current_tid();
        self.try_lock_for_tid(tid)
            .then_some(AbiReentrantMutexGuard { lock: self })
    }

    #[inline]
    #[allow(dead_code)]
    pub(crate) fn opaque_ptr(&self) -> *mut c_void {
        (self as *const Self).cast::<c_void>() as *mut c_void
    }

    /// Release one recursion level for a deliberately forgotten guard.
    ///
    /// # Safety
    ///
    /// The current thread must have acquired this lock and intentionally kept
    /// the guard alive with `mem::forget`.
    #[inline]
    #[allow(dead_code)]
    pub(crate) unsafe fn unlock_forgotten_guard(&self) {
        self.unlock_for_tid(current_tid());
    }

    #[inline]
    fn try_lock_for_tid(&self, tid: i32) -> bool {
        if self.owner_tid.load(Ordering::Acquire) == tid {
            let previous = self.recursion_depth.fetch_add(1, Ordering::Relaxed);
            debug_assert!(previous > 0);
            return true;
        }

        if self
            .owner_tid
            .compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            self.recursion_depth.store(1, Ordering::Relaxed);
            return true;
        }

        false
    }

    #[inline]
    fn unlock_for_tid(&self, tid: i32) {
        if self.owner_tid.load(Ordering::Acquire) != tid {
            return;
        }

        let depth = self.recursion_depth.load(Ordering::Relaxed);
        if depth > 1 {
            self.recursion_depth.store(depth - 1, Ordering::Relaxed);
            return;
        }

        self.recursion_depth.store(0, Ordering::Relaxed);
        self.owner_tid.store(0, Ordering::Release);
    }
}

#[inline]
fn current_tid() -> i32 {
    frankenlibc_core::syscall::sys_gettid().max(1)
}

pub(crate) struct AbiReentrantMutexGuard<'a, T> {
    lock: &'a AbiReentrantMutex<T>,
}

impl<T> Deref for AbiReentrantMutexGuard<'_, T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard proves this thread holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for AbiReentrantMutexGuard<'_, T> {
    #[inline]
    fn drop(&mut self) {
        self.lock.unlock_for_tid(current_tid());
    }
}

#[inline]
fn allocation_bound(ptr: *const c_char) -> Option<usize> {
    #[cfg(not(test))]
    {
        crate::malloc_abi::known_remaining(ptr as usize)
    }

    #[cfg(test)]
    {
        test_allocation_bound(ptr as usize)
    }
}

/// Scan a C string with an optional hard bound.
///
/// Returns `(len, terminated)` where:
/// - `len` is the byte length before the first NUL or before the bound.
/// - `terminated` indicates whether a NUL byte was observed.
///
/// # Safety
///
/// `ptr` must be valid to read up to the discovered length (and bound when given).
pub unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>) -> (usize, bool) {
    let effective_bound = match (bound, allocation_bound(ptr)) {
        (Some(limit), Some(alloc)) => Some(limit.min(alloc)),
        (Some(limit), None) => Some(limit),
        (None, Some(alloc)) => Some(alloc),
        (None, None) => None,
    };

    match effective_bound {
        Some(limit) => {
            for i in 0..limit {
                if unsafe { *ptr.add(i) } == 0 {
                    return (i, true);
                }
            }
            (limit, false)
        }
        None => {
            let mut i = 0usize;
            while unsafe { *ptr.add(i) } != 0 {
                i += 1;
            }
            (i, true)
        }
    }
}

#[cfg(test)]
static TEST_ALLOC_BOUNDS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

#[cfg(test)]
fn test_allocation_bound(addr: usize) -> Option<usize> {
    let guard = TEST_ALLOC_BOUNDS.lock().unwrap_or_else(|e| e.into_inner());
    guard.iter().find_map(|(base, len)| {
        let end = base.saturating_add(*len);
        (addr >= *base && addr < end).then_some(end - addr)
    })
}

#[cfg(test)]
mod tests {
    use super::{AbiReentrantMutex, TEST_ALLOC_BOUNDS, scan_c_string};
    use std::cell::Cell;

    struct TestBoundGuard {
        base: usize,
        len: usize,
    }

    impl TestBoundGuard {
        fn new(bytes: &[u8]) -> Self {
            let base = bytes.as_ptr() as usize;
            let len = bytes.len();
            TEST_ALLOC_BOUNDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((base, len));
            Self { base, len }
        }
    }

    impl Drop for TestBoundGuard {
        fn drop(&mut self) {
            TEST_ALLOC_BOUNDS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|entry| *entry != (self.base, self.len));
        }
    }

    #[test]
    fn scan_c_string_intersects_explicit_bound_with_tracked_allocation() {
        let bytes = *b"hello";
        let _guard = TestBoundGuard::new(&bytes);

        assert_eq!(
            unsafe { scan_c_string(bytes.as_ptr().cast::<std::ffi::c_char>(), Some(64)) },
            (5, false)
        );
    }

    #[test]
    fn scan_c_string_keeps_smaller_explicit_bound() {
        let bytes = *b"hello";
        let _guard = TestBoundGuard::new(&bytes);

        assert_eq!(
            unsafe { scan_c_string(bytes.as_ptr().cast::<std::ffi::c_char>(), Some(2)) },
            (2, false)
        );
    }

    #[test]
    fn abi_reentrant_mutex_allows_same_thread_recursion() {
        let lock = AbiReentrantMutex::new(Cell::new(0usize));
        let outer = lock.lock();
        outer.set(outer.get() + 1);

        {
            let inner = lock.lock();
            inner.set(inner.get() + 1);
        }

        assert_eq!(outer.get(), 2);
        drop(outer);
        assert_eq!(lock.lock().get(), 2);
    }

    #[test]
    fn abi_reentrant_mutex_try_lock_reports_same_thread_success() {
        let lock = AbiReentrantMutex::new(Cell::new(7usize));
        let _outer = lock.lock();
        let inner = lock
            .try_lock()
            .expect("same-thread recursive try_lock should succeed");
        assert_eq!(inner.get(), 7);
    }
}
