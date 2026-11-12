//! Shared internal utilities for ABI adapters.

use std::cell::UnsafeCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{c_char, c_void};
#[cfg(feature = "owned-tls-cache")]
use std::hash::{BuildHasherDefault, Hasher};
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

#[cfg(feature = "owned-tls-cache")]
#[derive(Clone)]
pub(crate) struct DeterministicHasher {
    state: u64,
}

#[cfg(feature = "owned-tls-cache")]
impl Default for DeterministicHasher {
    fn default() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

#[cfg(feature = "owned-tls-cache")]
impl Hasher for DeterministicHasher {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        for byte in bytes {
            self.state ^= u64::from(*byte);
            self.state = self.state.wrapping_mul(PRIME);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

#[cfg(feature = "owned-tls-cache")]
type ArtifactBuildHasher = BuildHasherDefault<DeterministicHasher>;

#[cfg(feature = "owned-tls-cache")]
pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V, ArtifactBuildHasher>;
#[cfg(not(feature = "owned-tls-cache"))]
pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V>;

#[cfg_attr(test, allow(dead_code))]
#[cfg(feature = "owned-tls-cache")]
pub(crate) type ArtifactHashSet<T> = HashSet<T, ArtifactBuildHasher>;
#[cfg_attr(test, allow(dead_code))]
#[cfg(not(feature = "owned-tls-cache"))]
pub(crate) type ArtifactHashSet<T> = HashSet<T>;

#[inline]
pub(crate) fn artifact_hash_map<K, V>() -> ArtifactHashMap<K, V> {
    ArtifactHashMap::default()
}

#[inline]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn artifact_hash_set<T>() -> ArtifactHashSet<T> {
    ArtifactHashSet::default()
}

/// Small ABI-internal reentrant mutex that avoids Rust TLS.
///
/// `parking_lot::ReentrantMutex` is excellent for normal Rust code, but its
/// owner tracking emits a thread-local RawThreadId key in the standalone
/// replacement artifact. ABI startup/interpose paths only need same-thread
/// recursion plus mutual exclusion, so this lock tracks ownership with the
/// kernel TID and backs off with `sched_yield` under contention.
pub(crate) struct AbiReentrantMutex<T, const KERNEL_TID: bool = false> {
    // Kernel-TID mode packs the u32 identity and u32 depth in one word. A
    // signal may reenter between any instructions, so publishing ownership
    // before a separate depth store would expose an incomplete acquisition.
    owner_tid: AtomicUsize,
    recursion_depth: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: the lock serializes mutable access to `value`; sharing the mutex is
// sound when the protected value can move across threads.
unsafe impl<T: Send, const KERNEL_TID: bool> Sync for AbiReentrantMutex<T, KERNEL_TID> {}
// SAFETY: ownership transfer preserves the lock/value invariants.
unsafe impl<T: Send, const KERNEL_TID: bool> Send for AbiReentrantMutex<T, KERNEL_TID> {}

impl<T> AbiReentrantMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            owner_tid: AtomicUsize::new(0),
            recursion_depth: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

}

impl<T> AbiReentrantMutex<T, true> {
    /// Stable kernel identity even when creating the first native thread
    /// changes the allocator's fast owner-key strategy inside a held lock.
    pub(crate) const fn new_kernel_tid(value: T) -> Self {
        assert!(
            usize::BITS == 64,
            "native loader locking requires a 64-bit target"
        );
        Self {
            owner_tid: AtomicUsize::new(0),
            recursion_depth: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }
}

impl<T, const KERNEL_TID: bool> AbiReentrantMutex<T, KERNEL_TID> {
    #[inline]
    pub(crate) fn lock(&self) -> AbiReentrantMutexGuard<'_, T, KERNEL_TID> {
        let tid = Self::current_owner_tid();
        let mut spins = 0u32;
        loop {
            if self.try_lock_for_tid(tid) {
                return AbiReentrantMutexGuard {
                    lock: self,
                    _not_send_sync: PhantomData,
                };
            }

            spins = spins.wrapping_add(1);
            if spins & 0x3ff == 0 {
                frankenlibc_core::syscall::sys_sched_yield();
            } else {
                std::hint::spin_loop();
            }
        }
    }

    /// Exclusive access proves no other thread holds or can take the lock.
    #[inline]
    #[allow(dead_code)]
    pub(crate) fn get_mut(&mut self) -> &mut T {
        self.value.get_mut()
    }

    #[inline]
    pub(crate) fn try_lock(&self) -> Option<AbiReentrantMutexGuard<'_, T, KERNEL_TID>> {
        let tid = Self::current_owner_tid();
        self.try_lock_for_tid(tid).then(|| AbiReentrantMutexGuard {
            lock: self,
            _not_send_sync: PhantomData,
        })
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
        self.unlock_for_tid(Self::current_owner_tid());
    }

    /// Call in a `fork` child for a lock the forking thread held across the
    /// clone. The child's only thread has a new TID, so ownership recorded
    /// under the parent's TID would make the guard's drop a silent no-op and
    /// leave the lock held forever: the next `fork`/`setenv` in the child
    /// spun at 100% CPU (`tar -czf`, bd-rc0923-epic-eeuy4f.5). Transfers
    /// ownership (and recursion depth) to the child's thread.
    ///
    /// # Safety
    ///
    /// Must only be called in a freshly forked child, before any other thread
    /// exists, with `parent_tid` read by the forking thread before the clone.
    #[allow(dead_code)]
    #[inline]
    pub(crate) unsafe fn adopt_in_fork_child(&self, parent_tid: usize) {
        if KERNEL_TID {
            let mut state = self.owner_tid.load(Ordering::Acquire);
            while (state as u64 >> 32) == parent_tid as u64 {
                let adopted =
                    ((Self::current_owner_tid() as u64) << 32) | u64::from(state as u32);
                match self.owner_tid.compare_exchange_weak(
                    state,
                    adopted as usize,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(current) => state = current,
                }
            }
            return;
        }
        let _ = self.owner_tid.compare_exchange(
            parent_tid,
            Self::current_owner_tid(),
            Ordering::AcqRel,
            Ordering::Relaxed,
        );
    }

    /// Owner key used for ownership, exposed so fork paths can record the parent's.
    #[allow(dead_code)]
    #[inline]
    pub(crate) fn current_owner_tid() -> usize {
        if KERNEL_TID {
            (frankenlibc_core::syscall::sys_gettid().max(1) as usize) << 1
        } else {
            current_tid()
        }
    }

    #[inline]
    fn try_lock_for_tid(&self, tid: usize) -> bool {
        if KERNEL_TID {
            let mut state = self.owner_tid.load(Ordering::Acquire);
            loop {
                let depth = if state == 0 {
                    1
                } else if (state as u64 >> 32) == tid as u64 {
                    let Some(depth) = (state as u32).checked_add(1) else {
                        return false;
                    };
                    depth
                } else {
                    return false;
                };
                let acquired = ((tid as u64) << 32) | u64::from(depth);
                match self.owner_tid.compare_exchange_weak(
                    state,
                    acquired as usize,
                    Ordering::Acquire,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return true,
                    Err(current) => state = current,
                }
            }
        }
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
    fn unlock_for_tid(&self, tid: usize) {
        if KERNEL_TID {
            let mut state = self.owner_tid.load(Ordering::Relaxed);
            loop {
                if (state as u64 >> 32) != tid as u64 {
                    return;
                }
                let released = if state as u32 > 1 { state - 1 } else { 0 };
                match self.owner_tid.compare_exchange_weak(
                    state,
                    released,
                    Ordering::Release,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => return,
                    Err(current) => state = current,
                }
            }
        }
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
fn current_tid() -> usize {
    #[cfg(not(test))]
    if let Some(owner_key) = crate::malloc_abi::fast_thread_owner_key() {
        return owner_key;
    }
    (frankenlibc_core::syscall::sys_gettid().max(1) as usize) << 1
}

/// An acquisition belongs to the current kernel thread, not just to the lock.
///
/// A bare `&AbiReentrantMutex<T>` would make this guard `Send + Sync` for any
/// `T: Send`, including `Cell<T>`. Moving it would let another thread access
/// the value while the owner recursively acquires it; sharing it would expose
/// a non-`Sync` value concurrently. A foreign-thread drop also cannot release
/// the owner's recursion level. Keep both auto traits disabled explicitly.
pub(crate) struct AbiReentrantMutexGuard<'a, T, const KERNEL_TID: bool = false> {
    lock: &'a AbiReentrantMutex<T, KERNEL_TID>,
    _not_send_sync: PhantomData<*mut ()>,
}

impl<T, const KERNEL_TID: bool> Deref for AbiReentrantMutexGuard<'_, T, KERNEL_TID> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: the guard proves this thread holds the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T, const KERNEL_TID: bool> Drop for AbiReentrantMutexGuard<'_, T, KERNEL_TID> {
    #[inline]
    fn drop(&mut self) {
        self.lock
            .unlock_for_tid(AbiReentrantMutex::<T, KERNEL_TID>::current_owner_tid());
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
/// # NOT `string_abi::scan_c_string`, and the difference is a page fault
///
/// There are TWO functions with this name in this crate and their read
/// footprints differ. THIS one walks byte by byte and stops at the terminator,
/// so it never touches a byte past the NUL — which is why a caller may hand it a
/// DEFENSIVE CAP (a limit it invented for a string of unknown length, like
/// `MAX_PUBLISHED_PROGNAME_BYTES`) over a pointer it does not own.
/// [`crate::string_abi::scan_c_string`] is the SWAR/SIMD scanner: its bounded arm
/// treats the bound as a promise of readable bytes and loads whole 128-byte
/// windows under it, so the same call there faults on a string that ends flush
/// against a page boundary.
///
/// The 20 modules that `use crate::util::scan_c_string` therefore get the safe
/// one for free, and `string_abi`'s is only ever reached FULLY QUALIFIED. That
/// invariant is not decoration — bd-defensive-cap-scan-sweep-fhk28c was filed
/// against six cap sites on the strength of the other function's contract, and
/// all six turned out to call this one. `tests/capped_scans_use_the_scalar_scanner.rs`
/// pins it so a future `use crate::string_abi::scan_c_string` cannot silently
/// change which scanner those bare calls resolve to.
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
    use super::{AbiReentrantMutex, AbiReentrantMutexGuard, TEST_ALLOC_BOUNDS, scan_c_string};
    use std::cell::Cell;
    use std::sync::Arc;

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

    #[test]
    fn abi_reentrant_mutex_guard_is_neither_send_nor_sync() {
        // Inference is unambiguous only when the second impl does not apply.
        // Restoring either auto trait makes this test fail to compile, before
        // an unsound cross-thread access can execute. No extra dependency or
        // doctest visibility workaround is needed for these private types.
        macro_rules! assert_not_impl {
            ($ty:ty, $bound:path) => {{
                trait AmbiguousIfImpl<A> {
                    fn check() {}
                }
                impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
                struct Implemented;
                impl<T: ?Sized + $bound> AmbiguousIfImpl<Implemented> for T {}
                let _ = <$ty as AmbiguousIfImpl<_>>::check;
            }};
        }

        assert_not_impl!(AbiReentrantMutexGuard<'static, usize>, Send);
        assert_not_impl!(AbiReentrantMutexGuard<'static, usize>, Sync);
        assert_not_impl!(AbiReentrantMutexGuard<'static, Cell<usize>>, Send);
        assert_not_impl!(AbiReentrantMutexGuard<'static, Cell<usize>>, Sync);

        // Only the acquisition is thread-bound: sharing the lock itself must
        // remain possible for Send-but-not-Sync protected values.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AbiReentrantMutex<Cell<usize>>>();
    }

    #[test]
    fn abi_reentrant_mutex_excludes_other_threads_until_final_guard_drop() {
        let lock = Arc::new(AbiReentrantMutex::new(Cell::new(7usize)));
        let outer = lock.lock();
        let inner = lock.try_lock().expect("recursive acquisition");

        let probe = Arc::clone(&lock);
        assert!(
            std::thread::spawn(move || probe.try_lock().is_none())
                .join()
                .expect("contending thread")
        );
        // Guards need not be dropped in acquisition order, but each one must
        // release exactly one level on the owner thread.
        drop(outer);
        inner.set(11);
        let probe = Arc::clone(&lock);
        assert!(
            std::thread::spawn(move || probe.try_lock().is_none())
                .join()
                .expect("contending thread")
        );
        drop(inner);

        let probe = Arc::clone(&lock);
        assert_eq!(
            std::thread::spawn(move || {
                let guard = probe.try_lock().expect("final drop releases lock");
                guard.get()
            })
            .join()
            .expect("next owner"),
            11
        );
    }

    #[test]
    fn abi_reentrant_mutex_serializes_recursive_cell_updates() {
        let lock = AbiReentrantMutex::new(Cell::new(0usize));
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..250 {
                        let outer = lock.lock();
                        outer.set(outer.get() + 1);
                        let inner = lock.lock();
                        inner.set(inner.get() + 1);
                    }
                });
            }
        });
        assert_eq!(lock.lock().get(), 2000);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn kernel_tid_lock_excludes_clone_threads_sharing_compiler_tls() {
        use frankenlibc_core::pthread::thread::{create_thread, join_thread};

        unsafe extern "C" fn probe(argument: usize) -> usize {
            // SAFETY: the parent retains the lock until joining this worker.
            let lock =
                unsafe { &*(argument as *const AbiReentrantMutex<Cell<usize>, true>) };
            let Some(outer) = lock.try_lock() else {
                return usize::MAX;
            };
            // Both acquisitions use this child's kernel identity. The
            // worker deliberately performs no heap or compiler-TLS operation.
            let Some(inner) = lock.try_lock() else {
                return usize::MAX - 1;
            };
            let value = outer.get();
            inner.set(value + 1);
            value
        }

        let lock = AbiReentrantMutex::new_kernel_tid(Cell::new(41usize));
        let argument = std::ptr::from_ref(&lock) as usize;
        let run = || {
            // SAFETY: valid C entry point; the borrowed lock outlives join.
            let thread = unsafe { create_thread(probe as *const () as usize, argument, 0) }
                .expect("native clone creation");
            // SAFETY: this parent owns the sole join for this live handle.
            unsafe { join_thread(thread) }.expect("native clone join")
        };
        let outer = lock.lock();
        let inner = lock.lock();
        assert_eq!(run(), usize::MAX);
        drop(outer);
        assert_eq!(run(), usize::MAX);
        drop(inner);
        assert_eq!(run(), 41);
        assert_eq!(lock.lock().get(), 42);
    }
}
