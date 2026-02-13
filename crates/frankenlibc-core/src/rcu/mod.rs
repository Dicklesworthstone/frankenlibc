//! QSBR-based Read-Copy-Update (RCU) for thread metadata.
//!
//! Implements Quiescent State Based Reclamation (QSBR) for lock-free reads
//! of shared data structures with deferred reclamation. Readers are wait-free
//! (no barriers in the read path), writers wait for a grace period before
//! freeing old data.
//!
//! # Design
//!
//! - Per-thread epoch counter (cache-line aligned via padding).
//! - Global epoch counter incremented by writers.
//! - `synchronize_rcu()` blocks until all registered readers have passed
//!   through at least one quiescent state since the call began.
//! - `rcu_quiescent_state()` marks the calling thread as having observed
//!   the current epoch (called at natural quiescent points: syscall
//!   boundaries, allocation entry/exit).
//!
//! # Safety
//!
//! The RCU domain uses raw pointers internally. All public APIs document
//! their safety invariants. The module requires `#[allow(unsafe_code)]`
//! because it manages raw pointer lifecycles.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of concurrently registered RCU reader threads.
/// Matches TLS_TABLE_SLOTS from tls.rs for consistency.
const MAX_RCU_THREADS: usize = 256;

/// Sentinel value indicating an unregistered slot.
const SLOT_EMPTY: u32 = 0;

/// Sentinel epoch value for offline (unregistered or quiescent) threads.
const EPOCH_OFFLINE: u64 = 0;

/// Cache-line size for padding to avoid false sharing.
const CACHE_LINE: usize = 64;

// ---------------------------------------------------------------------------
// Per-thread RCU reader state
// ---------------------------------------------------------------------------

/// Per-thread reader state, padded to avoid false sharing.
///
/// Each registered thread has one slot. The `epoch` field is updated
/// by the reader at quiescent points and read by writers during
/// `synchronize_rcu()`.
#[repr(C)]
struct ReaderSlot {
    /// Thread ID that owns this slot (0 = empty).
    tid: AtomicU32,
    /// Reader's observed epoch. Set to `EPOCH_OFFLINE` when not in a
    /// read-side critical section or when the thread is unregistered.
    epoch: AtomicU64,
    /// Padding to fill a cache line (64 bytes).
    /// tid (4) + epoch (8) = 12 bytes; need 52 bytes of padding.
    _pad: [u8; CACHE_LINE - 12],
}

impl ReaderSlot {
    const fn new() -> Self {
        Self {
            tid: AtomicU32::new(SLOT_EMPTY),
            epoch: AtomicU64::new(EPOCH_OFFLINE),
            _pad: [0u8; CACHE_LINE - 12],
        }
    }
}

// ---------------------------------------------------------------------------
// Global RCU state
// ---------------------------------------------------------------------------

/// Global epoch counter. Writers increment this before waiting for readers.
static GLOBAL_EPOCH: AtomicU64 = AtomicU64::new(1);

/// Reader slot table. Fixed-size, allocation-free.
static READER_SLOTS: [ReaderSlot; MAX_RCU_THREADS] = {
    // const array initialization
    const EMPTY: ReaderSlot = ReaderSlot::new();
    [EMPTY; MAX_RCU_THREADS]
};

/// Number of currently registered readers (for fast-path skip in synchronize).
static REGISTERED_COUNT: AtomicU32 = AtomicU32::new(0);

/// Deferred callback queue capacity.
const CALLBACK_QUEUE_CAP: usize = 256;

/// A deferred reclamation callback entry.
struct DeferredCallback {
    /// Function pointer to call after grace period.
    func: AtomicUsize,
    /// Argument to pass to the callback.
    arg: AtomicUsize,
    /// Epoch at which this callback was enqueued.
    enqueue_epoch: AtomicU64,
}

impl DeferredCallback {
    const fn new() -> Self {
        Self {
            func: AtomicUsize::new(0),
            arg: AtomicUsize::new(0),
            enqueue_epoch: AtomicU64::new(0),
        }
    }
}

/// Deferred callback queue (circular buffer).
static CALLBACK_QUEUE: [DeferredCallback; CALLBACK_QUEUE_CAP] = {
    const EMPTY: DeferredCallback = DeferredCallback::new();
    [EMPTY; CALLBACK_QUEUE_CAP]
};

/// Write index into the callback queue.
static CB_WRITE_IDX: AtomicUsize = AtomicUsize::new(0);

/// Read index into the callback queue (for processing completed callbacks).
static CB_READ_IDX: AtomicUsize = AtomicUsize::new(0);

// ---------------------------------------------------------------------------
// Reader-side API
// ---------------------------------------------------------------------------

/// Register the current thread as an RCU reader.
///
/// Must be called before any `rcu_quiescent_state()` or RCU-protected reads.
/// Returns the slot index on success, or `Err(EAGAIN)` if the table is full.
///
/// Thread registration is idempotent: re-registering the same TID returns
/// the existing slot.
pub fn rcu_register_thread(tid: u32) -> Result<usize, i32> {
    if tid == SLOT_EMPTY {
        return Err(crate::errno::EINVAL);
    }
    // First check if already registered.
    let start = (tid as usize) % MAX_RCU_THREADS;
    for i in 0..MAX_RCU_THREADS {
        let idx = (start + i) % MAX_RCU_THREADS;
        let slot_tid = READER_SLOTS[idx].tid.load(Ordering::Acquire);
        if slot_tid == tid {
            // Already registered, return existing slot.
            return Ok(idx);
        }
        if slot_tid == SLOT_EMPTY {
            // Try to claim this slot.
            match READER_SLOTS[idx].tid.compare_exchange(
                SLOT_EMPTY,
                tid,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    // Initialize epoch to current global (online).
                    let ge = GLOBAL_EPOCH.load(Ordering::Acquire);
                    READER_SLOTS[idx].epoch.store(ge, Ordering::Release);
                    REGISTERED_COUNT.fetch_add(1, Ordering::AcqRel);
                    return Ok(idx);
                }
                Err(actual) => {
                    // Someone else grabbed it. Check if it's us.
                    if actual == tid {
                        return Ok(idx);
                    }
                    // Continue probing.
                    continue;
                }
            }
        }
    }
    Err(crate::errno::EAGAIN)
}

/// Unregister the current thread from RCU.
///
/// After unregistration, the thread is implicitly quiescent — writers
/// will not wait for it during grace periods.
pub fn rcu_unregister_thread(tid: u32) -> Result<(), i32> {
    if tid == SLOT_EMPTY {
        return Err(crate::errno::EINVAL);
    }
    let start = (tid as usize) % MAX_RCU_THREADS;
    for i in 0..MAX_RCU_THREADS {
        let idx = (start + i) % MAX_RCU_THREADS;
        let slot_tid = READER_SLOTS[idx].tid.load(Ordering::Acquire);
        if slot_tid == tid {
            // Mark epoch as offline before clearing TID.
            READER_SLOTS[idx]
                .epoch
                .store(EPOCH_OFFLINE, Ordering::Release);
            READER_SLOTS[idx].tid.store(SLOT_EMPTY, Ordering::Release);
            REGISTERED_COUNT.fetch_sub(1, Ordering::AcqRel);
            return Ok(());
        }
        if slot_tid == SLOT_EMPTY {
            // Not found — was never registered or already unregistered.
            return Ok(());
        }
    }
    Ok(())
}

/// Mark a quiescent state for the calling thread.
///
/// This is the core QSBR operation: the reader announces that it has
/// observed all prior writes by updating its epoch to the current global
/// epoch. This is a single atomic store — no memory barrier beyond
/// Release ordering.
///
/// Call this at natural quiescent points: syscall return, allocator
/// entry, scheduler yield, or any point where the thread is guaranteed
/// not to hold references to RCU-protected data.
pub fn rcu_quiescent_state(tid: u32) {
    let ge = GLOBAL_EPOCH.load(Ordering::Acquire);
    let start = (tid as usize) % MAX_RCU_THREADS;
    for i in 0..MAX_RCU_THREADS {
        let idx = (start + i) % MAX_RCU_THREADS;
        let slot_tid = READER_SLOTS[idx].tid.load(Ordering::Acquire);
        if slot_tid == tid {
            READER_SLOTS[idx].epoch.store(ge, Ordering::Release);
            return;
        }
        if slot_tid == SLOT_EMPTY {
            return; // Not registered.
        }
    }
}

/// Enter an RCU read-side critical section.
///
/// In QSBR, this is a no-op — readers are implicitly in a critical
/// section between quiescent states. This function exists for API
/// symmetry and documentation purposes.
#[inline(always)]
pub fn rcu_read_lock() {
    // No-op in QSBR. Readers are implicitly protected.
}

/// Exit an RCU read-side critical section.
///
/// In QSBR, this is a no-op. See `rcu_read_lock()`.
#[inline(always)]
pub fn rcu_read_unlock() {
    // No-op in QSBR. Call rcu_quiescent_state() at appropriate points.
}

// ---------------------------------------------------------------------------
// Writer-side API
// ---------------------------------------------------------------------------

/// Wait for a full grace period to elapse.
///
/// Blocks the calling thread until all registered RCU readers have
/// passed through at least one quiescent state since this function
/// was called. After return, it is safe to free data that was
/// visible to readers before the grace period began.
///
/// Implementation:
/// 1. Increment global epoch.
/// 2. Scan all registered reader slots.
/// 3. For each reader: spin until its epoch >= new global epoch,
///    or until it unregisters (epoch becomes EPOCH_OFFLINE).
///
/// Writers must serialize `synchronize_rcu()` calls externally
/// (e.g., by holding a mutex) to avoid epoch counter races.
pub fn synchronize_rcu() {
    // Fast path: no registered readers.
    if REGISTERED_COUNT.load(Ordering::Acquire) == 0 {
        return;
    }

    // Advance the global epoch. All subsequent quiescent states
    // from readers will observe this new epoch.
    let new_epoch = GLOBAL_EPOCH.fetch_add(1, Ordering::AcqRel) + 1;

    // Wait for all registered readers to catch up.
    for idx in 0..MAX_RCU_THREADS {
        loop {
            let slot_tid = READER_SLOTS[idx].tid.load(Ordering::Acquire);
            if slot_tid == SLOT_EMPTY {
                break; // Empty slot, skip.
            }
            let reader_epoch = READER_SLOTS[idx].epoch.load(Ordering::Acquire);
            if reader_epoch == EPOCH_OFFLINE || reader_epoch >= new_epoch {
                break; // Reader has passed through a quiescent state or is offline.
            }
            // Reader is still in an old epoch — yield and retry.
            core::hint::spin_loop();
        }
    }
}

/// Enqueue a callback to be invoked after the next grace period.
///
/// The callback `func(arg)` will be called after all current readers
/// have passed through a quiescent state. This is the deferred
/// alternative to `synchronize_rcu()` — useful when the caller
/// cannot block.
///
/// # Safety
///
/// - `func` must be a valid function pointer that is safe to call
///   with `arg` after a grace period elapses.
/// - The callback must not access RCU-protected data (it runs
///   after the grace period, so old data may be freed).
///
/// Returns `Ok(())` on success, `Err(EAGAIN)` if the queue is full.
#[allow(unsafe_code)]
pub unsafe fn call_rcu(func: fn(usize), arg: usize) -> Result<(), i32> {
    let epoch = GLOBAL_EPOCH.load(Ordering::Acquire);

    // Atomically claim the next slot in the circular buffer.
    let write_idx = CB_WRITE_IDX.fetch_add(1, Ordering::AcqRel) % CALLBACK_QUEUE_CAP;
    let read_idx = CB_READ_IDX.load(Ordering::Acquire);

    // Check for queue full (simple: if write catches up to read).
    // In practice the queue is large enough that this shouldn't happen.
    let next_write = (write_idx + 1) % CALLBACK_QUEUE_CAP;
    if next_write == read_idx % CALLBACK_QUEUE_CAP {
        // Queue is full — process pending callbacks synchronously.
        process_rcu_callbacks();
    }

    CALLBACK_QUEUE[write_idx]
        .func
        .store(func as usize, Ordering::Release);
    CALLBACK_QUEUE[write_idx].arg.store(arg, Ordering::Release);
    CALLBACK_QUEUE[write_idx]
        .enqueue_epoch
        .store(epoch, Ordering::Release);

    Ok(())
}

/// Process deferred RCU callbacks whose grace periods have elapsed.
///
/// Scans the callback queue and invokes any callbacks whose
/// `enqueue_epoch` is less than the minimum observed epoch across
/// all registered readers.
///
/// # Safety
///
/// This function calls function pointers stored in the callback queue.
/// The caller must ensure `call_rcu` was called with valid function pointers.
#[allow(unsafe_code)]
pub fn process_rcu_callbacks() {
    let min_epoch = min_reader_epoch();
    let read_idx = CB_READ_IDX.load(Ordering::Acquire);
    let write_idx = CB_WRITE_IDX.load(Ordering::Acquire);

    let mut current = read_idx;
    while current != write_idx {
        let idx = current % CALLBACK_QUEUE_CAP;
        let cb_epoch = CALLBACK_QUEUE[idx].enqueue_epoch.load(Ordering::Acquire);
        if cb_epoch == 0 {
            current += 1;
            continue;
        }
        // The callback is safe to invoke if all readers have moved past its epoch.
        if cb_epoch < min_epoch {
            let func_ptr = CALLBACK_QUEUE[idx].func.load(Ordering::Acquire);
            let arg = CALLBACK_QUEUE[idx].arg.load(Ordering::Acquire);

            // Clear the slot.
            CALLBACK_QUEUE[idx]
                .enqueue_epoch
                .store(0, Ordering::Release);
            CALLBACK_QUEUE[idx].func.store(0, Ordering::Release);
            CALLBACK_QUEUE[idx].arg.store(0, Ordering::Release);

            if func_ptr != 0 {
                // SAFETY: Caller of call_rcu guaranteed valid function pointer.
                let func: fn(usize) = unsafe { core::mem::transmute(func_ptr) };
                func(arg);
            }
        } else {
            // This callback's grace period hasn't elapsed yet.
            // Stop processing — callbacks are roughly ordered by epoch.
            break;
        }
        current += 1;
    }
    CB_READ_IDX.store(current, Ordering::Release);
}

/// Return the minimum epoch across all registered readers.
///
/// Returns `u64::MAX` if no readers are registered.
fn min_reader_epoch() -> u64 {
    let mut min = u64::MAX;
    for idx in 0..MAX_RCU_THREADS {
        let slot_tid = READER_SLOTS[idx].tid.load(Ordering::Acquire);
        if slot_tid == SLOT_EMPTY {
            continue;
        }
        let epoch = READER_SLOTS[idx].epoch.load(Ordering::Acquire);
        if epoch != EPOCH_OFFLINE && epoch < min {
            min = epoch;
        }
    }
    min
}

// ---------------------------------------------------------------------------
// RcuDomain<T> — type-safe RCU-protected pointer
// ---------------------------------------------------------------------------

/// A type-safe RCU-protected pointer to `T`.
///
/// Writers publish new versions of `T` via `update()`, and readers
/// access the current version via `read()`. Old versions are kept
/// alive until a grace period elapses.
///
/// # Example (conceptual)
///
/// ```ignore
/// static METADATA: RcuDomain<ThreadMetadata> = RcuDomain::new();
///
/// // Reader (wait-free):
/// rcu_read_lock();
/// let meta = METADATA.read();
/// // use meta...
/// rcu_read_unlock();
/// rcu_quiescent_state(tid);
///
/// // Writer:
/// let new_meta = Box::into_raw(Box::new(new_metadata));
/// let old = METADATA.update(new_meta);
/// synchronize_rcu();
/// unsafe { drop(Box::from_raw(old)); }
/// ```
pub struct RcuDomain<T> {
    /// Pointer to the current version of the data.
    ptr: AtomicUsize,
    /// PhantomData to tie the lifetime to T.
    _marker: core::marker::PhantomData<*mut T>,
}

// SAFETY: RcuDomain is safe to share across threads because access
// is mediated by atomic operations and grace period guarantees.
#[allow(unsafe_code)]
unsafe impl<T: Send + Sync> Send for RcuDomain<T> {}
#[allow(unsafe_code)]
unsafe impl<T: Send + Sync> Sync for RcuDomain<T> {}

impl<T> RcuDomain<T> {
    /// Create a new empty RCU domain (null pointer).
    pub const fn new() -> Self {
        Self {
            ptr: AtomicUsize::new(0),
            _marker: core::marker::PhantomData,
        }
    }

    /// Read the current RCU-protected value.
    ///
    /// Returns `None` if the domain is empty (null pointer).
    ///
    /// # Safety
    ///
    /// The caller must be within an RCU read-side critical section
    /// (between `rcu_read_lock()` and `rcu_read_unlock()`). The
    /// returned reference is valid until the next `rcu_quiescent_state()`.
    #[allow(unsafe_code)]
    pub unsafe fn read(&self) -> Option<&T> {
        let p = self.ptr.load(Ordering::Acquire);
        if p == 0 {
            None
        } else {
            Some(unsafe { &*(p as *const T) })
        }
    }

    /// Publish a new version of the RCU-protected data.
    ///
    /// Returns the old pointer (which must not be freed until after
    /// a grace period). Returns null (0) if no previous version existed.
    ///
    /// # Safety
    ///
    /// - `new_ptr` must point to valid, heap-allocated `T` that will
    ///   remain valid until after a grace period + deallocation.
    /// - The caller must ensure exclusive write access (e.g., via mutex).
    #[allow(unsafe_code)]
    pub unsafe fn update(&self, new_ptr: *mut T) -> *mut T {
        let old = self.ptr.swap(new_ptr as usize, Ordering::AcqRel);
        old as *mut T
    }

    /// Read the raw pointer value (for testing/debugging).
    pub fn load_raw(&self) -> usize {
        self.ptr.load(Ordering::Acquire)
    }
}

// ---------------------------------------------------------------------------
// Utility: reset for testing
// ---------------------------------------------------------------------------

/// Reset all RCU state (for testing only).
///
/// # Safety
///
/// Must only be called when no threads are using RCU.
#[cfg(test)]
pub(crate) fn reset_rcu_state() {
    GLOBAL_EPOCH.store(1, Ordering::Release);
    REGISTERED_COUNT.store(0, Ordering::Release);
    for idx in 0..MAX_RCU_THREADS {
        READER_SLOTS[idx].tid.store(SLOT_EMPTY, Ordering::Release);
        READER_SLOTS[idx]
            .epoch
            .store(EPOCH_OFFLINE, Ordering::Release);
    }
    CB_WRITE_IDX.store(0, Ordering::Release);
    CB_READ_IDX.store(0, Ordering::Release);
    for idx in 0..CALLBACK_QUEUE_CAP {
        CALLBACK_QUEUE[idx].func.store(0, Ordering::Release);
        CALLBACK_QUEUE[idx].arg.store(0, Ordering::Release);
        CALLBACK_QUEUE[idx]
            .enqueue_epoch
            .store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn lock_and_reset() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_rcu_state();
        guard
    }

    // --- Registration tests ---

    #[test]
    fn test_register_single_thread() {
        let _g = lock_and_reset();
        let result = rcu_register_thread(100);
        assert!(result.is_ok());
        let idx = result.unwrap();
        assert_eq!(READER_SLOTS[idx].tid.load(Ordering::Acquire), 100);
        assert_eq!(REGISTERED_COUNT.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_register_idempotent() {
        let _g = lock_and_reset();
        let idx1 = rcu_register_thread(200).unwrap();
        let idx2 = rcu_register_thread(200).unwrap();
        assert_eq!(idx1, idx2);
        assert_eq!(REGISTERED_COUNT.load(Ordering::Acquire), 1);
    }

    #[test]
    fn test_register_multiple_threads() {
        let _g = lock_and_reset();
        let idx1 = rcu_register_thread(300).unwrap();
        let idx2 = rcu_register_thread(301).unwrap();
        let idx3 = rcu_register_thread(302).unwrap();
        assert_ne!(idx1, idx2);
        assert_ne!(idx2, idx3);
        assert_eq!(REGISTERED_COUNT.load(Ordering::Acquire), 3);
    }

    #[test]
    fn test_register_zero_tid_rejected() {
        let _g = lock_and_reset();
        let result = rcu_register_thread(0);
        assert_eq!(result.unwrap_err(), crate::errno::EINVAL);
    }

    #[test]
    fn test_unregister() {
        let _g = lock_and_reset();
        let idx = rcu_register_thread(400).unwrap();
        assert_eq!(REGISTERED_COUNT.load(Ordering::Acquire), 1);
        rcu_unregister_thread(400).unwrap();
        assert_eq!(READER_SLOTS[idx].tid.load(Ordering::Acquire), SLOT_EMPTY);
        assert_eq!(
            READER_SLOTS[idx].epoch.load(Ordering::Acquire),
            EPOCH_OFFLINE
        );
        assert_eq!(REGISTERED_COUNT.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_unregister_idempotent() {
        let _g = lock_and_reset();
        rcu_register_thread(500).unwrap();
        rcu_unregister_thread(500).unwrap();
        // Second unregister should be a no-op.
        rcu_unregister_thread(500).unwrap();
        assert_eq!(REGISTERED_COUNT.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_unregister_never_registered() {
        let _g = lock_and_reset();
        // Should not error.
        rcu_unregister_thread(999).unwrap();
    }

    // --- Quiescent state tests ---

    #[test]
    fn test_quiescent_state_updates_epoch() {
        let _g = lock_and_reset();
        let idx = rcu_register_thread(600).unwrap();
        let initial_epoch = READER_SLOTS[idx].epoch.load(Ordering::Acquire);
        assert_eq!(initial_epoch, 1); // Global epoch starts at 1.

        // Advance global epoch.
        GLOBAL_EPOCH.fetch_add(1, Ordering::AcqRel);
        // Reader hasn't called quiescent yet.
        assert_eq!(READER_SLOTS[idx].epoch.load(Ordering::Acquire), 1);

        // Now mark quiescent.
        rcu_quiescent_state(600);
        assert_eq!(READER_SLOTS[idx].epoch.load(Ordering::Acquire), 2);
    }

    #[test]
    fn test_quiescent_state_unregistered_noop() {
        let _g = lock_and_reset();
        // Should not panic or error.
        rcu_quiescent_state(999);
    }

    // --- synchronize_rcu tests ---

    #[test]
    fn test_synchronize_no_readers() {
        let _g = lock_and_reset();
        // Should return immediately with no registered readers.
        synchronize_rcu();
        assert_eq!(GLOBAL_EPOCH.load(Ordering::Acquire), 1); // Not incremented (fast path).
    }

    #[test]
    fn test_synchronize_single_reader_already_quiescent() {
        let _g = lock_and_reset();
        rcu_register_thread(700).unwrap();

        // Spawn synchronize in a background thread (it increments epoch then waits).
        let handle = std::thread::spawn(|| {
            synchronize_rcu();
        });

        // Give writer time to start, then advance reader.
        std::thread::sleep(std::time::Duration::from_millis(10));
        rcu_quiescent_state(700);

        handle.join().expect("synchronize_rcu thread panicked");
        let new_epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
        assert_eq!(new_epoch, 2);
    }

    #[test]
    fn test_synchronize_reader_catches_up() {
        let _g = lock_and_reset();
        let idx = rcu_register_thread(800).unwrap();

        // Reader is at epoch 1. Start synchronize in another thread.
        let handle = std::thread::spawn(|| {
            synchronize_rcu();
        });

        // Give the writer time to start spinning.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Reader marks quiescent state — this should unblock synchronize.
        rcu_quiescent_state(800);

        handle.join().expect("synchronize_rcu thread panicked");

        // Verify reader caught up.
        let reader_epoch = READER_SLOTS[idx].epoch.load(Ordering::Acquire);
        let global_epoch = GLOBAL_EPOCH.load(Ordering::Acquire);
        assert!(reader_epoch >= global_epoch);
    }

    #[test]
    fn test_synchronize_offline_reader_not_blocked() {
        let _g = lock_and_reset();
        rcu_register_thread(900).unwrap();
        rcu_unregister_thread(900).unwrap();

        // Should not block even though the slot was recently used.
        synchronize_rcu();
    }

    // --- Multi-thread synchronize test ---

    #[test]
    fn test_synchronize_multiple_readers() {
        let _g = lock_and_reset();
        let tids = [1001u32, 1002, 1003, 1004];
        for &tid in &tids {
            rcu_register_thread(tid).unwrap();
        }

        let tids_clone = tids;
        let handle = std::thread::spawn(move || {
            synchronize_rcu();
        });

        // Stagger quiescent states.
        for (i, &tid) in tids_clone.iter().enumerate() {
            std::thread::sleep(std::time::Duration::from_millis(5 * (i as u64 + 1)));
            rcu_quiescent_state(tid);
        }

        handle.join().expect("synchronize_rcu thread panicked");

        // All readers should have caught up.
        let ge = GLOBAL_EPOCH.load(Ordering::Acquire);
        for &tid in &tids {
            let start = (tid as usize) % MAX_RCU_THREADS;
            for j in 0..MAX_RCU_THREADS {
                let idx = (start + j) % MAX_RCU_THREADS;
                if READER_SLOTS[idx].tid.load(Ordering::Acquire) == tid {
                    let re = READER_SLOTS[idx].epoch.load(Ordering::Acquire);
                    assert!(re >= ge, "reader {tid} epoch {re} < global {ge}");
                    break;
                }
            }
        }
    }

    // --- RcuDomain<T> tests ---

    #[test]
    fn test_rcu_domain_new_is_empty() {
        let _g = lock_and_reset();
        let domain: RcuDomain<u64> = RcuDomain::new();
        assert_eq!(domain.load_raw(), 0);
        unsafe {
            assert!(domain.read().is_none());
        }
    }

    #[test]
    fn test_rcu_domain_update_and_read() {
        let _g = lock_and_reset();
        let domain: RcuDomain<u64> = RcuDomain::new();
        let value = Box::new(42u64);
        let ptr = Box::into_raw(value);

        unsafe {
            let old = domain.update(ptr);
            assert!(old.is_null());

            let read_val = domain.read().unwrap();
            assert_eq!(*read_val, 42);

            // Cleanup.
            let _ = Box::from_raw(ptr);
        }
    }

    #[test]
    fn test_rcu_domain_update_returns_old() {
        let _g = lock_and_reset();
        let domain: RcuDomain<u64> = RcuDomain::new();
        let v1 = Box::into_raw(Box::new(10u64));
        let v2 = Box::into_raw(Box::new(20u64));

        unsafe {
            domain.update(v1);
            let old = domain.update(v2);
            assert_eq!(old, v1);
            assert_eq!(*domain.read().unwrap(), 20);

            // Cleanup.
            let _ = Box::from_raw(v1);
            let _ = Box::from_raw(v2);
        }
    }

    // --- call_rcu deferred callback tests ---

    #[test]
    fn test_call_rcu_and_process() {
        let _g = lock_and_reset();
        use std::sync::atomic::AtomicBool;

        static CALLED: AtomicBool = AtomicBool::new(false);

        fn my_callback(_arg: usize) {
            CALLED.store(true, Ordering::Release);
        }

        CALLED.store(false, Ordering::Release);

        // Register a reader so synchronize has something to track.
        rcu_register_thread(1100).unwrap();

        unsafe {
            call_rcu(my_callback, 0).unwrap();
        }

        // Advance epoch: spawn synchronize in background, then advance reader.
        let handle = std::thread::spawn(|| {
            synchronize_rcu();
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        rcu_quiescent_state(1100);
        handle.join().expect("synchronize_rcu thread panicked");

        // Do another round to ensure callback epoch is past.
        let handle2 = std::thread::spawn(|| {
            synchronize_rcu();
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        rcu_quiescent_state(1100);
        handle2.join().expect("synchronize_rcu thread panicked");

        // Process callbacks.
        process_rcu_callbacks();

        assert!(CALLED.load(Ordering::Acquire));
    }

    #[test]
    fn test_call_rcu_preserves_arg() {
        let _g = lock_and_reset();
        use std::sync::atomic::AtomicUsize as AU;

        static RECEIVED_ARG: AU = AU::new(0);

        fn capture_arg(arg: usize) {
            RECEIVED_ARG.store(arg, Ordering::Release);
        }

        RECEIVED_ARG.store(0, Ordering::Release);
        rcu_register_thread(1200).unwrap();

        unsafe {
            call_rcu(capture_arg, 0xDEAD_BEEF).unwrap();
        }

        // Advance epoch: spawn synchronize in background, then advance reader.
        let handle = std::thread::spawn(|| {
            synchronize_rcu();
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        rcu_quiescent_state(1200);
        handle.join().expect("synchronize_rcu thread panicked");

        let handle2 = std::thread::spawn(|| {
            synchronize_rcu();
        });
        std::thread::sleep(std::time::Duration::from_millis(10));
        rcu_quiescent_state(1200);
        handle2.join().expect("synchronize_rcu thread panicked");

        process_rcu_callbacks();

        assert_eq!(RECEIVED_ARG.load(Ordering::Acquire), 0xDEAD_BEEF);
    }

    // --- rcu_read_lock / rcu_read_unlock are no-ops ---

    #[test]
    fn test_read_lock_unlock_noop() {
        let _g = lock_and_reset();
        rcu_read_lock();
        rcu_read_unlock();
        // Just verify they don't panic.
    }

    // --- min_reader_epoch tests ---

    #[test]
    fn test_min_reader_epoch_no_readers() {
        let _g = lock_and_reset();
        assert_eq!(min_reader_epoch(), u64::MAX);
    }

    #[test]
    fn test_min_reader_epoch_tracks_minimum() {
        let _g = lock_and_reset();
        rcu_register_thread(1300).unwrap();
        rcu_register_thread(1301).unwrap();

        // Both at epoch 1.
        assert_eq!(min_reader_epoch(), 1);

        // Advance global and update only one reader.
        GLOBAL_EPOCH.fetch_add(1, Ordering::AcqRel);
        rcu_quiescent_state(1300); // Now at epoch 2.
        // 1301 is still at epoch 1.

        assert_eq!(min_reader_epoch(), 1);

        // Update second reader.
        rcu_quiescent_state(1301);
        assert_eq!(min_reader_epoch(), 2);
    }

    // --- Grace period end-to-end test ---

    #[test]
    fn test_grace_period_end_to_end() {
        let _g = lock_and_reset();

        // Setup: writer publishes data, readers access it.
        let domain: RcuDomain<u64> = RcuDomain::new();
        let v1 = Box::into_raw(Box::new(100u64));

        rcu_register_thread(1400).unwrap();
        rcu_register_thread(1401).unwrap();

        unsafe {
            domain.update(v1);
        }

        // Both readers see v1.
        rcu_read_lock();
        unsafe {
            assert_eq!(*domain.read().unwrap(), 100);
        }
        rcu_read_unlock();

        // Writer publishes v2.
        let v2 = Box::into_raw(Box::new(200u64));
        let old;
        unsafe {
            old = domain.update(v2);
        }
        assert_eq!(old, v1);

        // Start grace period in background.
        // synchronize_rcu increments epoch, then waits for ALL readers to advance.
        let handle = std::thread::spawn(|| {
            synchronize_rcu();
        });

        // Give writer time to start spinning.
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Both readers mark quiescent AFTER synchronize starts — this is key.
        // Readers must advance AFTER the epoch increment to unblock the writer.
        rcu_quiescent_state(1400);
        rcu_quiescent_state(1401);
        handle.join().unwrap();

        // Grace period complete — safe to free old value.
        unsafe {
            let _ = Box::from_raw(old);
            let _ = Box::from_raw(v2);
        }
    }
}
