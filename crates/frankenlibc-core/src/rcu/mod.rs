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

use core::hint::spin_loop;
use core::marker::PhantomData;
use core::mem::{MaybeUninit, size_of};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering, fence};

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
const SEQLOCK_MAX_BYTES: usize = 64;
const SEQLOCK_LANE_BYTES: usize = 8;
const SEQLOCK_LANES: usize = SEQLOCK_MAX_BYTES / SEQLOCK_LANE_BYTES;

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
#[allow(clippy::declare_interior_mutable_const)]
static READER_SLOTS: [ReaderSlot; MAX_RCU_THREADS] = {
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
#[allow(clippy::declare_interior_mutable_const)]
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
    for slot in &READER_SLOTS {
        loop {
            let slot_tid = slot.tid.load(Ordering::Acquire);
            if slot_tid == SLOT_EMPTY {
                break; // Empty slot, skip.
            }
            let reader_epoch = slot.epoch.load(Ordering::Acquire);
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
    for slot in &READER_SLOTS {
        let slot_tid = slot.tid.load(Ordering::Acquire);
        if slot_tid == SLOT_EMPTY {
            continue;
        }
        let epoch = slot.epoch.load(Ordering::Acquire);
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

impl<T> Default for RcuDomain<T> {
    fn default() -> Self {
        Self::new()
    }
}

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
// RcuMigration<T> — shadow-mode migration helper
// ---------------------------------------------------------------------------

/// Active rollout phase for an [`RcuMigration`] wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationPhase {
    /// Read from both legacy mutex and RCU paths, compare results, and return
    /// the RCU value as primary output.
    Shadow = 0,
    /// Read from the RCU path only.
    RcuPrimary = 1,
    /// Read from the legacy mutex path only.
    MutexPrimary = 2,
}

impl MigrationPhase {
    fn from_u8(raw: u8) -> Self {
        match raw {
            1 => Self::RcuPrimary,
            2 => Self::MutexPrimary,
            _ => Self::Shadow,
        }
    }
}

/// Result from a migration wrapper read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationRead<T> {
    /// Primary value returned by the active phase.
    pub value: T,
    /// Shadow-path value, when dual-read comparison is enabled.
    pub shadow_value: Option<T>,
    /// Whether primary and shadow values matched (when shadow was computed).
    pub matched: bool,
}

/// Generic wrapper for lock-to-RCU migrations.
///
/// The wrapper keeps a legacy mutex-protected copy and an RCU-published copy of
/// the same payload. In `Shadow` phase it compares both read paths and tracks
/// mismatches; this supports deterministic rollout before removing the mutex
/// path entirely.
///
/// Memory-management policy:
/// - `update()` publishes a freshly boxed clone to RCU.
/// - previous RCU versions are reclaimed after `synchronize_rcu()`.
pub struct RcuMigration<T: Clone + PartialEq + Send + Sync + 'static> {
    legacy: std::sync::Mutex<T>,
    rcu: RcuDomain<T>,
    phase: core::sync::atomic::AtomicU8,
    mismatch_count: AtomicU64,
}

impl<T: Clone + PartialEq + Send + Sync + 'static> RcuMigration<T> {
    /// Create a new migration wrapper with synchronized legacy/RCU state.
    pub fn new(initial: T) -> Self {
        let rcu = RcuDomain::new();
        let ptr = Box::into_raw(Box::new(initial.clone()));
        // SAFETY: `ptr` comes from Box and remains valid until explicitly reclaimed.
        unsafe {
            let _ = rcu.update(ptr);
        }
        Self {
            legacy: std::sync::Mutex::new(initial),
            rcu,
            phase: core::sync::atomic::AtomicU8::new(MigrationPhase::Shadow as u8),
            mismatch_count: AtomicU64::new(0),
        }
    }

    /// Return the current rollout phase.
    pub fn phase(&self) -> MigrationPhase {
        MigrationPhase::from_u8(self.phase.load(Ordering::Acquire))
    }

    /// Set the active rollout phase.
    pub fn set_phase(&self, phase: MigrationPhase) {
        self.phase.store(phase as u8, Ordering::Release);
    }

    /// Number of observed shadow mismatches.
    pub fn mismatch_count(&self) -> u64 {
        self.mismatch_count.load(Ordering::Acquire)
    }

    /// Read according to the active phase.
    ///
    /// `tid` should be the current thread id when available. It is used to
    /// register the reader with QSBR and to mark a quiescent state after the
    /// read-side critical section.
    pub fn read(&self, tid: u32) -> MigrationRead<T> {
        match self.phase() {
            MigrationPhase::Shadow => self.read_shadow(tid),
            MigrationPhase::RcuPrimary => {
                let rcu_value = self.read_rcu(tid);
                MigrationRead {
                    value: rcu_value,
                    shadow_value: None,
                    matched: true,
                }
            }
            MigrationPhase::MutexPrimary => {
                let legacy_value = self.read_legacy();
                MigrationRead {
                    value: legacy_value,
                    shadow_value: None,
                    matched: true,
                }
            }
        }
    }

    /// Publish an updated value to both legacy and RCU paths.
    pub fn update<F>(&self, mutate: F)
    where
        F: FnOnce(&mut T),
    {
        self.update_with_result(|value| {
            mutate(value);
        });
    }

    /// Publish an updated value to both legacy and RCU paths while returning
    /// an application-defined result from the mutation closure.
    pub fn update_with_result<F, R>(&self, mutate: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let next_value = {
            let mut guard = match self.legacy.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let result = mutate(&mut guard);
            let next = guard.clone();
            (next, result)
        };
        let (next_value, result) = next_value;

        let next_ptr = Box::into_raw(Box::new(next_value));
        // SAFETY: `next_ptr` comes from Box and the old pointer is reclaimed only
        // after a grace period below.
        let old_ptr = unsafe { self.rcu.update(next_ptr) };
        if !old_ptr.is_null() {
            synchronize_rcu();
            // SAFETY: grace period has elapsed, so old readers cannot hold `old_ptr`.
            unsafe {
                let _ = Box::from_raw(old_ptr);
            }
        }
        result
    }

    /// Read both paths and compare.
    pub fn read_shadow(&self, tid: u32) -> MigrationRead<T> {
        let rcu_value = self.read_rcu(tid);
        let legacy_value = self.read_legacy();
        let matched = rcu_value == legacy_value;
        if !matched {
            self.mismatch_count.fetch_add(1, Ordering::AcqRel);
        }
        MigrationRead {
            value: rcu_value,
            shadow_value: Some(legacy_value),
            matched,
        }
    }

    fn read_legacy(&self) -> T {
        match self.legacy.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn read_rcu(&self, tid: u32) -> T {
        if tid != 0 {
            let _ = rcu_register_thread(tid);
        }
        rcu_read_lock();
        // SAFETY: protected by read-side section above.
        let value = unsafe {
            self.rcu
                .read()
                .expect("RcuMigration RCU domain must always contain a value")
                .clone()
        };
        rcu_read_unlock();
        if tid != 0 {
            rcu_quiescent_state(tid);
        }
        value
    }
}

impl<T: Clone + PartialEq + Send + Sync + 'static> Drop for RcuMigration<T> {
    fn drop(&mut self) {
        let raw = self.rcu.ptr.swap(0, Ordering::AcqRel);
        if raw != 0 {
            // SAFETY: `drop` requires exclusive access to `self`; callers must ensure
            // no concurrent readers outlive this wrapper.
            unsafe {
                let _ = Box::from_raw(raw as *mut T);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SeqLock<T> — lock-free readers for small configuration payloads
// ---------------------------------------------------------------------------

/// Sequence-lock for read-heavy configuration data.
///
/// Design goals:
/// - Readers are lock-free and wait-free when no concurrent writer is active.
/// - Writers serialize with a monotone sequence counter.
/// - Payload storage is split across atomic `u64` lanes to avoid torn reads and
///   undefined behavior from racy non-atomic loads/stores.
///
/// Constraints:
/// - `T` must be `Copy`.
/// - `size_of::<T>() <= 64` bytes.
#[repr(C)]
pub struct SeqLock<T: Copy> {
    sequence: AtomicU64,
    lanes: [AtomicU64; SEQLOCK_LANES],
    _marker: PhantomData<T>,
}

// SAFETY: all shared state is atomically accessed.
#[allow(unsafe_code)]
unsafe impl<T: Copy + Send> Send for SeqLock<T> {}
#[allow(unsafe_code)]
unsafe impl<T: Copy + Send + Sync> Sync for SeqLock<T> {}

impl<T: Copy> SeqLock<T> {
    /// Create a seqlock initialized with `initial`.
    #[must_use]
    pub fn new(initial: T) -> Self {
        assert!(
            size_of::<T>() <= SEQLOCK_MAX_BYTES,
            "SeqLock payload exceeds {} bytes (got {})",
            SEQLOCK_MAX_BYTES,
            size_of::<T>()
        );

        let this = Self {
            sequence: AtomicU64::new(0),
            lanes: std::array::from_fn(|_| AtomicU64::new(0)),
            _marker: PhantomData,
        };
        this.store_lanes(Self::encode(initial));
        this
    }

    /// Read a stable snapshot, retrying until the sequence is consistent.
    #[must_use]
    pub fn read(&self) -> T {
        self.read_with_retries().0
    }

    /// Read a stable snapshot and return retry count for observability/testing.
    #[must_use]
    pub fn read_with_retries(&self) -> (T, u32) {
        let mut retries = 0u32;
        loop {
            let before = self.sequence.load(Ordering::Acquire);
            if before & 1 == 1 {
                retries = retries.saturating_add(1);
                spin_loop();
                continue;
            }

            let lanes = self.load_lanes();
            fence(Ordering::Acquire);
            let after = self.sequence.load(Ordering::Acquire);
            if before == after && (after & 1) == 0 {
                return (Self::decode(lanes), retries);
            }

            retries = retries.saturating_add(1);
            spin_loop();
        }
    }

    /// Publish an entire new value.
    pub fn write(&self, value: T) {
        let writer_seq = self.begin_write();
        self.store_lanes(Self::encode(value));
        self.end_write(writer_seq);
    }

    /// Update the current value in-place under the writer sequence gate.
    pub fn update<F>(&self, mutate: F)
    where
        F: FnOnce(&mut T),
    {
        let writer_seq = self.begin_write();
        let mut value = Self::decode(self.load_lanes());
        mutate(&mut value);
        self.store_lanes(Self::encode(value));
        self.end_write(writer_seq);
    }

    #[must_use]
    pub fn sequence(&self) -> u64 {
        self.sequence.load(Ordering::Acquire)
    }

    fn begin_write(&self) -> u64 {
        loop {
            let current = self.sequence.load(Ordering::Acquire);
            if current & 1 == 1 {
                spin_loop();
                continue;
            }
            match self.sequence.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return current + 1,
                Err(_) => spin_loop(),
            }
        }
    }

    fn end_write(&self, writer_seq: u64) {
        fence(Ordering::Release);
        self.sequence.store(writer_seq + 1, Ordering::Release);
    }

    fn load_lanes(&self) -> [u64; SEQLOCK_LANES] {
        let mut lanes = [0u64; SEQLOCK_LANES];
        for (idx, slot) in self.lanes.iter().enumerate() {
            lanes[idx] = slot.load(Ordering::Relaxed);
        }
        lanes
    }

    fn store_lanes(&self, lanes: [u64; SEQLOCK_LANES]) {
        for (slot, lane) in self.lanes.iter().zip(lanes.into_iter()) {
            slot.store(lane, Ordering::Relaxed);
        }
    }

    fn encode(value: T) -> [u64; SEQLOCK_LANES] {
        let mut bytes = [0u8; SEQLOCK_MAX_BYTES];
        // SAFETY: `value` is valid for `size_of::<T>()` bytes.
        #[allow(unsafe_code)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                (&value as *const T).cast::<u8>(),
                bytes.as_mut_ptr(),
                size_of::<T>(),
            );
        }

        let mut lanes = [0u64; SEQLOCK_LANES];
        let mut idx = 0;
        while idx < SEQLOCK_LANES {
            let offset = idx * SEQLOCK_LANE_BYTES;
            let mut lane = [0u8; SEQLOCK_LANE_BYTES];
            lane.copy_from_slice(&bytes[offset..offset + SEQLOCK_LANE_BYTES]);
            lanes[idx] = u64::from_ne_bytes(lane);
            idx += 1;
        }
        lanes
    }

    fn decode(lanes: [u64; SEQLOCK_LANES]) -> T {
        let mut bytes = [0u8; SEQLOCK_MAX_BYTES];
        let mut idx = 0;
        while idx < SEQLOCK_LANES {
            let offset = idx * SEQLOCK_LANE_BYTES;
            bytes[offset..offset + SEQLOCK_LANE_BYTES].copy_from_slice(&lanes[idx].to_ne_bytes());
            idx += 1;
        }

        let mut value = MaybeUninit::<T>::uninit();
        // SAFETY: we copy exactly `size_of::<T>()` bytes from initialized buffer.
        #[allow(unsafe_code)]
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                value.as_mut_ptr().cast::<u8>(),
                size_of::<T>(),
            );
            value.assume_init()
        }
    }
}

impl<T: Copy + Default> Default for SeqLock<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

// ---------------------------------------------------------------------------
// Utility: reset for testing
// ---------------------------------------------------------------------------

/// Shared lock used by test modules that mutate global RCU state.
#[cfg(test)]
pub(crate) fn rcu_test_global_lock() -> &'static std::sync::Mutex<()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Reset all RCU state (for testing only).
///
/// # Safety
///
/// Must only be called when no threads are using RCU.
#[cfg(test)]
pub(crate) fn reset_rcu_state() {
    GLOBAL_EPOCH.store(1, Ordering::Release);
    REGISTERED_COUNT.store(0, Ordering::Release);
    for slot in READER_SLOTS.iter().take(MAX_RCU_THREADS) {
        slot.tid.store(SLOT_EMPTY, Ordering::Release);
        slot.epoch.store(EPOCH_OFFLINE, Ordering::Release);
    }
    CB_WRITE_IDX.store(0, Ordering::Release);
    CB_READ_IDX.store(0, Ordering::Release);
    for callback in CALLBACK_QUEUE.iter().take(CALLBACK_QUEUE_CAP) {
        callback.func.store(0, Ordering::Release);
        callback.arg.store(0, Ordering::Release);
        callback.enqueue_epoch.store(0, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn lock_and_reset() -> std::sync::MutexGuard<'static, ()> {
        let guard = rcu_test_global_lock()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
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

    // --- SeqLock tests ---

    #[repr(C)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct PairChecksum {
        a: u64,
        b: u64,
        checksum: u64,
    }

    impl PairChecksum {
        fn new(a: u64, b: u64) -> Self {
            Self {
                a,
                b,
                checksum: a ^ b,
            }
        }

        fn is_consistent(self) -> bool {
            self.checksum == (self.a ^ self.b)
        }
    }

    #[test]
    fn test_seqlock_roundtrip_u64() {
        let lock = SeqLock::new(11u64);
        assert_eq!(lock.read(), 11);
        lock.write(42);
        assert_eq!(lock.read(), 42);
        assert_eq!(lock.sequence() & 1, 0);
    }

    #[test]
    fn test_seqlock_update_composes() {
        let lock = SeqLock::new(PairChecksum::new(2, 9));
        lock.update(|value| {
            value.a = value.a.saturating_add(10);
            value.b = value.b.saturating_add(5);
            value.checksum = value.a ^ value.b;
        });

        let snapshot = lock.read();
        assert_eq!(snapshot, PairChecksum::new(12, 14));
        assert!(snapshot.is_consistent());
    }

    #[test]
    fn test_seqlock_rejects_payloads_over_64_bytes() {
        let result = std::panic::catch_unwind(|| {
            let _ = SeqLock::new([0u8; 65]);
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_seqlock_concurrent_reads_never_observe_torn_checksum() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let lock = Arc::new(SeqLock::new(PairChecksum::new(0, 0)));
        let running = Arc::new(AtomicBool::new(true));

        let writer_lock = Arc::clone(&lock);
        let writer_running = Arc::clone(&running);
        let writer = std::thread::spawn(move || {
            for i in 1..=50_000u64 {
                writer_lock.write(PairChecksum::new(i, i.rotate_left(7)));
            }
            writer_running.store(false, AtomicOrdering::Release);
        });

        let mut readers = Vec::new();
        for _ in 0..4 {
            let reader_lock = Arc::clone(&lock);
            let reader_running = Arc::clone(&running);
            readers.push(std::thread::spawn(move || {
                while reader_running.load(AtomicOrdering::Acquire) {
                    let snapshot = reader_lock.read();
                    assert!(snapshot.is_consistent(), "torn read detected: {snapshot:?}");
                }
                // Final read after writer completion.
                assert!(reader_lock.read().is_consistent());
            }));
        }

        writer.join().expect("writer thread panicked");
        for handle in readers {
            handle.join().expect("reader thread panicked");
        }
    }

    // --- RcuMigration<T> tests ---

    #[test]
    fn test_rcu_migration_shadow_reads_match_initial_value() {
        let _g = lock_and_reset();
        let migration = RcuMigration::new(7u64);
        let read = migration.read_shadow(1500);
        assert_eq!(read.value, 7);
        assert_eq!(read.shadow_value, Some(7));
        assert!(read.matched);
        assert_eq!(migration.mismatch_count(), 0);
    }

    #[test]
    fn test_rcu_migration_update_keeps_paths_in_sync() {
        let _g = lock_and_reset();
        let migration = RcuMigration::new(11u64);
        migration.update(|value| *value = value.saturating_add(9));

        let shadow = migration.read_shadow(1501);
        assert_eq!(shadow.value, 20);
        assert_eq!(shadow.shadow_value, Some(20));
        assert!(shadow.matched);

        migration.set_phase(MigrationPhase::MutexPrimary);
        let mutex_read = migration.read(1501);
        assert_eq!(mutex_read.value, 20);
        assert!(mutex_read.shadow_value.is_none());
        assert!(mutex_read.matched);

        migration.set_phase(MigrationPhase::RcuPrimary);
        let rcu_read = migration.read(1501);
        assert_eq!(rcu_read.value, 20);
        assert!(rcu_read.shadow_value.is_none());
        assert!(rcu_read.matched);
    }

    #[test]
    fn test_rcu_migration_detects_shadow_mismatch() {
        let _g = lock_and_reset();
        let migration = RcuMigration::new(1u64);
        {
            let mut legacy = migration.legacy.lock().unwrap_or_else(|e| e.into_inner());
            *legacy = 2;
        }

        let read = migration.read_shadow(1502);
        assert_eq!(read.value, 1);
        assert_eq!(read.shadow_value, Some(2));
        assert!(!read.matched);
        assert_eq!(migration.mismatch_count(), 1);
    }

    #[test]
    fn test_rcu_migration_update_with_result_reports_mutation_outcome() {
        let _g = lock_and_reset();
        let migration = RcuMigration::new(10u64);
        let new_value = migration.update_with_result(|value| {
            *value += 5;
            *value
        });
        assert_eq!(new_value, 15);

        let read = migration.read_shadow(1503);
        assert_eq!(read.value, 15);
        assert_eq!(read.shadow_value, Some(15));
        assert!(read.matched);
    }

    #[test]
    fn test_rcu_migration_shadow_million_reads_without_mismatch() {
        let _g = lock_and_reset();
        let migration = RcuMigration::new(123u64);

        for i in 0..1_000_000u64 {
            if i % 200_000 == 0 && i != 0 {
                migration.update(|value| *value = value.saturating_add(1));
            }
            // Use tid=0 for this stress test to avoid registering a reader slot.
            // The goal here is shadow-path equivalence, not QSBR registration behavior.
            let read = migration.read_shadow(0);
            assert!(read.matched, "shadow mismatch at iteration {i}");
        }

        assert_eq!(migration.mismatch_count(), 0);
    }
}
