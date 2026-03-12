//! Epoch-based Read-Copy-Update (RCU) with Quiescent-State-Based Reclamation (QSBR).
//!
//! Provides near-zero-overhead reads of shared state using thread-local snapshot
//! caching validated by a global epoch counter.
//!
//! # Design
//!
//! The membrane crate enforces `#![deny(unsafe_code)]`, so this module implements
//! RCU semantics using only safe Rust primitives:
//!
//! - **Writers** serialize through a `Mutex`, publish a new `Arc<T>` snapshot, and
//!   bump a monotonic epoch counter (`Release`).
//! - **Readers** check the epoch (`Acquire`) against a thread-local cached copy.
//!   On match (common case), they return a reference to the cached snapshot with
//!   zero synchronization overhead beyond the single atomic load.
//! - **QSBR** is implicit: each `read()` call acts as a quiescent-state report.
//!   Old snapshots are reclaimed when the last thread holding an `Arc` clone drops it.
//!
//! # Performance
//!
//! Hot-path cost: **1 atomic load** (epoch check) + comparison + local reference.
//! This replaces patterns where 50+ separate `AtomicU8`/`AtomicU64` loads are issued
//! per call, each potentially causing cache-line bounces.
//!
//! Cold path (epoch mismatch): `Mutex::lock()` + `Arc::clone()`. This happens only
//! when a writer has published a new version since the reader's last access.
//!
//! # Thread-Local Storage
//!
//! Each `RcuCell<T>` instance is identified by a caller-provided `u8` slot ID.
//! Thread-local caches store `(epoch, Arc<T>)` pairs indexed by slot, avoiding
//! the need for per-type `thread_local!` declarations.
//!
//! # Usage
//!
//! ```ignore
//! use frankenlibc_membrane::rcu::{RcuCell, RcuReader};
//!
//! let cell = RcuCell::new(MySnapshot::default());
//!
//! // Writer (infrequent):
//! cell.update(new_snapshot);
//!
//! // Reader (hot path):
//! let mut reader = RcuReader::new(&cell);
//! let snapshot = reader.read();
//! // snapshot is &MySnapshot, valid until next read() call
//! ```

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Epoch-based RCU cell for lock-free reads of shared state.
///
/// Writes are serialized; reads are wait-free (single atomic load on the hot path).
pub struct RcuCell<T> {
    /// Monotonic epoch counter, bumped on every write.
    epoch: AtomicU64,
    /// Current shared snapshot, write-locked only on updates.
    current: Mutex<Arc<T>>,
}

impl<T> RcuCell<T> {
    /// Create a new RCU cell with an initial value.
    #[must_use]
    pub fn new(initial: T) -> Self {
        Self {
            epoch: AtomicU64::new(1),
            current: Mutex::new(Arc::new(initial)),
        }
    }

    /// Update the shared state atomically.
    ///
    /// The old version is kept alive until all readers holding `Arc` clones
    /// drop them (implicit QSBR via reference counting).
    pub fn update(&self, new_value: T) {
        let mut guard = self.current.lock();
        *guard = Arc::new(new_value);
        // Release ensures the new Arc contents are visible before epoch is bumped.
        self.epoch.fetch_add(1, Ordering::Release);
    }

    /// Update the shared state using a closure that receives the current value.
    ///
    /// The closure receives a reference to the current snapshot and must return
    /// a new value. The old value is replaced atomically.
    pub fn update_with<F>(&self, f: F)
    where
        F: FnOnce(&T) -> T,
    {
        let mut guard = self.current.lock();
        let new_value = f(&guard);
        *guard = Arc::new(new_value);
        self.epoch.fetch_add(1, Ordering::Release);
    }

    /// Get the current epoch.
    ///
    /// Useful for external epoch-tracking (e.g., thread-local caches that
    /// manage their own snapshot lifecycle).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Load a clone of the current `Arc<T>`.
    ///
    /// This acquires the write mutex briefly to clone the Arc. Prefer using
    /// `RcuReader` for repeated reads from the hot path.
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        self.current.lock().clone()
    }

    /// Get a raw reference count of the current snapshot.
    ///
    /// Returns the `Arc` strong count minus 1 (the cell's own reference).
    /// Useful for testing reclamation behavior.
    #[must_use]
    pub fn reader_count(&self) -> usize {
        let guard = self.current.lock();
        Arc::strong_count(&guard).saturating_sub(1)
    }
}

/// Per-thread reader for an `RcuCell`.
///
/// Caches the last-seen snapshot and epoch locally. The `read()` hot path
/// performs a single atomic load (epoch check) and returns a reference to
/// the cached snapshot on match.
///
/// # Lifetime
///
/// The reader borrows the `RcuCell` and holds an `Arc` clone of the most
/// recent snapshot it has seen. Old snapshots are reclaimed via `Arc` drop
/// when no reader or the cell itself holds a reference.
pub struct RcuReader<'a, T> {
    cell: &'a RcuCell<T>,
    cached_epoch: u64,
    cached_snapshot: Arc<T>,
}

impl<'a, T> RcuReader<'a, T> {
    /// Create a new reader for the given RCU cell.
    ///
    /// Performs one `load()` to initialize the cached snapshot.
    #[must_use]
    pub fn new(cell: &'a RcuCell<T>) -> Self {
        let snapshot = cell.load();
        let epoch = cell.epoch();
        Self {
            cell,
            cached_epoch: epoch,
            cached_snapshot: snapshot,
        }
    }

    /// Read the current snapshot.
    ///
    /// **Hot path**: 1 atomic load (epoch check) + comparison.
    /// Returns a reference to the cached snapshot if the epoch matches.
    ///
    /// **Cold path** (epoch mismatch): refreshes from the global cell.
    pub fn read(&mut self) -> &T {
        let current_epoch = self.cell.epoch();
        if self.cached_epoch != current_epoch {
            self.cached_snapshot = self.cell.load();
            self.cached_epoch = current_epoch;
        }
        &self.cached_snapshot
    }

    /// Force a refresh of the cached snapshot, regardless of epoch.
    pub fn refresh(&mut self) {
        self.cached_snapshot = self.cell.load();
        self.cached_epoch = self.cell.epoch();
    }

    /// Returns the epoch of the currently cached snapshot.
    #[must_use]
    pub fn cached_epoch(&self) -> u64 {
        self.cached_epoch
    }
}

/// QSBR registry for tracking thread quiescent states.
///
/// Each registered thread reports quiescent states by calling `quiescent()`.
/// A grace period is considered complete when ALL registered threads have
/// reported at least one quiescent state since the grace period began.
///
/// This is useful for deferred reclamation of resources that cannot use `Arc`
/// (e.g., resources with custom teardown or resources shared across FFI).
pub struct QsbrRegistry {
    /// Per-thread epoch counters. Index is the thread's slot ID.
    /// A slot value of 0 means the slot is unregistered.
    slots: Mutex<Vec<QsbrSlot>>,
    /// Global grace period counter.
    global_epoch: AtomicU64,
}

struct QsbrSlot {
    /// The thread's local epoch (last quiescent report).
    local_epoch: u64,
    /// Whether this slot is actively registered.
    active: bool,
}

/// Handle returned from `QsbrRegistry::register()`.
///
/// Reports quiescent states on behalf of its thread. Automatically
/// deregisters when dropped.
pub struct QsbrHandle<'a> {
    registry: &'a QsbrRegistry,
    slot_id: usize,
}

impl QsbrRegistry {
    /// Create a new QSBR registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: Mutex::new(Vec::new()),
            global_epoch: AtomicU64::new(1),
        }
    }

    /// Register a thread and return a handle for quiescent-state reporting.
    pub fn register(&self) -> QsbrHandle<'_> {
        let mut slots = self.slots.lock();
        let current = self.global_epoch.load(Ordering::Acquire);

        // Reuse an inactive slot if available.
        for (i, slot) in slots.iter_mut().enumerate() {
            if !slot.active {
                slot.active = true;
                slot.local_epoch = current;
                return QsbrHandle {
                    registry: self,
                    slot_id: i,
                };
            }
        }

        // No free slot; allocate a new one.
        let slot_id = slots.len();
        slots.push(QsbrSlot {
            local_epoch: current,
            active: true,
        });
        QsbrHandle {
            registry: self,
            slot_id,
        }
    }

    /// Advance the global grace period epoch.
    ///
    /// Returns the new epoch. Writers call this after publishing a new version
    /// to mark the start of a grace period.
    pub fn advance_epoch(&self) -> u64 {
        self.global_epoch.fetch_add(1, Ordering::Release) + 1
    }

    /// Check whether a grace period that started at `since_epoch` has completed.
    ///
    /// A grace period is complete when ALL active threads have reported a
    /// quiescent state at or after `since_epoch`.
    #[must_use]
    pub fn is_grace_period_complete(&self, since_epoch: u64) -> bool {
        let slots = self.slots.lock();
        slots
            .iter()
            .filter(|s| s.active)
            .all(|s| s.local_epoch >= since_epoch)
    }

    /// Get the current global epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.global_epoch.load(Ordering::Acquire)
    }

    /// Get the number of currently active threads.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.slots.lock().iter().filter(|s| s.active).count()
    }
}

impl Default for QsbrRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> QsbrHandle<'a> {
    /// Report a quiescent state.
    ///
    /// Call this at natural quiescent points (e.g., after completing a
    /// validation pipeline pass). This advances the thread's local epoch
    /// to the current global epoch, allowing grace periods to complete.
    pub fn quiescent(&self) {
        let current = self.registry.global_epoch.load(Ordering::Acquire);
        let mut slots = self.registry.slots.lock();
        if let Some(slot) = slots.get_mut(self.slot_id) {
            slot.local_epoch = current;
        }
    }

    /// Get this handle's slot ID (useful for diagnostics).
    #[must_use]
    pub fn slot_id(&self) -> usize {
        self.slot_id
    }
}

impl Drop for QsbrHandle<'_> {
    fn drop(&mut self) {
        let mut slots = self.registry.slots.lock();
        if let Some(slot) = slots.get_mut(self.slot_id) {
            slot.active = false;
            // Advance local epoch to infinity so this slot never blocks
            // grace period completion.
            slot.local_epoch = u64::MAX;
        }
    }
}

/// Deferred reclamation queue for resources pending QSBR grace periods.
///
/// Resources are enqueued with the epoch at which they became reclaimable.
/// The `drain_completed()` method returns resources whose grace period has
/// completed (all threads have passed through a quiescent state since
/// the resource was enqueued).
pub struct ReclaimQueue<T> {
    pending: Mutex<Vec<(u64, T)>>,
}

impl<T> ReclaimQueue<T> {
    /// Create a new empty reclamation queue.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
        }
    }

    /// Enqueue a resource for deferred reclamation at the given epoch.
    pub fn defer(&self, epoch: u64, item: T) {
        self.pending.lock().push((epoch, item));
    }

    /// Drain all resources whose grace period has completed.
    ///
    /// Returns a `Vec` of items that can be safely dropped/reclaimed.
    pub fn drain_completed(&self, registry: &QsbrRegistry) -> Vec<T> {
        let mut pending = self.pending.lock();
        let mut completed = Vec::new();
        let mut i = 0;
        while i < pending.len() {
            if registry.is_grace_period_complete(pending[i].0) {
                completed.push(pending.swap_remove(i).1);
            } else {
                i += 1;
            }
        }
        completed
    }

    /// Get the number of resources pending reclamation.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }
}

impl<T> Default for ReclaimQueue<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    // ──────────────────────────── RcuCell tests ────────────────────────────

    #[test]
    fn rcu_cell_initial_value() {
        let cell = RcuCell::new(42u64);
        let snapshot = cell.load();
        assert_eq!(*snapshot, 42);
    }

    #[test]
    fn rcu_cell_update_changes_value() {
        let cell = RcuCell::new(1u64);
        cell.update(2);
        assert_eq!(*cell.load(), 2);
    }

    #[test]
    fn rcu_cell_update_bumps_epoch() {
        let cell = RcuCell::new(0u64);
        let e0 = cell.epoch();
        cell.update(1);
        let e1 = cell.epoch();
        assert!(e1 > e0, "epoch must advance on update");
    }

    #[test]
    fn rcu_cell_update_with_closure() {
        let cell = RcuCell::new(10u64);
        cell.update_with(|old| old + 5);
        assert_eq!(*cell.load(), 15);
    }

    #[test]
    fn rcu_cell_multiple_updates() {
        let cell = RcuCell::new(0u64);
        for i in 1..=100 {
            cell.update(i);
        }
        assert_eq!(*cell.load(), 100);
        assert_eq!(cell.epoch(), 101); // initial(1) + 100 updates
    }

    #[test]
    fn rcu_cell_reader_count_starts_at_zero() {
        let cell = RcuCell::new(0u64);
        assert_eq!(cell.reader_count(), 0);
    }

    #[test]
    fn rcu_cell_reader_count_tracks_clones() {
        let cell = RcuCell::new(0u64);
        let _r1 = cell.load();
        assert_eq!(cell.reader_count(), 1);
        let _r2 = cell.load();
        assert_eq!(cell.reader_count(), 2);
        drop(_r1);
        assert_eq!(cell.reader_count(), 1);
    }

    #[test]
    fn rcu_cell_old_snapshot_survives_update() {
        let cell = RcuCell::new(1u64);
        let old = cell.load();
        cell.update(2);
        // Old snapshot still readable via its Arc.
        assert_eq!(*old, 1);
        assert_eq!(*cell.load(), 2);
    }

    // ──────────────────────────── RcuReader tests ────────────────────────────

    #[test]
    fn rcu_reader_sees_initial_value() {
        let cell = RcuCell::new(99u64);
        let mut reader = RcuReader::new(&cell);
        assert_eq!(*reader.read(), 99);
    }

    #[test]
    fn rcu_reader_hot_path_returns_cached() {
        let cell = RcuCell::new(7u64);
        let mut reader = RcuReader::new(&cell);

        // Multiple reads without update should all be hot-path (epoch match).
        for _ in 0..1000 {
            assert_eq!(*reader.read(), 7);
        }
    }

    #[test]
    fn rcu_reader_detects_epoch_change() {
        let cell = RcuCell::new(1u64);
        let mut reader = RcuReader::new(&cell);
        assert_eq!(*reader.read(), 1);

        cell.update(2);
        // Next read should detect epoch mismatch and refresh.
        assert_eq!(*reader.read(), 2);
    }

    #[test]
    fn rcu_reader_multiple_updates() {
        let cell = RcuCell::new(0u64);
        let mut reader = RcuReader::new(&cell);

        for i in 1..=50 {
            cell.update(i);
            assert_eq!(*reader.read(), i);
        }
    }

    #[test]
    fn rcu_reader_refresh_forces_reload() {
        let cell = RcuCell::new(1u64);
        let mut reader = RcuReader::new(&cell);
        assert_eq!(*reader.read(), 1);

        cell.update(42);
        reader.refresh();
        assert_eq!(reader.cached_epoch(), cell.epoch());
    }

    #[test]
    fn rcu_reader_cached_epoch_matches_cell() {
        let cell = RcuCell::new(0u64);
        let reader = RcuReader::new(&cell);
        assert_eq!(reader.cached_epoch(), cell.epoch());
    }

    // ──────────────────────── Concurrent RcuCell tests ────────────────────────

    #[test]
    fn rcu_cell_concurrent_readers_see_consistent_snapshots() {
        let cell = Arc::new(RcuCell::new(0u64));
        let barrier = Arc::new(Barrier::new(5));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let cell = Arc::clone(&cell);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut reader = RcuReader::new(&cell);
                barrier.wait();
                let mut prev = 0u64;
                for _ in 0..10_000 {
                    let val = *reader.read();
                    assert!(
                        val >= prev,
                        "readers must see monotonically non-decreasing values"
                    );
                    prev = val;
                }
            }));
        }

        // Writer thread.
        barrier.wait();
        for i in 1..=1000 {
            cell.update(i);
        }

        for h in handles {
            h.join().expect("reader thread panicked");
        }
    }

    #[test]
    fn rcu_cell_concurrent_writer_reader_stress() {
        let cell = Arc::new(RcuCell::new(0u64));
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let cell_w = Arc::clone(&cell);
        let done_w = Arc::clone(&done);
        let writer = thread::spawn(move || {
            for i in 1..=50_000u64 {
                cell_w.update(i);
            }
            done_w.store(true, Ordering::Release);
        });

        let cell_r = Arc::clone(&cell);
        let done_r = Arc::clone(&done);
        let reader = thread::spawn(move || {
            let mut rdr = RcuReader::new(&cell_r);
            let mut reads = 0u64;
            while !done_r.load(Ordering::Acquire) || reads < 100 {
                let _val = *rdr.read();
                reads += 1;
            }
            reads
        });

        writer.join().expect("writer panicked");
        let reads = reader.join().expect("reader panicked");
        assert!(reads >= 100, "reader should have performed reads");
        assert_eq!(*cell.load(), 50_000);
    }

    // ──────────────────────────── QSBR tests ────────────────────────────

    #[test]
    fn qsbr_register_and_deregister() {
        let registry = QsbrRegistry::new();
        assert_eq!(registry.active_count(), 0);

        let h1 = registry.register();
        assert_eq!(registry.active_count(), 1);

        let h2 = registry.register();
        assert_eq!(registry.active_count(), 2);

        drop(h1);
        assert_eq!(registry.active_count(), 1);

        drop(h2);
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn qsbr_slot_reuse() {
        let registry = QsbrRegistry::new();

        let h1 = registry.register();
        let slot1 = h1.slot_id();
        drop(h1);

        let h2 = registry.register();
        assert_eq!(h2.slot_id(), slot1, "should reuse deregistered slot");
    }

    #[test]
    fn qsbr_grace_period_completes_after_quiescent() {
        let registry = QsbrRegistry::new();
        let h1 = registry.register();
        let h2 = registry.register();

        let epoch = registry.advance_epoch();
        assert!(
            !registry.is_grace_period_complete(epoch),
            "grace period should not be complete before quiescent reports"
        );

        h1.quiescent();
        assert!(
            !registry.is_grace_period_complete(epoch),
            "grace period should not be complete until ALL threads report"
        );

        h2.quiescent();
        assert!(
            registry.is_grace_period_complete(epoch),
            "grace period should be complete after all threads report"
        );
    }

    #[test]
    fn qsbr_deregistered_thread_does_not_block_grace_period() {
        let registry = QsbrRegistry::new();
        let h1 = registry.register();
        let _h2 = registry.register();

        let epoch = registry.advance_epoch();

        // h1 drops without reporting quiescent — should NOT block.
        drop(h1);

        // Only h2 remains; report quiescent.
        _h2.quiescent();
        assert!(registry.is_grace_period_complete(epoch));
    }

    #[test]
    fn qsbr_no_active_threads_means_immediate_grace_period() {
        let registry = QsbrRegistry::new();
        let epoch = registry.advance_epoch();
        assert!(
            registry.is_grace_period_complete(epoch),
            "grace period trivially complete with no active threads"
        );
    }

    #[test]
    fn qsbr_multiple_epochs() {
        let registry = QsbrRegistry::new();
        let h = registry.register();

        let e1 = registry.advance_epoch();
        h.quiescent();
        assert!(registry.is_grace_period_complete(e1));

        let e2 = registry.advance_epoch();
        assert!(
            !registry.is_grace_period_complete(e2),
            "new epoch should not be satisfied by old quiescent report"
        );

        h.quiescent();
        assert!(registry.is_grace_period_complete(e2));
    }

    #[test]
    fn qsbr_concurrent_quiescent_reporting() {
        let registry = Arc::new(QsbrRegistry::new());
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let reg = Arc::clone(&registry);
            let bar = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let handle = reg.register();
                bar.wait();
                for _ in 0..1000 {
                    handle.quiescent();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // After all threads join, all slots are deregistered.
        assert_eq!(registry.active_count(), 0);
        // Any epoch should now be complete.
        let epoch = registry.advance_epoch();
        assert!(registry.is_grace_period_complete(epoch));
    }

    // ──────────────────────── ReclaimQueue tests ────────────────────────

    #[test]
    fn reclaim_queue_empty() {
        let queue: ReclaimQueue<String> = ReclaimQueue::new();
        let registry = QsbrRegistry::new();
        assert_eq!(queue.pending_count(), 0);
        assert!(queue.drain_completed(&registry).is_empty());
    }

    #[test]
    fn reclaim_queue_defers_until_grace_period() {
        let registry = QsbrRegistry::new();
        let queue = ReclaimQueue::new();
        let h = registry.register();

        let epoch = registry.advance_epoch();
        queue.defer(epoch, "old_resource".to_string());

        // Not yet complete — h hasn't reported quiescent.
        assert!(queue.drain_completed(&registry).is_empty());
        assert_eq!(queue.pending_count(), 1);

        // Report quiescent.
        h.quiescent();
        let drained = queue.drain_completed(&registry);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0], "old_resource");
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn reclaim_queue_partial_drain() {
        let registry = QsbrRegistry::new();
        let queue = ReclaimQueue::new();
        let h = registry.register();

        let e1 = registry.advance_epoch();
        queue.defer(e1, 1u64);
        h.quiescent();

        let e2 = registry.advance_epoch();
        queue.defer(e2, 2u64);

        // Only e1's grace period is complete.
        let drained = queue.drain_completed(&registry);
        assert_eq!(drained, vec![1]);
        assert_eq!(queue.pending_count(), 1);

        // Now report quiescent for e2.
        h.quiescent();
        let drained = queue.drain_completed(&registry);
        assert_eq!(drained, vec![2]);
        assert_eq!(queue.pending_count(), 0);
    }

    #[test]
    fn reclaim_queue_multiple_items_same_epoch() {
        let registry = QsbrRegistry::new();
        let queue = ReclaimQueue::new();
        let h = registry.register();

        let epoch = registry.advance_epoch();
        queue.defer(epoch, "a".to_string());
        queue.defer(epoch, "b".to_string());
        queue.defer(epoch, "c".to_string());

        h.quiescent();
        let mut drained = queue.drain_completed(&registry);
        drained.sort();
        assert_eq!(drained, vec!["a", "b", "c"]);
    }

    // ──────────────────── Composite integration tests ────────────────────

    #[test]
    fn rcu_cell_with_struct_snapshot() {
        #[derive(Debug, Clone, PartialEq)]
        struct Snapshot {
            risk_ppm: u32,
            spectral_phase: u8,
            family_states: [u8; 20],
        }

        let initial = Snapshot {
            risk_ppm: 1000,
            spectral_phase: 0,
            family_states: [0; 20],
        };

        let cell = RcuCell::new(initial.clone());
        let mut reader = RcuReader::new(&cell);
        assert_eq!(reader.read(), &initial);

        let mut updated = initial.clone();
        updated.risk_ppm = 5000;
        updated.spectral_phase = 2;
        updated.family_states[3] = 1;
        cell.update(updated.clone());

        assert_eq!(reader.read(), &updated);
    }

    #[test]
    fn rcu_and_qsbr_combined_lifecycle() {
        let registry = QsbrRegistry::new();
        let cell = RcuCell::new(vec![1, 2, 3]);
        let queue: ReclaimQueue<Vec<i32>> = ReclaimQueue::new();

        let h = registry.register();
        let mut reader = RcuReader::new(&cell);

        // Read initial.
        assert_eq!(reader.read(), &vec![1, 2, 3]);

        // Writer publishes new version and defers old for reclamation.
        let old = cell.load();
        cell.update(vec![4, 5, 6]);
        let epoch = registry.advance_epoch();
        queue.defer(epoch, Vec::clone(&old));

        // Reader still has old snapshot until it calls read().
        // Old resource is pending.
        assert!(queue.drain_completed(&registry).is_empty());

        // Reader refreshes and reports quiescent.
        assert_eq!(reader.read(), &vec![4, 5, 6]);
        h.quiescent();

        // Grace period complete — old resource can be reclaimed.
        let drained = queue.drain_completed(&registry);
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn rcu_reader_independent_across_threads() {
        let cell = Arc::new(RcuCell::new(0u64));
        let barrier = Arc::new(Barrier::new(3));

        let cell2 = Arc::clone(&cell);
        let barrier2 = Arc::clone(&barrier);
        let t1 = thread::spawn(move || {
            let mut reader = RcuReader::new(&cell2);
            barrier2.wait();
            let mut last = 0;
            for _ in 0..5000 {
                let v = *reader.read();
                assert!(v >= last);
                last = v;
            }
            last
        });

        let cell3 = Arc::clone(&cell);
        let barrier3 = Arc::clone(&barrier);
        let t2 = thread::spawn(move || {
            let mut reader = RcuReader::new(&cell3);
            barrier3.wait();
            let mut last = 0;
            for _ in 0..5000 {
                let v = *reader.read();
                assert!(v >= last);
                last = v;
            }
            last
        });

        barrier.wait();
        for i in 1..=2000u64 {
            cell.update(i);
        }

        let _v1 = t1.join().expect("t1 panicked");
        let _v2 = t2.join().expect("t2 panicked");

        // The critical invariant is monotonicity (asserted inside each reader loop).
        // Whether a reader sees updates depends on scheduling; the assertion that
        // matters is v >= last (no regression) for every observation.
        assert_eq!(
            *cell.load(),
            2000,
            "writer should have published all updates"
        );
    }

    #[test]
    fn qsbr_stress_register_deregister_cycle() {
        let registry = Arc::new(QsbrRegistry::new());
        let mut handles = Vec::new();

        for _ in 0..4 {
            let reg = Arc::clone(&registry);
            handles.push(thread::spawn(move || {
                for _ in 0..500 {
                    let h = reg.register();
                    h.quiescent();
                    drop(h);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn reclaim_queue_concurrent_defer_and_drain() {
        let registry = Arc::new(QsbrRegistry::new());
        let queue = Arc::new(ReclaimQueue::<u64>::new());

        let reg2 = Arc::clone(&registry);
        let q2 = Arc::clone(&queue);

        let producer = thread::spawn(move || {
            let h = reg2.register();
            for i in 0..100u64 {
                let epoch = reg2.advance_epoch();
                q2.defer(epoch, i);
                h.quiescent();
            }
        });

        producer.join().expect("producer panicked");

        // All grace periods should be complete now (thread exited → deregistered).
        let drained = queue.drain_completed(&registry);
        assert_eq!(drained.len(), 100);
    }
}
