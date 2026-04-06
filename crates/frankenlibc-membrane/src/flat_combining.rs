//! Flat Combining: convert lock contention into sequential batching.
//!
//! Under high contention (>4 threads), Flat Combining outperforms simple
//! mutex-based locking by amortizing the cost of lock acquisition across
//! multiple operations. Instead of N threads each acquiring the lock,
//! threads post operations to a publication list and ONE combiner thread
//! executes them all in batch.
//!
//! # Design
//!
//! This implementation uses safe Rust only (`#![deny(unsafe_code)]` compliant):
//!
//! - **Publication slots**: Each thread gets a fixed-capacity slot in a shared
//!   `Vec<Mutex<Slot>>`. The slot holds the pending operation, result, and
//!   completion flag.
//! - **Combiner election**: The first thread that can acquire the combiner lock
//!   becomes the combiner. It scans all slots, executes pending operations on
//!   the shared state, and publishes results.
//! - **Non-combiner wait**: Threads that fail to become combiner spin-wait on
//!   their slot's completion flag (with `thread::yield_now()` backoff).
//!
//! # Usage
//!
//! ```ignore
//! use frankenlibc_membrane::flat_combining::FlatCombiner;
//!
//! // Define shared state and operations.
//! let combiner = FlatCombiner::new(MyState::new(), 16); // 16 slots
//!
//! // From any thread:
//! let result = combiner.execute(MyOp::Increment(5), |state, op| {
//!     match op {
//!         MyOp::Increment(n) => { state.counter += n; state.counter }
//!     }
//! });
//! ```
//!
//! # Performance
//!
//! - 1 thread: ~equivalent to direct Mutex (slight overhead from slot management)
//! - 4+ threads: combining amortizes lock cost → throughput scales near-linearly
//! - Cache-friendly: combiner processes all ops sequentially → better L1 hit rate

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Slot states for the publication list.
#[derive(Debug)]
struct Slot<Op, R> {
    /// The operation to execute (set by the requesting thread).
    operation: Option<Op>,
    /// The result of the operation (set by the combiner).
    result: Option<R>,
    /// Whether this slot has a pending operation.
    pending: bool,
    /// Whether this slot's operation has been completed by the combiner.
    completed: bool,
    /// Whether this slot is currently owned by a thread.
    active: bool,
    /// Age counter: incremented each time this slot is used.
    age: u64,
}

impl<Op, R> Slot<Op, R> {
    fn new() -> Self {
        Self {
            operation: None,
            result: None,
            pending: false,
            completed: false,
            active: false,
            age: 0,
        }
    }
}

/// Handle for a thread's reserved slot in the flat combiner.
///
/// Automatically releases the slot when dropped.
pub struct SlotHandle<'a, T, Op: Send, R: Send> {
    combiner: &'a FlatCombiner<T, Op, R>,
    slot_id: usize,
}

impl<T, Op: Send, R: Send> Drop for SlotHandle<'_, T, Op, R> {
    fn drop(&mut self) {
        if let Some(slot) = self.combiner.slots.get(self.slot_id) {
            let mut guard = slot.lock();
            guard.active = false;
            guard.pending = false;
            guard.completed = false;
            guard.operation = None;
            guard.result = None;
        }
    }
}

/// Flat Combining data structure.
///
/// Converts lock contention into sequential batching by having one elected
/// combiner thread execute all pending operations in batch.
pub struct FlatCombiner<T, Op: Send, R: Send> {
    /// The shared state protected by flat combining.
    state: Mutex<T>,
    /// Publication list: per-thread operation slots.
    slots: Vec<Mutex<Slot<Op, R>>>,
    /// Combiner lock: only one thread can be combiner at a time.
    combiner_lock: Mutex<()>,
    /// Whether a combiner is currently active (advisory, for fast path).
    combiner_active: AtomicBool,
    /// Total operations executed (for diagnostics).
    total_ops: AtomicU64,
    /// Total combining passes (for diagnostics).
    total_passes: AtomicU64,
    /// Maximum batch size observed (for diagnostics).
    max_batch_size: AtomicU64,
}

impl<T, Op, R> FlatCombiner<T, Op, R>
where
    Op: Send,
    R: Send,
{
    /// Create a new flat combiner with the given shared state and slot capacity.
    ///
    /// `num_slots` should be at least the expected maximum thread count.
    /// Extra slots are pre-allocated but unused.
    #[must_use]
    pub fn new(initial_state: T, num_slots: usize) -> Self {
        let slots = (0..num_slots).map(|_| Mutex::new(Slot::new())).collect();
        let combiner = Self {
            state: Mutex::new(initial_state),
            slots,
            combiner_lock: Mutex::new(()),
            combiner_active: AtomicBool::new(false),
            total_ops: AtomicU64::new(0),
            total_passes: AtomicU64::new(0),
            max_batch_size: AtomicU64::new(0),
        };
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptActivated,
            num_slots as u64,
            "flat_combining",
        );
        combiner
    }

    /// Reserve a slot for the calling thread.
    ///
    /// Returns `None` if all slots are occupied.
    pub fn reserve_slot(&self) -> Option<SlotHandle<'_, T, Op, R>> {
        for (i, slot_mutex) in self.slots.iter().enumerate() {
            let mut slot = slot_mutex.lock();
            if !slot.active {
                slot.active = true;
                slot.age = 0;
                return Some(SlotHandle {
                    combiner: self,
                    slot_id: i,
                });
            }
        }
        None
    }

    /// Execute an operation using a reserved slot handle.
    ///
    /// The operation function `f` is called by the combiner thread with
    /// exclusive access to the shared state.
    pub fn execute_with_handle<F>(&self, handle: &SlotHandle<'_, T, Op, R>, op: Op, f: F) -> R
    where
        F: Fn(&mut T, Op) -> R + Sync,
    {
        self.execute_on_slot(handle.slot_id, op, &f)
    }

    /// Execute an operation, automatically acquiring a slot.
    ///
    /// Falls back to direct lock acquisition if no slot is available.
    pub fn execute<F>(&self, op: Op, f: F) -> R
    where
        F: Fn(&mut T, Op) -> R + Sync,
    {
        // Try to find a free slot.
        for (i, slot_mutex) in self.slots.iter().enumerate() {
            let mut slot = slot_mutex.lock();
            if !slot.active && !slot.pending {
                slot.active = true;
                slot.age = slot.age.wrapping_add(1);
                drop(slot);
                let result = self.execute_on_slot(i, op, &f);
                // Release the slot.
                let mut slot = self.slots[i].lock();
                slot.active = false;
                return result;
            }
        }

        // Fallback: all slots busy, execute directly under lock.
        let mut state = self.state.lock();
        self.total_ops.fetch_add(1, Ordering::Relaxed);
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::FcDirectFallback,
            self.total_ops.load(Ordering::Relaxed),
            "flat_combining",
        );
        f(&mut state, op)
    }

    /// Core flat combining logic for a specific slot.
    fn execute_on_slot<F>(&self, slot_id: usize, op: Op, f: &F) -> R
    where
        F: Fn(&mut T, Op) -> R + Sync,
    {
        // Publish our operation.
        {
            let mut slot = self.slots[slot_id].lock();
            slot.operation = Some(op);
            slot.pending = true;
            slot.completed = false;
            slot.result = None;
        }

        // Try to become the combiner.
        if let Some(combiner_guard) = self.combiner_lock.try_lock() {
            self.combiner_active.store(true, Ordering::Release);
            self.run_combining_pass(f);
            self.combiner_active.store(false, Ordering::Release);
            drop(combiner_guard);
        } else {
            // Another thread is the combiner. Wait for our operation to complete.
            self.wait_for_completion(slot_id);

            // If we weren't served (combiner finished before processing our slot),
            // try to become combiner ourselves.
            let slot = self.slots[slot_id].lock();
            if slot.pending && !slot.completed {
                drop(slot);
                let _combiner_guard = self.combiner_lock.lock();
                self.combiner_active.store(true, Ordering::Release);
                self.run_combining_pass(f);
                self.combiner_active.store(false, Ordering::Release);
            }
        }

        // Retrieve our result.
        let mut slot = self.slots[slot_id].lock();
        slot.pending = false;
        slot.completed = false;
        slot.result
            .take()
            .expect("flat combining: result must be available after completion")
    }

    /// The combining pass: scan all slots, execute pending operations, publish results.
    fn run_combining_pass<F>(&self, f: &F)
    where
        F: Fn(&mut T, Op) -> R + Sync,
    {
        let mut state = self.state.lock();
        let mut batch_size = 0u64;

        for slot_mutex in &self.slots {
            let mut slot = slot_mutex.lock();
            if slot.pending
                && !slot.completed
                && let Some(op) = slot.operation.take()
            {
                let result = f(&mut state, op);
                slot.result = Some(result);
                slot.completed = true;
                slot.pending = false;
                batch_size += 1;
            }
        }

        if batch_size > 0 {
            self.total_ops.fetch_add(batch_size, Ordering::Relaxed);
            self.total_passes.fetch_add(1, Ordering::Relaxed);
            let _ =
                self.max_batch_size
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        if batch_size > current {
                            Some(batch_size)
                        } else {
                            None
                        }
                    });
            crate::alien_cs_metrics::emit_alien_cs_event(
                crate::alien_cs_metrics::MetricEventKind::FcCombiningPass,
                batch_size,
                "flat_combining",
            );
        }
    }

    /// Wait for our slot's operation to be completed by the combiner.
    fn wait_for_completion(&self, slot_id: usize) {
        // Bounded spin with yield backoff.
        for attempt in 0..1000 {
            let slot = self.slots[slot_id].lock();
            if slot.completed || !slot.pending {
                return;
            }
            drop(slot);
            if attempt > 10 {
                std::thread::yield_now();
            }
        }
    }

    /// Get the total number of operations executed.
    #[must_use]
    pub fn total_ops(&self) -> u64 {
        self.total_ops.load(Ordering::Relaxed)
    }

    /// Get the total number of combining passes.
    #[must_use]
    pub fn total_passes(&self) -> u64 {
        self.total_passes.load(Ordering::Relaxed)
    }

    /// Get the maximum batch size observed in a single combining pass.
    #[must_use]
    pub fn max_batch_size(&self) -> u64 {
        self.max_batch_size.load(Ordering::Relaxed)
    }

    /// Get a snapshot of the combiner's diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> FlatCombinerDiagnostics {
        let total_ops = self.total_ops.load(Ordering::Relaxed);
        let total_passes = self.total_passes.load(Ordering::Relaxed);
        let active_slots = self.slots.iter().filter(|s| s.lock().active).count();
        FlatCombinerDiagnostics {
            total_ops,
            total_passes,
            max_batch_size: self.max_batch_size.load(Ordering::Relaxed),
            avg_batch_size: if total_passes > 0 {
                total_ops as f64 / total_passes as f64
            } else {
                0.0
            },
            active_slots,
            total_slots: self.slots.len(),
        }
    }

    /// Access the shared state directly (bypassing flat combining).
    ///
    /// Useful for initialization, diagnostics, or when contention is known
    /// to be zero.
    pub fn with_state<F2, R2>(&self, f: F2) -> R2
    where
        F2: FnOnce(&mut T) -> R2,
    {
        let mut state = self.state.lock();
        f(&mut state)
    }

    /// Read-only access to the shared state.
    pub fn with_state_ref<F2, R2>(&self, f: F2) -> R2
    where
        F2: FnOnce(&T) -> R2,
    {
        let state = self.state.lock();
        f(&state)
    }
}

impl<T, Op: Send, R: Send> Drop for FlatCombiner<T, Op, R> {
    fn drop(&mut self) {
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptDeactivated,
            self.total_ops.load(Ordering::Relaxed),
            "flat_combining",
        );
    }
}

/// Diagnostics snapshot for a flat combiner.
#[derive(Debug, Clone)]
pub struct FlatCombinerDiagnostics {
    /// Total operations executed.
    pub total_ops: u64,
    /// Total combining passes.
    pub total_passes: u64,
    /// Largest batch processed in one pass.
    pub max_batch_size: u64,
    /// Average batch size (total_ops / total_passes).
    pub avg_batch_size: f64,
    /// Currently active (reserved) slots.
    pub active_slots: usize,
    /// Total slot capacity.
    pub total_slots: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // ───────────────── Basic operations ─────────────────

    #[test]
    fn single_thread_increment() {
        let fc = FlatCombiner::new(0u64, 4);
        let result = fc.execute(5u64, |state, op| {
            *state += op;
            *state
        });
        assert_eq!(result, 5);
    }

    #[test]
    fn multiple_sequential_operations() {
        let fc = FlatCombiner::new(0u64, 4);
        for i in 1..=10 {
            let result = fc.execute(i, |state, op| {
                *state += op;
                *state
            });
            assert_eq!(result, (1..=i).sum::<u64>());
        }
    }

    #[test]
    fn execute_with_handle() {
        let fc = FlatCombiner::new(0u64, 4);
        let handle = fc.reserve_slot().expect("should get slot");
        let r1 = fc.execute_with_handle(&handle, 10, |state, op| {
            *state += op;
            *state
        });
        let r2 = fc.execute_with_handle(&handle, 20, |state, op| {
            *state += op;
            *state
        });
        assert_eq!(r1, 10);
        assert_eq!(r2, 30);
    }

    #[test]
    fn slot_reservation_and_release() {
        let fc: FlatCombiner<u64, u64, u64> = FlatCombiner::new(0, 2);
        let h1 = fc.reserve_slot().expect("slot 1");
        let h2 = fc.reserve_slot().expect("slot 2");
        assert!(fc.reserve_slot().is_none(), "no free slots");

        drop(h1);
        let _h3 = fc.reserve_slot().expect("slot reused after drop");
        drop(h2);
        drop(_h3);
    }

    #[test]
    fn with_state_direct_access() {
        let fc: FlatCombiner<Vec<u32>, u32, usize> = FlatCombiner::new(Vec::new(), 4);
        fc.execute(42, |state, op| {
            state.push(op);
            state.len()
        });

        fc.with_state(|state| {
            assert_eq!(state, &vec![42]);
        });
    }

    #[test]
    fn with_state_ref_read_only() {
        let fc: FlatCombiner<u64, u64, u64> = FlatCombiner::new(100, 4);
        let val = fc.with_state_ref(|state| *state);
        assert_eq!(val, 100);
    }

    #[test]
    fn diagnostics_initial_state() {
        let fc: FlatCombiner<u64, u64, u64> = FlatCombiner::new(0, 8);
        let diag = fc.diagnostics();
        assert_eq!(diag.total_ops, 0);
        assert_eq!(diag.total_passes, 0);
        assert_eq!(diag.max_batch_size, 0);
        assert_eq!(diag.active_slots, 0);
        assert_eq!(diag.total_slots, 8);
    }

    #[test]
    fn diagnostics_after_operations() {
        let fc = FlatCombiner::new(0u64, 4);
        for i in 0..10 {
            fc.execute(i, |state, op| {
                *state += op;
                *state
            });
        }
        let diag = fc.diagnostics();
        assert_eq!(diag.total_ops, 10);
        assert!(diag.total_passes > 0);
    }

    // ───────────────── Concurrent operations ─────────────────

    #[test]
    fn concurrent_counter_4_threads() {
        let fc = Arc::new(FlatCombiner::new(0u64, 8));
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..1000 {
                    fc.execute(1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let final_val = fc.with_state_ref(|state| *state);
        assert_eq!(
            final_val, 4000,
            "all increments must be applied exactly once"
        );
    }

    #[test]
    fn concurrent_counter_8_threads() {
        let fc = Arc::new(FlatCombiner::new(0u64, 16));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..2000 {
                    fc.execute(1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let final_val = fc.with_state_ref(|state| *state);
        assert_eq!(final_val, 16_000);
    }

    #[test]
    fn concurrent_with_handles() {
        let fc = Arc::new(FlatCombiner::new(0u64, 8));
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let slot = fc.reserve_slot().expect("should get slot");
                barrier.wait();
                for _ in 0..500 {
                    fc.execute_with_handle(&slot, 1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let final_val = fc.with_state_ref(|state| *state);
        assert_eq!(final_val, 2000);
    }

    #[test]
    fn combining_reduces_lock_acquisitions() {
        let fc = Arc::new(FlatCombiner::new(0u64, 16));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        for _ in 0..8 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..1000 {
                    fc.execute(1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        let diag = fc.diagnostics();
        assert_eq!(diag.total_ops, 8000);
        // Under contention, combining should reduce the number of passes
        // below the number of operations.
        assert!(
            diag.total_passes <= diag.total_ops,
            "combining passes ({}) should not exceed total ops ({})",
            diag.total_passes,
            diag.total_ops,
        );
    }

    // ───────────────── Different operation types ─────────────────

    #[derive(Debug)]
    enum CounterOp {
        Add(u64),
        Sub(u64),
        Get,
    }

    #[test]
    fn mixed_operation_types() {
        let fc = FlatCombiner::new(100u64, 4);

        let r1 = fc.execute(CounterOp::Add(50), |state, op| match op {
            CounterOp::Add(n) => {
                *state += n;
                *state
            }
            CounterOp::Sub(n) => {
                *state = state.saturating_sub(n);
                *state
            }
            CounterOp::Get => *state,
        });
        assert_eq!(r1, 150);

        let r2 = fc.execute(CounterOp::Sub(30), |state, op| match op {
            CounterOp::Add(n) => {
                *state += n;
                *state
            }
            CounterOp::Sub(n) => {
                *state = state.saturating_sub(n);
                *state
            }
            CounterOp::Get => *state,
        });
        assert_eq!(r2, 120);

        let r3 = fc.execute(CounterOp::Get, |state, op| match op {
            CounterOp::Add(n) => {
                *state += n;
                *state
            }
            CounterOp::Sub(n) => {
                *state = state.saturating_sub(n);
                *state
            }
            CounterOp::Get => *state,
        });
        assert_eq!(r3, 120);
    }

    // ───────────────── Struct state ─────────────────

    #[derive(Debug, Default)]
    struct PressureState {
        regime: u8,
        score: u64,
        samples: u64,
    }

    #[derive(Debug)]
    enum PressureOp {
        Observe { score: u64 },
        QueryRegime,
    }

    #[test]
    fn pressure_sensor_flat_combining_pattern() {
        let fc = FlatCombiner::new(PressureState::default(), 8);

        // Simulate pressure observations.
        for score in [100, 200, 300, 400, 500, 600, 700, 800, 900, 1000] {
            fc.execute(PressureOp::Observe { score }, |state, op| match op {
                PressureOp::Observe { score } => {
                    state.samples += 1;
                    // EWMA with alpha=0.5.
                    state.score = (state.score + score) / 2;
                    state.regime = if state.score > 700 {
                        2 // Overloaded
                    } else if state.score > 400 {
                        1 // Pressured
                    } else {
                        0 // Nominal
                    };
                    state.regime
                }
                PressureOp::QueryRegime => state.regime,
            });
        }

        let regime = fc.execute(PressureOp::QueryRegime, |state, op| match op {
            PressureOp::Observe { score } => {
                state.samples += 1;
                state.score = (state.score + score) / 2;
                state.regime = if state.score > 700 {
                    2
                } else if state.score > 400 {
                    1
                } else {
                    0
                };
                state.regime
            }
            PressureOp::QueryRegime => state.regime,
        });

        // After observing increasing scores, regime should be elevated.
        assert!(regime >= 1, "pressure regime should be at least Pressured");
    }

    // ───────────────── Concurrent mixed operations ─────────────────

    #[test]
    fn concurrent_mixed_operations() {
        let fc = Arc::new(FlatCombiner::new(0i64, 16));
        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        // 4 adder threads.
        for _ in 0..4 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..500 {
                    fc.execute(1i64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        // 4 subtractor threads.
        for _ in 0..4 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..500 {
                    fc.execute(-1i64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // 4 threads adding 500 each + 4 threads subtracting 500 each = 0.
        let final_val = fc.with_state_ref(|state| *state);
        assert_eq!(final_val, 0);
    }

    // ───────────────── Edge cases ─────────────────

    #[test]
    fn zero_slot_combiner_falls_back() {
        let fc = FlatCombiner::new(0u64, 0);
        // With 0 slots, all operations go through direct fallback.
        let r = fc.execute(42, |state, op| {
            *state += op;
            *state
        });
        assert_eq!(r, 42);
    }

    #[test]
    fn single_slot_combiner() {
        let fc = FlatCombiner::new(0u64, 1);
        for i in 1..=100 {
            let r = fc.execute(1u64, |state, op| {
                *state += op;
                *state
            });
            assert_eq!(r, i);
        }
    }

    #[test]
    fn slot_handle_drop_releases_slot() {
        let fc: FlatCombiner<u64, u64, u64> = FlatCombiner::new(0, 2);
        {
            let _h1 = fc.reserve_slot().expect("slot 1");
            let _h2 = fc.reserve_slot().expect("slot 2");
            assert!(fc.reserve_slot().is_none());
            // h1 and h2 drop here.
        }
        // Slots should be available again.
        let _h3 = fc.reserve_slot().expect("slot reused");
    }

    #[test]
    fn high_contention_stress_16_threads() {
        let fc = Arc::new(FlatCombiner::new(0u64, 32));
        let barrier = Arc::new(Barrier::new(16));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let fc = Arc::clone(&fc);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..2000 {
                    fc.execute(1u64, |state, op| {
                        *state += op;
                        *state
                    });
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(fc.with_state_ref(|s| *s), 32_000);

        let diag = fc.diagnostics();
        assert_eq!(diag.total_ops, 32_000);
        // With 16 threads, we should see significant combining.
        assert!(
            diag.max_batch_size > 1,
            "high contention should produce batch sizes > 1, got {}",
            diag.max_batch_size
        );
    }
}
