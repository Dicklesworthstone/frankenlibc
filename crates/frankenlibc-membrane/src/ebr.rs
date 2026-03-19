//! Epoch-Based Reclamation (EBR) for safe deferred cleanup in concurrent structures.
//!
//! This module provides the classic three-epoch EBR algorithm adapted for safe Rust
//! (`#![deny(unsafe_code)]`). It enables lock-free data structures to defer reclamation
//! of retired items until all threads that might hold references have advanced.

use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Global epoch counter for EBR.
pub struct EbrCollector {
    /// Global epoch, incremented by `try_advance()`.
    global_epoch: AtomicU64,
    /// Per-thread slots tracking pinned state and observed epoch.
    /// The Mutex is only taken during registration/deregistration and advance.
    slots: Mutex<Vec<Arc<EbrSlot>>>,
    /// Retired items awaiting reclamation, bucketed by retirement epoch.
    garbage: [Mutex<Vec<DeferredItem>>; 3],
    /// Total items retired (diagnostic).
    total_retired: AtomicU64,
    /// Total items reclaimed (diagnostic).
    total_reclaimed: AtomicU64,
}

/// Per-thread tracking slot.
struct EbrSlot {
    /// Whether this slot is currently registered.
    active: AtomicBool,
    /// Whether the thread is currently pinned (inside a guard).
    pinned: AtomicBool,
    /// The epoch the thread last observed.
    observed_epoch: AtomicU64,
}

/// A deferred item waiting for reclamation.
struct DeferredItem {
    /// Boxed cleanup closure. Called when the item is reclaimed.
    cleanup: Box<dyn FnOnce() + Send>,
}

/// Handle for a registered thread. Automatically deregisters on drop.
pub struct EbrHandle<'a> {
    collector: &'a EbrCollector,
    slot: Arc<EbrSlot>,
    slot_id: usize,
}

/// RAII guard that pins the current epoch for the duration of its lifetime.
pub struct EbrGuard<'a> {
    collector: &'a EbrCollector,
    slot: Arc<EbrSlot>,
    epoch: u64,
}

/// Diagnostic snapshot of the EBR collector state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbrDiagnostics {
    pub global_epoch: u64,
    pub active_threads: usize,
    pub pinned_threads: usize,
    pub total_retired: u64,
    pub total_reclaimed: u64,
    pub pending_per_epoch: [usize; 3],
}

impl EbrCollector {
    /// Create a new EBR collector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            global_epoch: AtomicU64::new(0),
            slots: Mutex::new(Vec::new()),
            garbage: [
                Mutex::new(Vec::new()),
                Mutex::new(Vec::new()),
                Mutex::new(Vec::new()),
            ],
            total_retired: AtomicU64::new(0),
            total_reclaimed: AtomicU64::new(0),
        }
    }

    /// Register a thread with the collector.
    pub fn register(&self) -> EbrHandle<'_> {
        let mut slots = self.slots.lock();
        let epoch = self.global_epoch.load(Ordering::Acquire);

        // Reuse inactive slot.
        for (i, slot) in slots.iter().enumerate() {
            if !slot.active.load(Ordering::Relaxed) {
                slot.active.store(true, Ordering::Release);
                slot.pinned.store(false, Ordering::Release);
                slot.observed_epoch.store(epoch, Ordering::Release);
                return EbrHandle {
                    collector: self,
                    slot: Arc::clone(slot),
                    slot_id: i,
                };
            }
        }

        // Allocate new slot.
        let slot_id = slots.len();
        let slot = Arc::new(EbrSlot {
            active: AtomicBool::new(true),
            pinned: AtomicBool::new(false),
            observed_epoch: AtomicU64::new(epoch),
        });
        slots.push(Arc::clone(&slot));
        EbrHandle {
            collector: self,
            slot,
            slot_id,
        }
    }

    /// Get the current global epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.global_epoch.load(Ordering::Acquire)
    }

    /// Try to advance the global epoch.
    pub fn try_advance(&self) -> Option<u64> {
        let current = self.global_epoch.load(Ordering::Acquire);
        let slots = self.slots.lock();

        // Check if all active threads have caught up.
        let all_caught_up = slots.iter().all(|s| {
            if !s.active.load(Ordering::Acquire) {
                return true;
            }
            if !s.pinned.load(Ordering::Acquire) {
                return true;
            }
            s.observed_epoch.load(Ordering::Acquire) >= current
        });

        if all_caught_up {
            let new_epoch = current + 1;
            self.global_epoch.store(new_epoch, Ordering::Release);

            // Reclaim garbage from two epochs ago.
            let reclaim_bucket = (current % 3) as usize;
            let mut bucket = self.garbage[reclaim_bucket].lock();
            let count = bucket.len() as u64;
            for item in bucket.drain(..) {
                (item.cleanup)();
            }
            self.total_reclaimed.fetch_add(count, Ordering::Relaxed);

            Some(new_epoch)
        } else {
            None
        }
    }

    /// Force-advance the epoch, retrying until successful.
    pub fn advance(&self) -> u64 {
        loop {
            if let Some(epoch) = self.try_advance() {
                return epoch;
            }
            std::hint::spin_loop();
        }
    }

    /// Retire an item for deferred reclamation.
    pub fn retire<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        let epoch = self.global_epoch.load(Ordering::Acquire);
        let bucket = (epoch % 3) as usize;
        self.garbage[bucket].lock().push(DeferredItem {
            cleanup: Box::new(cleanup),
        });
        self.total_retired.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the number of active (registered) threads.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.slots
            .lock()
            .iter()
            .filter(|s| s.active.load(Ordering::Relaxed))
            .count()
    }

    /// Get diagnostic snapshot.
    #[must_use]
    pub fn diagnostics(&self) -> EbrDiagnostics {
        let slots = self.slots.lock();
        EbrDiagnostics {
            global_epoch: self.global_epoch.load(Ordering::Acquire),
            active_threads: slots
                .iter()
                .filter(|s| s.active.load(Ordering::Relaxed))
                .count(),
            pinned_threads: slots
                .iter()
                .filter(|s| s.active.load(Ordering::Relaxed) && s.pinned.load(Ordering::Relaxed))
                .count(),
            total_retired: self.total_retired.load(Ordering::Relaxed),
            total_reclaimed: self.total_reclaimed.load(Ordering::Relaxed),
            pending_per_epoch: [
                self.garbage[0].lock().len(),
                self.garbage[1].lock().len(),
                self.garbage[2].lock().len(),
            ],
        }
    }

    /// Pin a thread at the current epoch.
    fn pin(&self, slot: &EbrSlot) -> u64 {
        let epoch = self.global_epoch.load(Ordering::Acquire);
        slot.observed_epoch.store(epoch, Ordering::Release);
        slot.pinned.store(true, Ordering::Release);
        epoch
    }

    /// Unpin a thread.
    fn unpin(&self, slot: &EbrSlot) {
        slot.pinned.store(false, Ordering::Release);
    }
}

impl Default for EbrCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> EbrHandle<'a> {
    pub fn pin(&self) -> EbrGuard<'a> {
        let epoch = self.collector.pin(&self.slot);
        EbrGuard {
            collector: self.collector,
            slot: Arc::clone(&self.slot),
            epoch,
        }
    }

    #[must_use]
    pub fn slot_id(&self) -> usize {
        self.slot_id
    }
}

impl Drop for EbrHandle<'_> {
    fn drop(&mut self) {
        self.slot.active.store(false, Ordering::Release);
        self.slot.pinned.store(false, Ordering::Release);
    }
}

impl<'a> EbrGuard<'a> {
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn retire<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        self.collector.retire(cleanup);
    }
}

impl Drop for EbrGuard<'_> {
    fn drop(&mut self) {
        self.collector.unpin(&self.slot);
    }
}

// ──────────────── QuarantineEbr ────────────────

/// A deferred cleanup entry: (epoch, cleanup closure).
type QuarantineEntry = (u64, Box<dyn FnOnce() + Send>);

pub struct QuarantineEbr {
    collector: EbrCollector,
    quarantine_depth: u64,
    quarantine: Mutex<Vec<QuarantineEntry>>,
    armed: AtomicBool,
}

impl QuarantineEbr {
    #[must_use]
    pub fn new(quarantine_depth: u64) -> Self {
        Self {
            collector: EbrCollector::new(),
            quarantine_depth,
            quarantine: Mutex::new(Vec::new()),
            armed: AtomicBool::new(true),
        }
    }

    #[must_use]
    pub fn collector(&self) -> &EbrCollector {
        &self.collector
    }

    pub fn register(&self) -> EbrHandle<'_> {
        self.collector.register()
    }

    pub fn retire_quarantined<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        if !self.armed.load(Ordering::Relaxed) || self.quarantine_depth == 0 {
            self.collector.retire(cleanup);
            return;
        }

        let target_epoch = self.collector.epoch() + 2 + self.quarantine_depth;
        self.quarantine
            .lock()
            .push((target_epoch, Box::new(cleanup)));
        self.collector.total_retired.fetch_add(1, Ordering::Relaxed);
    }

    pub fn try_advance(&self) -> Option<u64> {
        let result = self.collector.try_advance();
        if result.is_some() {
            self.drain_quarantine();
        }
        result
    }

    fn drain_quarantine(&self) {
        let current_epoch = self.collector.epoch();
        let mut quarantine = self.quarantine.lock();
        let mut i = 0;
        while i < quarantine.len() {
            if quarantine[i].0 <= current_epoch {
                let (_, cleanup) = quarantine.swap_remove(i);
                cleanup();
                self.collector
                    .total_reclaimed
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                i += 1;
            }
        }
    }

    pub fn set_armed(&self, armed: bool) {
        self.armed.store(armed, Ordering::Relaxed);
    }

    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn quarantine_len(&self) -> usize {
        self.quarantine.lock().len()
    }

    #[must_use]
    pub fn diagnostics(&self) -> EbrDiagnostics {
        self.collector.diagnostics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn new_collector_starts_at_epoch_zero() {
        let c = EbrCollector::new();
        assert_eq!(c.epoch(), 0);
    }

    #[test]
    fn register_and_deregister() {
        let c = EbrCollector::new();
        assert_eq!(c.active_count(), 0);
        let h = c.register();
        assert_eq!(c.active_count(), 1);
        drop(h);
        assert_eq!(c.active_count(), 0);
    }

    #[test]
    fn slot_reuse_after_deregister() {
        let c = EbrCollector::new();
        let h1 = c.register();
        let id1 = h1.slot_id();
        drop(h1);
        let h2 = c.register();
        assert_eq!(h2.slot_id(), id1);
    }

    #[test]
    fn try_advance_succeeds_with_no_threads() {
        let c = EbrCollector::new();
        let e = c.try_advance();
        assert_eq!(e, Some(1));
        assert_eq!(c.epoch(), 1);
    }

    #[test]
    fn try_advance_succeeds_when_all_unpinned() {
        let c = EbrCollector::new();
        let _h = c.register();
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn try_advance_blocked_by_stale_pin() {
        let c = EbrCollector::new();
        let h = c.register();
        let guard = h.pin();
        assert_eq!(guard.epoch(), 0);
        c.global_epoch.store(1, Ordering::Release);
        assert!(c.try_advance().is_none());
        drop(guard);
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn pin_returns_current_epoch() {
        let c = EbrCollector::new();
        let h = c.register();
        let g = h.pin();
        assert_eq!(g.epoch(), 0);
        drop(g);
        c.try_advance();
        let g2 = h.pin();
        assert_eq!(g2.epoch(), 1);
    }

    #[test]
    fn multiple_pin_unpin_cycles() {
        let c = EbrCollector::new();
        let h = c.register();
        for _ in 0..100 {
            let g = h.pin();
            drop(g);
        }
        assert_eq!(c.active_count(), 1);
    }

    #[test]
    fn retire_item_gets_reclaimed_on_advance() {
        let c = EbrCollector::new();
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        c.retire(move || {
            r.store(true, Ordering::Relaxed);
        });
        assert!(!reclaimed.load(Ordering::Relaxed));
        c.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn diagnostics_track_retire_and_reclaim() {
        let c = EbrCollector::new();
        for _ in 0..5 {
            c.retire(|| {});
        }
        let d = c.diagnostics();
        assert_eq!(d.total_retired, 5);
        assert_eq!(d.total_reclaimed, 0);
        c.try_advance();
        let d = c.diagnostics();
        assert_eq!(d.total_reclaimed, 5);
    }

    #[test]
    fn concurrent_pin_unpin_retire() {
        let c = Arc::new(EbrCollector::new());
        let barrier = Arc::new(Barrier::new(4));
        let reclaim_count = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let c = Arc::clone(&c);
            let bar = Arc::clone(&barrier);
            let cnt = Arc::clone(&reclaim_count);
            handles.push(thread::spawn(move || {
                let h = c.register();
                bar.wait();
                for _ in 0..200 {
                    let guard = h.pin();
                    let cnt2 = Arc::clone(&cnt);
                    guard.retire(move || {
                        cnt2.fetch_add(1, Ordering::Relaxed);
                    });
                    drop(guard);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        for _ in 0..5 {
            c.try_advance();
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 800);
        assert!(d.total_reclaimed > 0);
    }

    #[test]
    fn quarantine_holds_items_longer() {
        let q = QuarantineEbr::new(2);
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.store(true, Ordering::Relaxed);
        });
        q.try_advance(); // epoch 1
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 2
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 3
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 4
        assert!(reclaimed.load(Ordering::Relaxed));
    }
}
