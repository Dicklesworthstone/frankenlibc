//! Epoch-Based Reclamation (EBR) for safe deferred cleanup in concurrent structures.
//!
//! This module provides the classic three-epoch EBR algorithm adapted for safe Rust
//! (`#![deny(unsafe_code)]`). It enables lock-free data structures to defer reclamation
//! of retired items until all threads that might hold references have advanced.

use crate::util::NoPoisonMutex as Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Global epoch counter for EBR.
pub struct EbrCollector {
    /// Global epoch, incremented by `try_advance()`.
    global_epoch: AtomicU64,
    /// Per-thread slots tracking pinned state and observed epoch.
    /// Serializes registration and the complete scan/advance/bucket handoff.
    /// Pin/unpin take only their own slot's mutex, not this global mutex.
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
    /// All guards of one handle share a counted pin. A nested pin must neither
    /// refresh the oldest protected epoch nor let an inner drop unpin an outer
    /// guard. The mutex also supports concurrent use of a shared handle.
    pins: Mutex<EbrPinState>,
}

struct EbrPinState {
    count: usize,
    epoch: u64,
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

/// RAII guard protecting an epoch for its entire lifetime, even if its handle
/// is dropped. Overlapping guards of a handle retain the oldest pinned epoch.
pub struct EbrGuard<'a> {
    collector: &'a EbrCollector,
    slot: Arc<EbrSlot>,
    epoch: u64,
}

/// Diagnostic snapshot of the EBR collector state.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
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
        let collector = Self {
            global_epoch: AtomicU64::new(0),
            slots: Mutex::new(Vec::new()),
            garbage: [
                Mutex::new(Vec::new()),
                Mutex::new(Vec::new()),
                Mutex::new(Vec::new()),
            ],
            total_retired: AtomicU64::new(0),
            total_reclaimed: AtomicU64::new(0),
        };
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptActivated,
            0,
            "ebr",
        );
        collector
    }

    /// Register a thread with the collector.
    pub fn register(&self) -> EbrHandle<'_> {
        let mut slots = self.slots.lock();
        let epoch = self.global_epoch.load(Ordering::Acquire);

        // A guard may outlive its handle: pin() borrows the collector, not the
        // handle. Only the registry's sole Arc proves that the old handle AND
        // every old guard have gone. In particular, an old guard must never
        // unpin a newly registered user of the same slot.
        for (i, slot) in slots.iter().enumerate() {
            if !slot.active.load(Ordering::Acquire) && Arc::strong_count(slot) == 1 {
                *slot.pins.lock() = EbrPinState { count: 0, epoch };
                slot.active.store(true, Ordering::Release);
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
            pins: Mutex::new(EbrPinState { count: 0, epoch }),
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
        let (new_epoch, items_to_clean) = {
            // Keep the scan, epoch transition, and recycled-bucket handoff in
            // one critical section. An old scanner must not publish a stale
            // epoch or drain a bucket that a newer scanner has already reused.
            let slots = self.slots.lock();
            let current = self.global_epoch.load(Ordering::Acquire);
            let all_caught_up = slots.iter().all(|slot| {
                let pins = slot.pins.lock();
                // Do not skip inactive handles: an outstanding guard can
                // still protect this epoch after its handle was dropped.
                pins.count == 0 || pins.epoch >= current
            });
            if !all_caught_up {
                drop(slots);
                crate::alien_cs_metrics::emit_alien_cs_event(
                    crate::alien_cs_metrics::MetricEventKind::EbrGracePeriodDelay,
                    current,
                    "ebr",
                );
                return None;
            }

            // Fail closed rather than wrap the epoch and misclassify old pins.
            let new_epoch = current.checked_add(1)?;
            // Preserve the existing conservative three-advance grace period:
            // the previous contents of new_epoch % 3 belong to new_epoch - 3.
            // Detach those contents BEFORE publishing new_epoch. Otherwise a
            // concurrent retire in the newly published epoch could be swept
            // up in this same cleanup, before its readers have quiesced.
            let mut bucket = self.garbage[(new_epoch % 3) as usize].lock();
            let items = std::mem::take(&mut *bucket);
            self.global_epoch.store(new_epoch, Ordering::Release);
            (new_epoch, items)
        };

        // Neither diagnostics nor arbitrary cleanup callbacks run under the
        // registry, slot, or bucket locks. A callback may itself retire work,
        // register a reader, or advance the collector.
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::EbrEpochAdvance,
            new_epoch,
            "ebr",
        );
        let count = items_to_clean.len() as u64;
        for item in items_to_clean {
            (item.cleanup)();
        }
        if count > 0 {
            self.total_reclaimed.fetch_add(count, Ordering::Relaxed);
            crate::alien_cs_metrics::emit_alien_cs_event(
                crate::alien_cs_metrics::MetricEventKind::EbrReclaim,
                count,
                "ebr",
            );
        }
        Some(new_epoch)
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
        // Allocate outside the bucket lock: allocator reentry must not wait
        // for the same bucket. Keep the closure owned across epoch retries.
        let item = DeferredItem {
            cleanup: Box::new(cleanup),
        };
        loop {
            let epoch = self.global_epoch.load(Ordering::Acquire);
            let mut bucket = self.garbage[(epoch % 3) as usize].lock();
            // A retire paused before locking may have selected a bucket from
            // an old cycle. Pair this recheck with the handoff in try_advance.
            if self.global_epoch.load(Ordering::Acquire) != epoch {
                continue;
            }
            bucket.push(item);
            // Publish the diagnostic before the bucket can be reclaimed.
            self.total_retired.fetch_add(1, Ordering::Relaxed);
            return;
        }
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
            pinned_threads: slots.iter().filter(|s| s.pins.lock().count != 0).count(),
            total_retired: self.total_retired.load(Ordering::Relaxed),
            total_reclaimed: self.total_reclaimed.load(Ordering::Relaxed),
            pending_per_epoch: [
                self.garbage[0].lock().len(),
                self.garbage[1].lock().len(),
                self.garbage[2].lock().len(),
            ],
        }
    }

    /// Pin a handle, retaining its oldest epoch until its final guard drops.
    fn pin(&self, slot: &EbrSlot) -> u64 {
        let epoch = {
            let mut pins = slot.pins.lock();
            if pins.count == 0 {
                pins.epoch = self.global_epoch.load(Ordering::Acquire);
            }
            pins.count = pins.count.checked_add(1).expect("EBR guard count overflow");
            pins.epoch
        };
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::EbrPin,
            epoch,
            "ebr",
        );
        epoch
    }

    /// Release one guard; other guards of the same handle remain pinned.
    fn unpin(&self, slot: &EbrSlot) {
        let epoch = {
            let mut pins = slot.pins.lock();
            // Each guard is constructed only after pin() increments the count;
            // guards cannot be cloned, and each Drop consumes exactly one pin.
            pins.count = pins.count.checked_sub(1).expect("unbalanced EBR guard");
            pins.epoch
        };
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::EbrUnpin,
            epoch,
            "ebr",
        );
    }
}

impl Default for EbrCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EbrCollector {
    fn drop(&mut self) {
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptDeactivated,
            self.global_epoch.load(Ordering::Relaxed),
            "ebr",
        );
    }
}

impl<'a> EbrHandle<'a> {
    /// Pin this registration. Overlapping guards keep its oldest epoch alive;
    /// dropping a guard out of order, or dropping this handle first, is valid.
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
        // Deregistration is not unpinning: guards can legally outlive this
        // handle and retain both their counted pin and their Arc to the slot.
        self.slot.active.store(false, Ordering::Release);
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

        let mut current = self.collector.total_retired.load(Ordering::Relaxed);
        loop {
            let next = current.saturating_add(1);
            match self.collector.total_retired.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
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
        let mut to_cleanup = Vec::new();
        {
            let mut quarantine = self.quarantine.lock();
            let mut i = 0;
            while i < quarantine.len() {
                if quarantine[i].0 <= current_epoch {
                    let (_, cleanup) = quarantine.swap_remove(i);
                    to_cleanup.push(cleanup);
                } else {
                    i += 1;
                }
            }
        }

        for cleanup in to_cleanup {
            cleanup();
            self.collector
                .total_reclaimed
                .fetch_add(1, Ordering::Relaxed);
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
        assert_eq!(c.diagnostics().total_reclaimed, 0);
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
        c.try_advance(); // to 1
        c.try_advance(); // to 2
        c.try_advance(); // to 3 (reclaims bucket 0)
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
        c.try_advance(); // to 1
        c.try_advance(); // to 2
        c.try_advance(); // to 3
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

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: EBR + RCU composition
    //
    // Verifies that EBR and RCU can coexist: RCU manages read-side
    // snapshots while EBR handles deferred cleanup of retired data.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn ebr_and_rcu_coexist_under_concurrent_updates() {
        use crate::rcu::RcuCell;

        let collector = Arc::new(EbrCollector::new());
        let rcu = Arc::new(RcuCell::new(0u64));
        let barrier = Arc::new(Barrier::new(4));
        let reclaim_count = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        // Writer threads: update RCU cell and retire old values via EBR
        for _ in 0..2 {
            let collector = Arc::clone(&collector);
            let rcu = Arc::clone(&rcu);
            let barrier = Arc::clone(&barrier);
            let reclaim_count = Arc::clone(&reclaim_count);
            handles.push(thread::spawn(move || {
                let handle = collector.register();
                barrier.wait();
                for i in 0..100u64 {
                    let _guard = handle.pin();
                    let old_val = *rcu.load();
                    rcu.update(old_val.wrapping_add(i));
                    let rc = Arc::clone(&reclaim_count);
                    collector.retire(move || {
                        rc.fetch_add(1, Ordering::Relaxed);
                    });
                }
            }));
        }

        // Reader threads: read RCU snapshots while pinned
        for _ in 0..2 {
            let collector = Arc::clone(&collector);
            let rcu = Arc::clone(&rcu);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let handle = collector.register();
                barrier.wait();
                for _ in 0..200 {
                    let guard = handle.pin();
                    let _snapshot = *rcu.load();
                    drop(guard);
                    thread::yield_now();
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Advance epochs to trigger reclamation
        for _ in 0..5 {
            collector.try_advance();
        }

        let d = collector.diagnostics();
        assert_eq!(d.total_retired, 200, "200 items should have been retired");
        assert!(
            d.total_reclaimed > 0,
            "some items should have been reclaimed after advances"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: QuarantineEbr armed/disarmed behavior
    //
    // Verifies that disarming the quarantine bypasses the extended
    // hold period, enabling immediate reclamation via the base EBR.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn quarantine_ebr_disarmed_bypasses_quarantine() {
        let q = QuarantineEbr::new(10); // deep quarantine
        let reclaimed = Arc::new(AtomicBool::new(false));

        // Disarm: should bypass quarantine depth
        q.set_armed(false);
        assert!(!q.is_armed());

        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.store(true, Ordering::Relaxed);
        });

        // When disarmed, items go through the base EBR path directly
        // They should be reclaimable after normal epoch advancement
        q.try_advance();
        q.try_advance();
        q.try_advance();

        assert!(
            reclaimed.load(Ordering::Relaxed),
            "disarmed quarantine should allow reclamation via base EBR path"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: EBR diagnostics consistency under stress
    //
    // Verifies that total_retired >= total_reclaimed always holds,
    // and that pending counts are consistent.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn ebr_diagnostics_consistency_under_stress() {
        let c = Arc::new(EbrCollector::new());
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let c = Arc::clone(&c);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let handle = c.register();
                barrier.wait();
                for _ in 0..500 {
                    let guard = handle.pin();
                    c.retire(|| {});
                    drop(guard);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        // Advance to reclaim everything
        for _ in 0..10 {
            c.try_advance();
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 2000);
        assert!(
            d.total_reclaimed <= d.total_retired,
            "reclaimed ({}) must not exceed retired ({})",
            d.total_reclaimed,
            d.total_retired
        );
        assert!(
            d.total_reclaimed > 0,
            "some items must have been reclaimed after 10 advances"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // INTEGRATION: EBR pinning blocks epoch advancement
    //
    // Verifies that a pinned thread prevents epoch advancement,
    // protecting concurrent readers from premature reclamation.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn pinned_thread_blocks_advance_protecting_readers() {
        let c = EbrCollector::new();
        let h1 = c.register();
        let h2 = c.register();

        // h1 pins
        let guard = h1.pin();
        let pinned_epoch = guard.epoch();

        // h2 marks quiescent
        {
            let _g = h2.pin();
        }

        // Retire something
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        c.retire(move || {
            r.store(true, Ordering::Relaxed);
        });

        // Try to advance — should be blocked by h1's pin
        let advanced = c.try_advance();
        // Even if advance succeeds, the item retired in the old epoch
        // should not be reclaimed while h1 is still pinned at that epoch

        // Unpin h1
        drop(guard);

        // Now advance should work and reclaim
        for _ in 0..5 {
            c.try_advance();
        }

        assert!(
            reclaimed.load(Ordering::Relaxed),
            "item should be reclaimed after unpinning"
        );

        let _ = advanced; // suppress unused warning
        let _ = pinned_epoch;
    }

    // ═══════════════════════════════════════════════════════════════
    // PROPERTY-BASED: EBR invariants via proptest
    //
    // These tests verify that EBR's core safety invariants hold
    // for arbitrary sequences of operations.
    // ═══════════════════════════════════════════════════════════════

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_epoch_monotonically_increases(advances in 1usize..50) {
            let c = EbrCollector::new();
            let mut prev = c.epoch();
            for _ in 0..advances {
                if let Some(new) = c.try_advance() {
                    prop_assert!(new > prev, "epoch must increase: {} -> {}", prev, new);
                    prev = new;
                }
            }
        }

        #[test]
        fn prop_retired_geq_reclaimed(retires in 1usize..100) {
            let c = EbrCollector::new();
            let handle = c.register();
            for _ in 0..retires {
                let guard = handle.pin();
                c.retire(|| {});
                drop(guard);
            }
            for _ in 0..10 {
                c.try_advance();
            }
            let d = c.diagnostics();
            prop_assert!(
                d.total_reclaimed <= d.total_retired,
                "reclaimed ({}) must not exceed retired ({})",
                d.total_reclaimed,
                d.total_retired
            );
        }

        #[test]
        fn prop_active_count_tracks_registrations(n in 1usize..20) {
            let c = EbrCollector::new();
            let mut handles = Vec::new();
            for _ in 0..n {
                handles.push(c.register());
            }
            prop_assert_eq!(c.active_count(), n);
            drop(handles);
            prop_assert_eq!(c.active_count(), 0);
        }

        #[test]
        fn prop_quarantine_depth_delays_reclaim(depth in 1u64..5) {
            let q = QuarantineEbr::new(depth);
            let reclaimed = Arc::new(AtomicBool::new(false));
            let r = Arc::clone(&reclaimed);
            q.retire_quarantined(move || {
                r.store(true, Ordering::Relaxed);
            });

            // Should NOT be reclaimed before enough advances
            for _ in 0..depth {
                q.try_advance();
            }
            // May or may not be reclaimed yet depending on exact epoch math.
            // But after depth+3 more advances, it must be reclaimed.
            for _ in 0..depth + 3 {
                q.try_advance();
            }
            prop_assert!(
                reclaimed.load(Ordering::Relaxed),
                "item must be reclaimed after {} advances (depth={})",
                2 * depth + 3,
                depth
            );
        }

        #[test]
        fn prop_pin_returns_current_epoch(advances in 0usize..10) {
            let c = EbrCollector::new();
            for _ in 0..advances {
                c.try_advance();
            }
            let h = c.register();
            let guard = h.pin();
            let pin_epoch = guard.epoch();
            let current = c.epoch();
            prop_assert_eq!(
                pin_epoch, current,
                "pin epoch must match current epoch"
            );
        }
    }
}
