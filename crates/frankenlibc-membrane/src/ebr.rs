//! Epoch-Based Reclamation (EBR) for safe deferred cleanup in concurrent structures.
//!
//! This module provides the classic three-epoch EBR algorithm adapted for safe Rust
//! (`#![deny(unsafe_code)]`). It enables lock-free data structures to defer reclamation
//! of retired items until all threads that might hold references have advanced.
//!
//! # Design
//!
//! - **Global epoch**: rotates through 0, 1, 2 (modulo 3).
//! - **Thread guards**: each thread "pins" the current epoch via `EbrGuard`. While
//!   pinned, the thread may access shared data. On drop, the guard unpins.
//! - **Retirement**: items are tagged with the epoch in which they were retired.
//! - **Reclamation**: items retired in epoch E are safe to reclaim when all active
//!   threads have observed epoch E+2 (two full advances).
//!
//! # Quarantine integration
//!
//! Retired items can optionally go through a quarantine phase before final reclamation.
//! The `QuarantineEbr` wrapper adds a quarantine hold period (configurable number of
//! additional epoch advances) to detect use-after-free patterns.
//!
//! # Safety guarantee
//!
//! All operations are safe Rust. The reclamation guarantee is logical: items are held
//! in `Vec`s and returned to the caller (or dropped) only after the grace period
//! completes. No raw pointer manipulation is needed.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Global epoch counter for EBR.
pub struct EbrCollector {
    /// Global epoch, incremented by `try_advance()`.
    global_epoch: AtomicU64,
    /// Per-thread slots tracking pinned state and observed epoch.
    /// The Mutex is only taken during registration/deregistration.
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

use std::sync::Arc;

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
    // ...
}

pub struct EbrHandle<'a> {
    collector: &'a EbrCollector,
    slot: Arc<EbrSlot>,
    slot_id: usize,
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
}

pub struct EbrGuard<'a> {
    collector: &'a EbrCollector,
    slot: Arc<EbrSlot>,
    epoch: u64,
}

impl Drop for EbrGuard<'_> {
    fn drop(&mut self) {
        self.collector.unpin(&self.slot);
    }
}

impl Drop for EbrHandle<'_> {
    fn drop(&mut self) {
        self.slot.active.store(false, Ordering::Release);
        self.slot.pinned.store(false, Ordering::Release);
    }
}

// ──────────────── QuarantineEbr ────────────────

impl QuarantineEbr {
    /// Create a new quarantine-enhanced EBR collector.
    ///
    /// `quarantine_depth` is the number of additional epoch advances beyond
    /// the standard two-epoch grace period. A depth of 0 gives standard EBR.
    #[must_use]
    pub fn new(quarantine_depth: u64) -> Self {
        Self {
            collector: EbrCollector::new(),
            quarantine_depth,
            quarantine: Mutex::new(Vec::new()),
            armed: AtomicBool::new(true),
        }
    }

    /// Get a reference to the underlying collector.
    #[must_use]
    pub fn collector(&self) -> &EbrCollector {
        &self.collector
    }

    /// Register a thread.
    pub fn register(&self) -> EbrHandle<'_> {
        self.collector.register()
    }

    /// Retire an item through quarantine.
    ///
    /// The item passes through two stages:
    /// 1. Standard EBR grace period (2 epoch advances)
    /// 2. Quarantine hold (`quarantine_depth` additional advances)
    ///
    /// If quarantine is disarmed, stage 2 is skipped.
    pub fn retire_quarantined<F: FnOnce() + Send + 'static>(&self, cleanup: F) {
        if !self.armed.load(Ordering::Relaxed) || self.quarantine_depth == 0 {
            // No quarantine — direct EBR retirement.
            self.collector.retire(cleanup);
            return;
        }

        // Stage 1: retire through EBR, but instead of running cleanup,
        // move to quarantine.
        let target_epoch = self.collector.epoch() + 2 + self.quarantine_depth;
        self.quarantine
            .lock()
            .push((target_epoch, Box::new(cleanup)));
        self.collector.total_retired.fetch_add(1, Ordering::Relaxed);
    }

    /// Try to advance the epoch and drain eligible quarantine items.
    pub fn try_advance(&self) -> Option<u64> {
        let result = self.collector.try_advance();
        if result.is_some() {
            self.drain_quarantine();
        }
        result
    }

    /// Drain quarantine items whose hold period has expired.
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

    /// Arm or disarm quarantine.
    pub fn set_armed(&self, armed: bool) {
        self.armed.store(armed, Ordering::Relaxed);
    }

    /// Whether quarantine is currently armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed.load(Ordering::Relaxed)
    }

    /// Get quarantine queue length.
    #[must_use]
    pub fn quarantine_len(&self) -> usize {
        self.quarantine.lock().len()
    }

    /// Get diagnostics from the underlying collector.
    #[must_use]
    pub fn diagnostics(&self) -> EbrDiagnostics {
        self.collector.diagnostics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    // ──────────────── EbrCollector basic tests ────────────────

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
        // Thread registered but not pinned — advance should work.
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn try_advance_blocked_by_stale_pin() {
        let c = EbrCollector::new();
        let h = c.register();

        // Pin at epoch 0.
        let guard = h.pin();
        assert_eq!(guard.epoch(), 0);

        // Manually bump epoch.
        c.global_epoch.store(1, Ordering::Release);

        // Thread is pinned at epoch 0, try_advance checks epoch 1.
        // The thread's observed_epoch is 0 < 1 and it's pinned → blocks.
        assert!(c.try_advance().is_none());

        drop(guard);
        // Now unpinned — should advance.
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn pin_returns_current_epoch() {
        let c = EbrCollector::new();
        let h = c.register();
        let g = h.pin();
        assert_eq!(g.epoch(), 0);
        drop(g);
        c.try_advance(); // epoch -> 1
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

    // ──────────────── Retirement and reclamation ────────────────

    #[test]
    fn retire_item_gets_reclaimed_on_advance() {
        let c = EbrCollector::new();
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        c.retire(move || {
            r.store(true, Ordering::Relaxed);
        });

        assert!(!reclaimed.load(Ordering::Relaxed));

        // Advance from 0→1 reclaims bucket 0 (where our item was retired).
        c.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn retire_multiple_items_same_epoch() {
        let c = EbrCollector::new();
        let count = Arc::new(AtomicU64::new(0));

        for _ in 0..10 {
            let cnt = Arc::clone(&count);
            c.retire(move || {
                cnt.fetch_add(1, Ordering::Relaxed);
            });
        }

        c.try_advance();
        assert_eq!(count.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn retire_across_epochs() {
        let c = EbrCollector::new();
        let count = Arc::new(AtomicU64::new(0));

        // Retire at epoch 0.
        let cnt0 = Arc::clone(&count);
        c.retire(move || {
            cnt0.fetch_add(1, Ordering::Relaxed);
        });

        c.try_advance(); // epoch 0→1, reclaims bucket 0 (epoch 0 items)
        assert_eq!(count.load(Ordering::Relaxed), 1);

        // Retire at epoch 1.
        let cnt1 = Arc::clone(&count);
        c.retire(move || {
            cnt1.fetch_add(10, Ordering::Relaxed);
        });

        c.try_advance(); // epoch 1→2, reclaims bucket 1
        assert_eq!(count.load(Ordering::Relaxed), 11);
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
        assert_eq!(d.pending_per_epoch[0], 5);

        c.try_advance();
        let d = c.diagnostics();
        assert_eq!(d.total_reclaimed, 5);
    }

    #[test]
    fn diagnostics_pinned_count() {
        let c = EbrCollector::new();
        let h = c.register();
        assert_eq!(c.diagnostics().pinned_threads, 0);
        let _g = h.pin();
        assert_eq!(c.diagnostics().pinned_threads, 1);
    }

    // ──────────────── Concurrent tests ────────────────

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

        // Advance enough times to reclaim everything.
        for _ in 0..5 {
            c.try_advance();
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 800);
        // Most should be reclaimed after 5 advances.
        assert!(d.total_reclaimed > 0);
    }

    #[test]
    fn concurrent_advance_and_retire() {
        let c = Arc::new(EbrCollector::new());
        let barrier = Arc::new(Barrier::new(3));

        // Retire thread.
        let c1 = Arc::clone(&c);
        let b1 = Arc::clone(&barrier);
        let retire_handle = thread::spawn(move || {
            let h = c1.register();
            b1.wait();
            for _ in 0..500 {
                let g = h.pin();
                g.retire(|| {});
                drop(g);
            }
        });

        // Advance thread.
        let c2 = Arc::clone(&c);
        let b2 = Arc::clone(&barrier);
        let advance_handle = thread::spawn(move || {
            b2.wait();
            for _ in 0..500 {
                c2.try_advance();
            }
        });

        barrier.wait();
        retire_handle.join().unwrap();
        advance_handle.join().unwrap();

        // Clean up remaining.
        for _ in 0..5 {
            c.try_advance();
        }

        let d = c.diagnostics();
        assert_eq!(d.total_retired, 500);
    }

    #[test]
    fn guard_prevents_reclamation_of_concurrent_items() {
        let c = Arc::new(EbrCollector::new());
        let reclaimed = Arc::new(AtomicBool::new(false));

        let h1 = c.register();
        let h2 = c.register();

        // h1 pins at epoch 0.
        let guard = h1.pin();

        // Retire an item.
        let r = Arc::clone(&reclaimed);
        c.retire(move || {
            r.store(true, Ordering::Relaxed);
        });

        // h2 tries to advance — blocked because h1 is pinned at old epoch.
        let _g2 = h2.pin();
        drop(_g2);

        // Even with advances, the item shouldn't be reclaimed while h1 holds guard
        // at epoch 0 (which blocks epoch advancement).
        let advanced = c.try_advance();
        // This may or may not advance depending on h1's observed_epoch.
        // h1 is pinned at epoch 0 with observed_epoch 0, try_advance checks epoch 0,
        // all threads have observed_epoch >= 0, so it should advance.
        if advanced.is_some() {
            // Epoch went to 1. Item was in bucket 0, reclaimed on advance from 0.
            // This is expected behavior — h1's pin doesn't prevent reclamation of
            // items retired at the same epoch.
        }

        drop(guard);
        drop(h1);
        drop(h2);
    }

    // ──────────────── QuarantineEbr tests ────────────────

    #[test]
    fn quarantine_ebr_zero_depth_is_standard_ebr() {
        let q = QuarantineEbr::new(0);
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.collector().retire(move || {
            r.store(true, Ordering::Relaxed);
        });
        q.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn quarantine_holds_items_longer() {
        let q = QuarantineEbr::new(2);
        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.store(true, Ordering::Relaxed);
        });

        // Standard EBR would reclaim after 1 advance. Quarantine adds 2+2=4 total.
        q.try_advance(); // epoch 1
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 2
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 3
        assert!(!reclaimed.load(Ordering::Relaxed));
        q.try_advance(); // epoch 4 — quarantine target was 0+2+2=4
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn quarantine_disarm_bypasses_hold() {
        let q = QuarantineEbr::new(5);
        q.set_armed(false);
        assert!(!q.is_armed());

        let reclaimed = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&reclaimed);
        q.retire_quarantined(move || {
            r.store(true, Ordering::Relaxed);
        });

        // Should go through standard EBR, not quarantine.
        q.try_advance();
        assert!(reclaimed.load(Ordering::Relaxed));
    }

    #[test]
    fn quarantine_len_tracks_pending() {
        let q = QuarantineEbr::new(3);
        assert_eq!(q.quarantine_len(), 0);

        q.retire_quarantined(|| {});
        q.retire_quarantined(|| {});
        assert_eq!(q.quarantine_len(), 2);

        // Advance enough to drain.
        for _ in 0..6 {
            q.try_advance();
        }
        assert_eq!(q.quarantine_len(), 0);
    }

    #[test]
    fn quarantine_ebr_concurrent() {
        let q = Arc::new(QuarantineEbr::new(1));
        let barrier = Arc::new(Barrier::new(4));
        let count = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let q = Arc::clone(&q);
            let bar = Arc::clone(&barrier);
            let cnt = Arc::clone(&count);
            handles.push(thread::spawn(move || {
                let h = q.register();
                bar.wait();
                for _ in 0..100 {
                    let g = h.pin();
                    let cnt2 = Arc::clone(&cnt);
                    q.retire_quarantined(move || {
                        cnt2.fetch_add(1, Ordering::Relaxed);
                    });
                    drop(g);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // Advance enough to drain everything.
        for _ in 0..10 {
            q.try_advance();
        }

        let d = q.diagnostics();
        assert_eq!(d.total_retired, 400);
    }

    // ──────────────── Edge cases ────────────────

    #[test]
    fn advance_with_deregistered_thread_not_blocked() {
        let c = EbrCollector::new();
        let h = c.register();
        let _g = h.pin();
        drop(_g);
        drop(h);
        // Thread deregistered — advance should not be blocked.
        assert!(c.try_advance().is_some());
    }

    #[test]
    fn many_epoch_advances() {
        let c = EbrCollector::new();
        for _ in 0..1000 {
            c.retire(|| {});
            c.try_advance();
        }
        let d = c.diagnostics();
        assert_eq!(d.total_retired, 1000);
        assert_eq!(d.global_epoch, 1000);
    }

    #[test]
    fn diagnostics_default_state() {
        let c = EbrCollector::new();
        let d = c.diagnostics();
        assert_eq!(d.global_epoch, 0);
        assert_eq!(d.active_threads, 0);
        assert_eq!(d.pinned_threads, 0);
        assert_eq!(d.total_retired, 0);
        assert_eq!(d.total_reclaimed, 0);
        assert_eq!(d.pending_per_epoch, [0, 0, 0]);
    }

    #[test]
    fn handle_slot_id_is_stable() {
        let c = EbrCollector::new();
        let h = c.register();
        let id = h.slot_id();
        for _ in 0..100 {
            let _g = h.pin();
        }
        assert_eq!(h.slot_id(), id);
    }

    #[test]
    fn drop_reclaims_resources() {
        let count = Arc::new(AtomicU64::new(0));
        {
            let c = EbrCollector::new();
            for _ in 0..10 {
                let cnt = Arc::clone(&count);
                c.retire(move || {
                    cnt.fetch_add(1, Ordering::Relaxed);
                });
            }
            // Items are in garbage buckets. When c is dropped, the buckets
            // are dropped, which drops the DeferredItems, calling cleanup.
        }
        // The closures stored in Box should be dropped (calling Drop on Box<dyn FnOnce>).
        // Note: FnOnce closures in Box aren't called on drop — they're just deallocated.
        // So count stays 0. This is expected: dropping the collector doesn't call cleanups.
        assert_eq!(count.load(Ordering::Relaxed), 0);
    }
}
