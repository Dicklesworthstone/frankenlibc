//! Integration tests for Epoch-Based Reclamation (EBR).
//!
//! Covers: arena metadata reclamation, quarantine-based UAF detection,
//! concurrent retirement/reclamation, and interaction with pin/unpin guards.

use frankenlibc_membrane::ebr::{EbrCollector, QuarantineEbr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ──────────────── Arena metadata reclamation scenario ────────────────

#[derive(Debug)]
struct ArenaMetadata {
    generation: u64,
    _shard_id: u32,
    _slot_count: u32,
}

#[test]
fn arena_metadata_retired_on_rebalance() {
    let collector = EbrCollector::new();
    let reclaimed_gens = Arc::new(Mutex::new(Vec::new()));

    // Simulate rebalancing: retire old shard metadata.
    for generation in 0..5u64 {
        let meta = ArenaMetadata {
            generation,
            _shard_id: 0,
            _slot_count: 256,
        };
        let gens = Arc::clone(&reclaimed_gens);
        collector.retire(move || {
            gens.lock().push(meta.generation);
        });
    }

    // Advance past grace period.
    collector.try_advance();
    collector.try_advance();
    collector.try_advance();

    let reclaimed = reclaimed_gens.lock();
    assert_eq!(reclaimed.len(), 5, "all metadata should be reclaimed");
}

use parking_lot::Mutex;

// ──────────────── TLS cache invalidation pattern ────────────────

#[test]
fn tls_cache_entry_retired_safely() {
    let collector = Arc::new(EbrCollector::new());
    let reclaim_count = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(Barrier::new(5));

    // 4 reader threads pin while accessing cache entries.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = Arc::clone(&collector);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let h = c.register();
            bar.wait();
            for _ in 0..500 {
                let _guard = h.pin();
                // Simulate cache lookup while pinned.
                std::hint::black_box(42u64);
            }
        }));
    }

    // Writer thread retires stale cache entries.
    barrier.wait();
    for _ in 0..100 {
        let cnt = Arc::clone(&reclaim_count);
        collector.retire(move || {
            cnt.fetch_add(1, Ordering::Relaxed);
        });
    }

    for h in handles {
        h.join().expect("reader panicked");
    }

    // After all readers exit, advance to reclaim.
    for _ in 0..5 {
        collector.try_advance();
    }

    let d = collector.diagnostics();
    assert_eq!(d.total_retired, 100);
    assert!(d.total_reclaimed > 0);
}

// ──────────────── Quarantine UAF detection ────────────────

#[test]
fn quarantine_delays_reclamation_for_uaf_detection() {
    let q = QuarantineEbr::new(3); // 3 extra epochs
    let reclaimed = Arc::new(AtomicBool::new(false));
    let probe_alive = Arc::new(AtomicBool::new(true));

    // Retire an item through quarantine.
    let r = Arc::clone(&reclaimed);
    let p = Arc::clone(&probe_alive);
    q.retire_quarantined(move || {
        r.store(true, Ordering::Relaxed);
        p.store(false, Ordering::Relaxed);
    });

    // Simulate "UAF probe window": item should still be alive for several epochs.
    for epoch in 0..4 {
        q.try_advance();
        if epoch < 3 {
            assert!(
                probe_alive.load(Ordering::Relaxed),
                "item should still be in quarantine at epoch {}",
                epoch + 1
            );
        }
    }

    // After quarantine + grace period, item is reclaimed.
    q.try_advance();
    q.try_advance();
    assert!(reclaimed.load(Ordering::Relaxed));
}

#[test]
fn quarantine_batch_retirement() {
    let q = QuarantineEbr::new(2);
    let count = Arc::new(AtomicU64::new(0));

    // Retire 100 items.
    for _ in 0..100 {
        let cnt = Arc::clone(&count);
        q.retire_quarantined(move || {
            cnt.fetch_add(1, Ordering::Relaxed);
        });
    }

    assert_eq!(q.quarantine_len(), 100);

    // Not enough advances yet.
    q.try_advance();
    q.try_advance();
    assert!(count.load(Ordering::Relaxed) < 100);

    // Enough advances to drain all.
    for _ in 0..5 {
        q.try_advance();
    }
    assert_eq!(count.load(Ordering::Relaxed), 100);
    assert_eq!(q.quarantine_len(), 0);
}

// ──────────────── Multi-thread retirement stress ────────────────

#[test]
fn multi_thread_retire_and_advance() {
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(9));
    let reclaim_count = Arc::new(AtomicU64::new(0));

    // 8 threads each retiring 200 items.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = Arc::clone(&collector);
        let bar = Arc::clone(&barrier);
        let cnt = Arc::clone(&reclaim_count);
        handles.push(thread::spawn(move || {
            let h = c.register();
            bar.wait();
            for _ in 0..200 {
                let g = h.pin();
                let cnt2 = Arc::clone(&cnt);
                g.retire(move || {
                    cnt2.fetch_add(1, Ordering::Relaxed);
                });
                drop(g);
                // Periodically advance.
                c.try_advance();
            }
        }));
    }

    barrier.wait();
    for h in handles {
        h.join().expect("thread panicked");
    }

    // Final cleanup.
    for _ in 0..10 {
        collector.try_advance();
    }

    let d = collector.diagnostics();
    assert_eq!(d.total_retired, 1600);
    assert_eq!(d.active_threads, 0);
}

// ──────────────── Pin guard prevents premature reclaim ────────────────

#[test]
fn pinned_guard_delays_epoch_advance() {
    let collector = Arc::new(EbrCollector::new());

    let h1 = collector.register();
    let h2 = collector.register();

    // h1 pins at epoch 0.
    let guard1 = h1.pin();
    assert_eq!(guard1.epoch(), 0);

    // Retire an item at epoch 0.
    let reclaimed = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&reclaimed);
    collector.retire(move || {
        r.store(true, Ordering::Relaxed);
    });

    // h2 tries advance — should succeed (h1's observed_epoch == current).
    // In 3-epoch EBR, advancing from 0 to 1 reclaims bucket (0+1)%3 = 1.
    // Our item is in bucket (0%3) = 0.
    let _ = collector.try_advance().expect("advance 0->1");
    assert!(
        !reclaimed.load(Ordering::Relaxed),
        "should not reclaim bucket 0 yet"
    );

    // Advance 1->2 (needs everyone to have observed epoch 1).
    // But guard1 is pinned at epoch 0! 0 < 1, so this MUST FAIL.
    let advanced_blocked = collector.try_advance();
    assert!(
        advanced_blocked.is_none(),
        "advance 1->2 must be blocked by guard1 pinned at 0"
    );
    assert!(!reclaimed.load(Ordering::Relaxed));

    // Drop the guard.
    drop(guard1);

    // Now advance 1->2 should succeed.
    let _ = collector.try_advance().expect("advance 1->2");
    assert!(!reclaimed.load(Ordering::Relaxed));

    // Advance 2->3 (reclaims bucket 0).
    let _ = collector.try_advance().expect("advance 2->3");
    assert!(
        reclaimed.load(Ordering::Relaxed),
        "bucket 0 should now be reclaimed"
    );

    drop(h1);
    drop(h2);
}

// ──────────────── Quarantine arm/disarm toggle ────────────────

#[test]
fn quarantine_toggle_under_load() {
    let q = Arc::new(QuarantineEbr::new(3));
    let barrier = Arc::new(Barrier::new(3));
    let armed_count = Arc::new(AtomicU64::new(0));
    let disarmed_count = Arc::new(AtomicU64::new(0));

    // Thread 1: retires with quarantine armed.
    let q1 = Arc::clone(&q);
    let bar1 = Arc::clone(&barrier);
    let ac = Arc::clone(&armed_count);
    let t1 = thread::spawn(move || {
        bar1.wait();
        for _ in 0..100 {
            let cnt = Arc::clone(&ac);
            q1.retire_quarantined(move || {
                cnt.fetch_add(1, Ordering::Relaxed);
            });
        }
    });

    // Thread 2: disarms quarantine partway through.
    let q2 = Arc::clone(&q);
    let bar2 = Arc::clone(&barrier);
    let dc = Arc::clone(&disarmed_count);
    let t2 = thread::spawn(move || {
        bar2.wait();
        thread::yield_now();
        q2.set_armed(false);
        for _ in 0..100 {
            let cnt = Arc::clone(&dc);
            q2.retire_quarantined(move || {
                cnt.fetch_add(1, Ordering::Relaxed);
            });
        }
    });

    barrier.wait();
    t1.join().unwrap();
    t2.join().unwrap();

    // Advance enough to reclaim everything.
    for _ in 0..10 {
        q.try_advance();
    }

    let total = armed_count.load(Ordering::Relaxed) + disarmed_count.load(Ordering::Relaxed);
    assert_eq!(total, 200, "all 200 items should eventually be reclaimed");
}

// ──────────────── Diagnostics under mixed workload ────────────────

#[test]
fn diagnostics_consistent_after_mixed_workload() {
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(5));

    // 2 retire threads + 2 advance threads.
    let mut handles = Vec::new();

    for _ in 0..2 {
        let c = Arc::clone(&collector);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let h = c.register();
            bar.wait();
            for _ in 0..300 {
                let g = h.pin();
                g.retire(|| {});
                drop(g);
            }
        }));
    }

    for _ in 0..2 {
        let c = Arc::clone(&collector);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            bar.wait();
            for _ in 0..300 {
                c.try_advance();
            }
        }));
    }

    barrier.wait();
    for h in handles {
        h.join().unwrap();
    }

    // Final cleanup.
    for _ in 0..5 {
        collector.try_advance();
    }

    let d = collector.diagnostics();
    assert_eq!(d.total_retired, 600);
    assert!(
        d.total_reclaimed <= d.total_retired,
        "cannot reclaim more than retired"
    );
    assert_eq!(d.active_threads, 0);
}
