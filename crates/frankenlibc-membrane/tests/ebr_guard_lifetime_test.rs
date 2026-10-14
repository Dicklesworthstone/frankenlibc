//! Regression coverage for counted guards, slot lifetime, and epoch handoff.
//! These tests use the real collector, not a replacement allocator or mock.

use frankenlibc_membrane::ebr::{EbrCollector, QuarantineEbr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

fn retire_flag(collector: &EbrCollector) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let retired = Arc::clone(&flag);
    collector.retire(move || retired.store(true, Ordering::Release));
    flag
}

fn drain(collector: &EbrCollector) {
    for _ in 0..8 {
        let _ = collector.try_advance();
    }
}

#[test]
fn nested_guard_drop_keeps_outer_pin() {
    let collector = EbrCollector::new();
    let handle = collector.register();
    let outer = handle.pin();
    let reclaimed = retire_flag(&collector);
    drop(handle.pin());

    drain(&collector);
    assert!(!reclaimed.load(Ordering::Acquire));
    assert_eq!(collector.diagnostics().pinned_threads, 1);
    drop(outer);
    drain(&collector);
    assert!(reclaimed.load(Ordering::Acquire));
}

#[test]
fn nested_pin_does_not_refresh_the_oldest_protected_epoch() {
    let collector = EbrCollector::new();
    let handle = collector.register();
    let outer = handle.pin();
    assert_eq!(collector.try_advance(), Some(1));
    let inner = handle.pin();
    assert_eq!(inner.epoch(), outer.epoch());
    assert_eq!(collector.try_advance(), None);
    drop(inner);
    assert_eq!(collector.try_advance(), None);
    drop(outer);
    assert_eq!(collector.try_advance(), Some(2));
}

#[test]
fn out_of_order_guard_drop_keeps_the_last_guard_pinned() {
    let collector = EbrCollector::new();
    let handle = collector.register();
    let first = handle.pin();
    let second = handle.pin();
    let reclaimed = retire_flag(&collector);
    drop(first);
    drain(&collector);
    assert!(!reclaimed.load(Ordering::Acquire));
    drop(second);
    drain(&collector);
    assert!(reclaimed.load(Ordering::Acquire));
}

#[test]
fn guard_outliving_handle_still_blocks_reclamation() {
    let collector = EbrCollector::new();
    let handle = collector.register();
    let guard = handle.pin();
    let reclaimed = retire_flag(&collector);
    drop(handle);
    assert_eq!(collector.active_count(), 0);
    assert_eq!(collector.diagnostics().pinned_threads, 1);
    drain(&collector);
    assert!(!reclaimed.load(Ordering::Acquire));
    drop(guard);
    drain(&collector);
    assert!(reclaimed.load(Ordering::Acquire));
}

#[test]
fn registration_never_reuses_a_slot_with_an_outstanding_guard() {
    let collector = EbrCollector::new();
    let first = collector.register();
    let first_id = first.slot_id();
    let old_guard = first.pin();
    drop(first);

    let second = collector.register();
    assert_ne!(second.slot_id(), first_id);
    let new_guard = second.pin();
    drop(old_guard);
    let reclaimed = retire_flag(&collector);
    drain(&collector);
    assert!(!reclaimed.load(Ordering::Acquire));
    drop(new_guard);
    drain(&collector);
    assert!(reclaimed.load(Ordering::Acquire));

    // The finished registration's slot remains reusable, not leaked.
    let third = collector.register();
    assert_eq!(third.slot_id(), first_id);
}

#[test]
fn shared_handle_pin_on_another_thread_preserves_outer_guard() {
    let collector = EbrCollector::new();
    let handle = collector.register();
    let outer = handle.pin();
    let reclaimed = retire_flag(&collector);
    assert_eq!(collector.try_advance(), Some(1));
    thread::scope(|scope| {
        scope
            .spawn(|| drop(handle.pin()))
            .join()
            .expect("pin worker");
    });
    drain(&collector);
    assert!(!reclaimed.load(Ordering::Acquire));
    drop(outer);
    drain(&collector);
    assert!(reclaimed.load(Ordering::Acquire));
}

#[test]
fn quarantine_honors_a_guard_after_its_handle_is_dropped() {
    let quarantine = QuarantineEbr::new(4);
    let handle = quarantine.register();
    let guard = handle.pin();
    let flag = Arc::new(AtomicBool::new(false));
    let retired = Arc::clone(&flag);
    quarantine.retire_quarantined(move || retired.store(true, Ordering::Release));
    drop(handle);
    for _ in 0..16 {
        let _ = quarantine.try_advance();
    }
    assert!(!flag.load(Ordering::Acquire));
    drop(guard);
    for _ in 0..16 {
        let _ = quarantine.try_advance();
    }
    assert!(flag.load(Ordering::Acquire));
}

#[test]
fn concurrent_advancers_publish_distinct_epochs() {
    const THREADS: usize = 8;
    const ADVANCES: usize = 200;
    let collector = Arc::new(EbrCollector::new());
    let start = Arc::new(Barrier::new(THREADS));
    let workers: Vec<_> = (0..THREADS)
        .map(|_| {
            let collector = Arc::clone(&collector);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                (0..ADVANCES)
                    .map(|_| collector.try_advance().expect("no pinned readers"))
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let mut epochs = Vec::new();
    for worker in workers {
        epochs.extend(worker.join().expect("advance worker"));
    }
    epochs.sort_unstable();
    assert_eq!(
        epochs,
        (1..=(THREADS * ADVANCES) as u64).collect::<Vec<_>>()
    );
    assert_eq!(collector.epoch(), (THREADS * ADVANCES) as u64);
}

#[test]
fn cleanup_may_register_pin_and_retire_without_holding_collector_locks() {
    let collector = Arc::new(EbrCollector::new());
    let callback_collector = Arc::clone(&collector);
    let completed = Arc::new(AtomicBool::new(false));
    let second_cleanup = Arc::clone(&completed);
    collector.retire(move || {
        let handle = callback_collector.register();
        let guard = handle.pin();
        callback_collector.retire(move || second_cleanup.store(true, Ordering::Release));
        drop(handle);
        drop(guard);
    });

    let (done_tx, done_rx) = mpsc::channel();
    let worker_collector = Arc::clone(&collector);
    let worker = thread::spawn(move || {
        drain(&worker_collector);
        done_tx.send(()).expect("test receiver");
    });
    // A regression holding a lock through the callback fails instead of
    // indefinitely blocking the whole integration-test binary.
    done_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("reentrant cleanup blocked");
    worker.join().expect("cleanup worker");
    assert!(completed.load(Ordering::Acquire));
}

#[test]
fn a_detached_cleanup_batch_cannot_sweep_new_retirements() {
    let collector = Arc::new(EbrCollector::new());
    let (entered_tx, entered_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    collector.retire(move || {
        entered_tx.send(()).expect("test receiver");
        resume_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("resume cleanup");
    });
    let worker_collector = Arc::clone(&collector);
    let worker = thread::spawn(move || {
        for _ in 0..3 {
            let _ = worker_collector.try_advance();
        }
    });
    entered_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("cleanup never entered");

    let handle = collector.register();
    let guard = handle.pin();
    let reclaimed = retire_flag(&collector);
    drain(&collector);
    let reclaimed_while_pinned = reclaimed.load(Ordering::Acquire);
    resume_tx.send(()).expect("cleanup receiver");
    worker.join().expect("cleanup worker");
    assert!(!reclaimed_while_pinned);
    assert!(!reclaimed.load(Ordering::Acquire));
    drop(guard);
    drain(&collector);
    assert!(reclaimed.load(Ordering::Acquire));
    let diagnostics = collector.diagnostics();
    assert_eq!(diagnostics.total_retired, 2);
    assert_eq!(diagnostics.total_reclaimed, 2);
}
