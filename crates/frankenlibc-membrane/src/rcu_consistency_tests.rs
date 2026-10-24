//! Regressions for coherent snapshot publication and reentrant reclamation.
//!
//! Destructor-driven interleavings below are deterministic: no scheduler race
//! or timing threshold is needed to reproduce a stale version stamp.

use super::{RcuCell, RcuReader};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

struct Snapshot {
    value: u64,
    on_drop: Option<Box<dyn FnOnce() + Send + Sync>>,
}

impl Snapshot {
    fn plain(value: u64) -> Self {
        Self {
            value,
            on_drop: None,
        }
    }

    fn with_drop(value: u64, on_drop: impl FnOnce() + Send + Sync + 'static) -> Self {
        Self {
            value,
            on_drop: Some(Box::new(on_drop)),
        }
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        if let Some(on_drop) = self.on_drop.take() {
            on_drop();
        }
    }
}

fn refresh_during_reclamation(force: bool) {
    let cell = Arc::new(RcuCell::new(Snapshot::plain(0)));
    let weak = Arc::downgrade(&cell);
    cell.update(Snapshot::with_drop(1, move || {
        // Once the reader drops its old cached Arc, publish yet another
        // version before refresh returns. This is the exact dangerous gap
        // between the former load() and epoch() calls.
        weak.upgrade().expect("cell remains live").update(Snapshot::plain(3));
    }));
    let mut reader = RcuReader::new(&cell);
    cell.update(Snapshot::plain(2));
    assert_eq!(cell.epoch(), 3);
    assert_eq!(reader.cached_epoch(), 2);

    if force {
        reader.refresh();
    } else {
        assert_eq!(reader.read().value, 2);
    }
    assert_eq!(cell.epoch(), 4, "the destructor must actually publish");
    assert_eq!(reader.cached_snapshot.value, 2);
    assert_eq!(
        reader.cached_epoch(),
        3,
        "old snapshot must not be stamped with a later publication's epoch"
    );
    assert_eq!(reader.read().value, 3, "a subsequent read must observe the update");
    assert_eq!(reader.cached_epoch(), 4);
}

#[test]
fn forced_refresh_does_not_hide_destructor_publication() {
    refresh_during_reclamation(true);
}

#[test]
fn cold_read_preserves_the_loaded_snapshot_version() {
    refresh_during_reclamation(false);
}

fn writer_reclamation_allows_reentry(with_closure: bool) {
    let cell = Arc::new(RcuCell::new(Snapshot::plain(0)));
    let observed = Arc::new(AtomicU64::new(0));
    let weak = Arc::downgrade(&cell);
    let receipt = Arc::clone(&observed);
    cell.update(Snapshot::with_drop(1, move || {
        let cell = weak.upgrade().expect("cell remains live");
        // Fail promptly under the old implementation instead of hanging a
        // test process forever on the reentrant load/update just below.
        let available = cell.current.try_lock();
        assert!(available.is_some(), "snapshot destructor ran under the writer lock");
        drop(available);
        let (epoch, snapshot) = cell.load_versioned();
        assert_eq!((epoch, snapshot.value), (3, 2));
        receipt.store(epoch, Ordering::Release);
        cell.update(Snapshot::plain(3));
    }));
    if with_closure {
        cell.update_with(|old| Snapshot::plain(old.value + 1));
    } else {
        cell.update(Snapshot::plain(2));
    }
    assert_eq!(observed.load(Ordering::Acquire), 3);
    let (epoch, snapshot) = cell.load_versioned();
    assert_eq!((epoch, snapshot.value), (4, 3));
}

#[test]
fn update_reclaims_outside_the_writer_lock() {
    writer_reclamation_allows_reentry(false);
}

#[test]
fn update_with_reclaims_outside_the_writer_lock() {
    writer_reclamation_allows_reentry(true);
}

fn writer_publication_survives_destructor_panic(with_closure: bool) {
    let cell = RcuCell::new(Snapshot::with_drop(0, || panic!("old snapshot destructor")));
    let result = catch_unwind(AssertUnwindSafe(|| {
        if with_closure {
            cell.update_with(|old| Snapshot::plain(old.value + 1));
        } else {
            cell.update(Snapshot::plain(1));
        }
    }));
    assert!(result.is_err(), "the destructor panic must be observed");
    let (epoch, snapshot) = cell.load_versioned();
    assert_eq!((epoch, snapshot.value), (2, 1), "publication precedes reclamation");
    cell.update(Snapshot::plain(2));
    assert_eq!(cell.epoch(), 3);
    assert_eq!(cell.load().value, 2);
}

#[test]
fn update_publishes_before_a_panicking_destructor() {
    writer_publication_survives_destructor_panic(false);
}

#[test]
fn update_with_publishes_before_a_panicking_destructor() {
    writer_publication_survives_destructor_panic(true);
}

#[test]
fn reader_installs_complete_pair_before_a_panicking_destructor() {
    let cell = RcuCell::new(Snapshot::with_drop(0, || panic!("cached snapshot destructor")));
    let mut reader = RcuReader::new(&cell);
    cell.update(Snapshot::plain(1));
    let result = catch_unwind(AssertUnwindSafe(|| reader.refresh()));
    assert!(result.is_err());
    assert_eq!(reader.cached_snapshot.value, 1);
    assert_eq!(reader.cached_epoch(), 2, "panic must not leave a split cached pair");
    assert_eq!(reader.read().value, 1);
    cell.update(Snapshot::plain(2));
    assert_eq!(reader.read().value, 2);
    assert_eq!(reader.cached_epoch(), 3);
}

#[test]
fn panicking_update_closure_leaves_the_old_pair_unchanged() {
    let cell = RcuCell::new(41u64);
    let before = cell.load_versioned();
    let result = catch_unwind(AssertUnwindSafe(|| {
        cell.update_with(|_| panic!("replacement computation failed"));
    }));
    assert!(result.is_err());
    let after = cell.load_versioned();
    assert_eq!(after.0, before.0);
    assert!(Arc::ptr_eq(&before.1, &after.1));
    cell.update_with(|old| old + 1);
    assert_eq!(cell.load_versioned().0, 2);
    assert_eq!(*cell.load(), 42);
}

#[test]
fn epoch_exhaustion_never_changes_or_relabels_the_snapshot() {
    for with_closure in [false, true] {
        let cell = RcuCell::new(0u64);
        cell.epoch.store(u64::MAX - 1, Ordering::Release);
        cell.update(1);
        let before = cell.load_versioned();
        assert_eq!(before.0, u64::MAX);
        let called = AtomicBool::new(false);
        let result = catch_unwind(AssertUnwindSafe(|| {
            if with_closure {
                cell.update_with(|_| {
                    called.store(true, Ordering::Relaxed);
                    2
                });
            } else {
                cell.update(2);
            }
        }));
        assert!(result.is_err());
        assert!(!called.load(Ordering::Relaxed), "exhaustion is checked before invoking user code");
        let after = cell.load_versioned();
        assert_eq!(after.0, u64::MAX);
        assert_eq!(*after.1, 1);
        assert!(Arc::ptr_eq(&before.1, &after.1));
    }
}

#[test]
fn concurrent_readers_observe_exact_version_pairs_without_lost_updates() {
    let cell = Arc::new(RcuCell::new(0u64));
    let start = Arc::new(Barrier::new(7));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let cell = Arc::clone(&cell);
        let start = Arc::clone(&start);
        threads.push(std::thread::spawn(move || {
            start.wait();
            for _ in 0..2000 {
                cell.update_with(|old| old + 1);
            }
        }));
    }
    for _ in 0..2 {
        let cell = Arc::clone(&cell);
        let start = Arc::clone(&start);
        threads.push(std::thread::spawn(move || {
            let mut reader = RcuReader::new(&cell);
            start.wait();
            for index in 0..8000 {
                if index % 2 == 0 {
                    reader.refresh();
                }
                let value = *reader.read();
                assert_eq!(reader.cached_epoch(), value + 1, "reader cached a split version pair");
                let (epoch, snapshot) = cell.load_versioned();
                assert_eq!(epoch, *snapshot + 1);
            }
        }));
    }
    start.wait();
    // Join every worker even when one fails, so no worker leaks into later tests.
    let failed = threads.into_iter().map(|thread| thread.join().is_err()).filter(|failed| *failed).count();
    assert_eq!(failed, 0);
    let (epoch, value) = cell.load_versioned();
    assert_eq!((epoch, *value), (8001, 8000));
}
