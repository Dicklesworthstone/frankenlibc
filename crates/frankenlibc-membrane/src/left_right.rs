//! Left-Right synchronization for consistent wait-free snapshot reads.
//!
//! Left-Right keeps two snapshots of the same logical value. Writers clone the
//! current snapshot into the inactive side, publish it, wait for readers that
//! were still sampling the previous side, then bring the drained side up to the
//! same version. Readers never take locks on the hot path; they pin the current
//! side in a visible slot, confirm it did not flip, and then reuse a cached
//! `Arc<T>` snapshot until the side/version changes.
//!
//! Compared with [`crate::rcu::RcuCell`], this module targets multi-field state
//! that must be observed as an internally consistent snapshot on every read.

use parking_lot::Mutex;
use std::hint::spin_loop;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Instant;

const SIDE_COUNT: usize = 2;
const LEFT_SIDE: usize = 0;
#[cfg(test)]
const RIGHT_SIDE: usize = 1;
const SLOT_IDLE: u8 = 0;
const SLOW_DRAIN_WARN_NS: u64 = 100_000;

/// Left-Right snapshot store.
///
/// Writes clone and mutate a full snapshot. Reads are wait-free on the steady
/// path: one side load, two visible-slot stores, one version load, and cached
/// snapshot reuse when no write has published a newer side/version.
pub struct LeftRight<T: Clone + Send + Sync> {
    active_side: AtomicU8,
    versions: [AtomicU64; SIDE_COUNT],
    sides: [Mutex<Arc<T>>; SIDE_COUNT],
    writer_lock: Mutex<()>,
    readers: Mutex<Vec<Option<Arc<AtomicU8>>>>,
    diag: LeftRightDiagCounters,
}

struct LeftRightDiagCounters {
    reads: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    writes: AtomicU64,
    slow_drains: AtomicU64,
    last_drain_wait_ns: AtomicU64,
    max_drain_wait_ns: AtomicU64,
}

impl Default for LeftRightDiagCounters {
    fn default() -> Self {
        Self {
            reads: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            slow_drains: AtomicU64::new(0),
            last_drain_wait_ns: AtomicU64::new(0),
            max_drain_wait_ns: AtomicU64::new(0),
        }
    }
}

/// Snapshot of Left-Right diagnostics.
#[derive(Debug, Clone, PartialEq)]
pub struct LeftRightDiagnostics {
    /// Total read operations through registered readers.
    pub reads: u64,
    /// Reads satisfied from the cached snapshot.
    pub cache_hits: u64,
    /// Reads that had to refresh because the side or version changed.
    pub cache_misses: u64,
    /// Total committed writes.
    pub writes: u64,
    /// Number of drains that exceeded the slow-drain threshold.
    pub slow_drains: u64,
    /// Drain wait recorded for the latest write.
    pub last_drain_wait_ns: u64,
    /// Maximum observed drain wait.
    pub max_drain_wait_ns: u64,
    /// Number of currently registered readers.
    pub registered_readers: usize,
    /// Active side (`0` = left, `1` = right).
    pub active_side: usize,
    /// Version of the active side.
    pub active_version: u64,
    /// Cache hit ratio across all reads.
    pub hit_ratio: f64,
}

/// Cached reader for a [`LeftRight`] cell.
///
/// Each reader owns a visible slot in the parent `LeftRight`. Writers scan the
/// slots after publishing a new active side and wait until no reader is still
/// sampling the drained side. The slot is cleared before returning the cached
/// reference, so the returned `&T` remains valid via the reader's local `Arc`.
pub struct LeftRightReader<'a, T: Clone + Send + Sync> {
    lock: &'a LeftRight<T>,
    registry_index: usize,
    slot: Arc<AtomicU8>,
    cached_side: usize,
    cached_version: u64,
    cached_snapshot: Arc<T>,
}

impl<T: Clone + Send + Sync> LeftRight<T> {
    /// Create a new Left-Right store with mirrored left/right snapshots.
    #[must_use]
    pub fn new(initial: T) -> Self {
        let left = Arc::new(initial.clone());
        let right = Arc::new(initial);
        let lock = Self {
            active_side: AtomicU8::new(LEFT_SIDE as u8),
            versions: [AtomicU64::new(1), AtomicU64::new(1)],
            sides: [Mutex::new(left), Mutex::new(right)],
            writer_lock: Mutex::new(()),
            readers: Mutex::new(Vec::new()),
            diag: LeftRightDiagCounters::default(),
        };
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptActivated,
            1,
            "left_right",
        );
        lock
    }

    /// Create a registered reader with an initial cached snapshot.
    #[must_use]
    pub fn reader(&self) -> LeftRightReader<'_, T> {
        let (registry_index, slot) = self.register_reader();
        let (side, version, snapshot) = self.load_active_versioned();
        self.diag.reads.fetch_add(1, Ordering::Relaxed);
        self.diag.cache_misses.fetch_add(1, Ordering::Relaxed);
        LeftRightReader {
            lock: self,
            registry_index,
            slot,
            cached_side: side,
            cached_version: version,
            cached_snapshot: snapshot,
        }
    }

    /// Version of the active side.
    #[must_use]
    pub fn version(&self) -> u64 {
        let side = self.active_side();
        self.versions[side].load(Ordering::Acquire)
    }

    /// Currently active side (`0` = left, `1` = right).
    #[must_use]
    pub fn active_side(&self) -> usize {
        self.active_side.load(Ordering::Acquire) as usize
    }

    /// Clone the current active snapshot.
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        let (_, _, snapshot) = self.load_active_versioned();
        snapshot
    }

    /// Load the active side, version, and snapshot together.
    #[must_use]
    pub fn load_active_versioned(&self) -> (usize, u64, Arc<T>) {
        loop {
            let side = self.active_side();
            let snapshot = self.sides[side].lock().clone();
            let version = self.versions[side].load(Ordering::Acquire);
            if self.active_side() == side {
                return (side, version, snapshot);
            }
            spin_loop();
        }
    }

    /// Mutate the shared value via the inactive side, then publish atomically.
    ///
    /// Writers are serialized. The closure sees a unique `&mut T` clone of the
    /// current active snapshot; after it returns, the mutated snapshot becomes
    /// visible to new readers and is then mirrored back to the drained side.
    pub fn write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let _writer_guard = self.writer_lock.lock();
        let active_side = self.active_side();
        let inactive_side = inactive_side(active_side);
        let mut next_value = (**self.sides[active_side].lock()).clone();
        let result = f(&mut next_value);

        let published = Arc::new(next_value);
        let new_version = self.version().saturating_add(1);

        *self.sides[inactive_side].lock() = Arc::clone(&published);
        self.versions[inactive_side].store(new_version, Ordering::Release);
        self.active_side
            .store(inactive_side as u8, Ordering::Release);

        let drain_wait_ns = self.wait_for_side_to_drain(active_side);

        *self.sides[active_side].lock() = published;
        self.versions[active_side].store(new_version, Ordering::Release);
        self.diag.writes.fetch_add(1, Ordering::Relaxed);
        self.diag
            .last_drain_wait_ns
            .store(drain_wait_ns, Ordering::Relaxed);
        update_max(&self.diag.max_drain_wait_ns, drain_wait_ns);
        if drain_wait_ns > SLOW_DRAIN_WARN_NS {
            self.diag.slow_drains.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Produce a stable diagnostics snapshot.
    #[must_use]
    pub fn diagnostics(&self) -> LeftRightDiagnostics {
        let reads = self.diag.reads.load(Ordering::Relaxed);
        let cache_hits = self.diag.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.diag.cache_misses.load(Ordering::Relaxed);
        let writes = self.diag.writes.load(Ordering::Relaxed);
        let slow_drains = self.diag.slow_drains.load(Ordering::Relaxed);
        let last_drain_wait_ns = self.diag.last_drain_wait_ns.load(Ordering::Relaxed);
        let max_drain_wait_ns = self.diag.max_drain_wait_ns.load(Ordering::Relaxed);
        let registered_readers = self
            .readers
            .lock()
            .iter()
            .filter(|entry| entry.is_some())
            .count();
        let active_side = self.active_side();
        let active_version = self.versions[active_side].load(Ordering::Acquire);
        let hit_ratio = if reads == 0 {
            f64::NAN
        } else {
            cache_hits as f64 / reads as f64
        };

        LeftRightDiagnostics {
            reads,
            cache_hits,
            cache_misses,
            writes,
            slow_drains,
            last_drain_wait_ns,
            max_drain_wait_ns,
            registered_readers,
            active_side,
            active_version,
            hit_ratio,
        }
    }

    fn load_side(&self, side: usize) -> (u64, Arc<T>) {
        let snapshot = self.sides[side].lock().clone();
        let version = self.versions[side].load(Ordering::Acquire);
        (version, snapshot)
    }

    fn register_reader(&self) -> (usize, Arc<AtomicU8>) {
        let slot = Arc::new(AtomicU8::new(SLOT_IDLE));
        let mut readers = self.readers.lock();
        if let Some((index, entry)) = readers
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.is_none())
        {
            *entry = Some(Arc::clone(&slot));
            (index, slot)
        } else {
            let index = readers.len();
            readers.push(Some(Arc::clone(&slot)));
            (index, slot)
        }
    }

    fn unregister_reader(&self, index: usize, slot: &Arc<AtomicU8>) {
        let mut readers = self.readers.lock();
        let should_clear = readers
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|existing| Arc::ptr_eq(existing, slot));
        if should_clear {
            readers[index] = None;
        }
    }

    fn wait_for_side_to_drain(&self, side: usize) -> u64 {
        let tracked_side = encode_side(side);
        let start = Instant::now();
        let mut spins = 0u32;

        loop {
            let drained = {
                let readers = self.readers.lock();
                readers.iter().all(|entry| {
                    entry
                        .as_ref()
                        .is_none_or(|slot| slot.load(Ordering::Acquire) != tracked_side)
                })
            };

            if drained {
                return u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            }

            spins = spins.saturating_add(1);
            if spins.is_multiple_of(64) {
                std::thread::yield_now();
            } else {
                spin_loop();
            }
        }
    }
}

impl<'a, T: Clone + Send + Sync> LeftRightReader<'a, T> {
    /// Read the current snapshot.
    ///
    /// The hot path performs no lock acquisition and reuses the cached `Arc<T>`
    /// when the side and version are unchanged since the previous read.
    pub fn read(&mut self) -> &T {
        loop {
            self.lock.diag.reads.fetch_add(1, Ordering::Relaxed);
            let side = self.lock.active_side();
            self.slot.store(encode_side(side), Ordering::Release);

            if self.lock.active_side() != side {
                self.slot.store(SLOT_IDLE, Ordering::Release);
                spin_loop();
                continue;
            }

            let current_version = self.lock.versions[side].load(Ordering::Acquire);
            if self.cached_side == side && self.cached_version == current_version {
                self.lock.diag.cache_hits.fetch_add(1, Ordering::Relaxed);
            } else {
                self.lock.diag.cache_misses.fetch_add(1, Ordering::Relaxed);
                let (version, snapshot) = self.lock.load_side(side);
                self.cached_side = side;
                self.cached_version = version;
                self.cached_snapshot = snapshot;
            }

            self.slot.store(SLOT_IDLE, Ordering::Release);
            return &self.cached_snapshot;
        }
    }

    /// Returns the cached side backing the currently held snapshot.
    #[must_use]
    pub fn cached_side(&self) -> usize {
        self.cached_side
    }

    /// Returns the version of the currently cached snapshot.
    #[must_use]
    pub fn cached_version(&self) -> u64 {
        self.cached_version
    }

    /// Force a refresh from the currently active side.
    pub fn refresh(&mut self) {
        let (side, version, snapshot) = self.lock.load_active_versioned();
        self.cached_side = side;
        self.cached_version = version;
        self.cached_snapshot = snapshot;
        self.slot.store(SLOT_IDLE, Ordering::Release);
    }
}

impl<T: Clone + Send + Sync> Drop for LeftRight<T> {
    fn drop(&mut self) {
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptDeactivated,
            self.version(),
            "left_right",
        );
    }
}

impl<T: Clone + Send + Sync> Drop for LeftRightReader<'_, T> {
    fn drop(&mut self) {
        self.slot.store(SLOT_IDLE, Ordering::Release);
        self.lock.unregister_reader(self.registry_index, &self.slot);
    }
}

#[inline]
fn inactive_side(side: usize) -> usize {
    side ^ 1
}

#[inline]
fn encode_side(side: usize) -> u8 {
    debug_assert!(side < SIDE_COUNT);
    side as u8 + 1
}

fn update_max(target: &AtomicU64, candidate: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while candidate > current {
        match target.compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::thread;
    use std::time::Duration;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Pair {
        left: u64,
        right: u64,
    }

    impl Pair {
        fn is_consistent(&self) -> bool {
            self.right == self.left ^ u64::MAX
        }
    }

    #[test]
    fn new_left_right_starts_on_left_side() {
        let lock = LeftRight::new(42u64);
        assert_eq!(lock.active_side(), LEFT_SIDE);
        assert_eq!(lock.version(), 1);
        assert_eq!(*lock.load(), 42);
    }

    #[test]
    fn reader_sees_initial_snapshot() {
        let lock = LeftRight::new(String::from("hello"));
        let mut reader = lock.reader();

        assert_eq!(reader.read(), "hello");
        assert_eq!(reader.cached_side(), LEFT_SIDE);
        assert_eq!(reader.cached_version(), 1);
    }

    #[test]
    fn write_publishes_new_snapshot_and_flips_side() {
        let lock = LeftRight::new(1u64);
        let mut reader = lock.reader();

        lock.write(|value| *value = 7);

        assert_eq!(*reader.read(), 7);
        assert_eq!(lock.version(), 2);
        assert_eq!(reader.cached_version(), 2);
        assert_eq!(reader.cached_side(), RIGHT_SIDE);
    }

    #[test]
    fn reader_hot_path_reuses_cached_snapshot() {
        let lock = LeftRight::new(7u64);
        let mut reader = lock.reader();

        for _ in 0..1_000 {
            assert_eq!(*reader.read(), 7);
        }

        let diag = lock.diagnostics();
        assert!(diag.cache_hits >= 1_000);
        assert!(diag.cache_misses >= 1);
    }

    #[test]
    fn reader_drop_releases_registration_slot() {
        let lock = LeftRight::new(5u64);
        let reader = lock.reader();
        assert_eq!(lock.diagnostics().registered_readers, 1);
        drop(reader);
        assert_eq!(lock.diagnostics().registered_readers, 0);
    }

    #[test]
    fn consistent_multi_field_snapshots_under_writes() {
        let lock = StdArc::new(LeftRight::new(Pair {
            left: 0,
            right: u64::MAX,
        }));
        let barrier = StdArc::new(Barrier::new(5));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let lock = StdArc::clone(&lock);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut reader = lock.reader();
                barrier.wait();
                for _ in 0..20_000 {
                    let snapshot = reader.read();
                    assert!(
                        snapshot.is_consistent(),
                        "reader observed inconsistent pair: {snapshot:?}"
                    );
                }
            }));
        }

        barrier.wait();
        for value in 1..=2_000u64 {
            lock.write(|pair| {
                pair.left = value;
                pair.right = value ^ u64::MAX;
            });
        }

        for handle in handles {
            handle.join().expect("reader thread panicked");
        }
    }

    #[test]
    fn writer_completes_under_continuous_readers() {
        let lock = StdArc::new(LeftRight::new(Pair {
            left: 1,
            right: 1 ^ u64::MAX,
        }));
        let running = StdArc::new(AtomicBool::new(true));
        let barrier = StdArc::new(Barrier::new(5));
        let mut readers = Vec::new();

        for _ in 0..4 {
            let lock = StdArc::clone(&lock);
            let running = StdArc::clone(&running);
            let barrier = StdArc::clone(&barrier);
            readers.push(thread::spawn(move || {
                let mut reader = lock.reader();
                barrier.wait();
                while running.load(Ordering::Acquire) {
                    let snapshot = reader.read();
                    assert!(snapshot.is_consistent());
                }
            }));
        }

        let lock_writer = StdArc::clone(&lock);
        let barrier_writer = StdArc::clone(&barrier);
        let writer = thread::spawn(move || {
            barrier_writer.wait();
            for value in 2..=5_000u64 {
                lock_writer.write(|pair| {
                    pair.left = value;
                    pair.right = value ^ u64::MAX;
                });
            }
        });

        writer
            .join()
            .expect("writer thread panicked during reader churn");
        running.store(false, Ordering::Release);

        for reader in readers {
            reader.join().expect("reader thread panicked");
        }

        let snapshot = lock.load();
        assert!(snapshot.is_consistent());
        assert_eq!(snapshot.left, 5_000);
    }

    #[test]
    fn concurrent_readers_observe_monotonic_versions() {
        let lock = StdArc::new(LeftRight::new(0u64));
        let done = StdArc::new(AtomicBool::new(false));
        let latest_version = StdArc::new(AtomicU64::new(1));

        let writer_lock = StdArc::clone(&lock);
        let writer_done = StdArc::clone(&done);
        let writer_version = StdArc::clone(&latest_version);
        let writer = thread::spawn(move || {
            for value in 1..=10_000u64 {
                writer_lock.write(|slot| *slot = value);
                writer_version.store(writer_lock.version(), Ordering::Release);
            }
            writer_done.store(true, Ordering::Release);
        });

        let mut readers = Vec::new();
        for _ in 0..4 {
            let lock = StdArc::clone(&lock);
            let done = StdArc::clone(&done);
            let latest_version = StdArc::clone(&latest_version);
            readers.push(thread::spawn(move || {
                let mut reader = lock.reader();
                let mut previous = reader.cached_version();
                while !done.load(Ordering::Acquire)
                    || reader.cached_version() < latest_version.load(Ordering::Acquire)
                {
                    let _ = reader.read();
                    let current = reader.cached_version();
                    assert!(current >= previous, "versions must never move backwards");
                    previous = current;
                }
            }));
        }

        writer.join().expect("writer panicked");
        for reader in readers {
            reader.join().expect("reader panicked");
        }
    }

    #[test]
    fn refresh_loads_current_active_snapshot() {
        let lock = LeftRight::new(1u64);
        let mut reader = lock.reader();

        lock.write(|value| *value = 99);
        reader.refresh();

        assert_eq!(*reader.read(), 99);
        assert_eq!(reader.cached_version(), lock.version());
    }

    #[test]
    fn repeated_writes_keep_versions_in_sync() {
        let lock = LeftRight::new(0u64);
        for value in 1..=32 {
            lock.write(|slot| *slot = value);
            let (side, version, snapshot) = lock.load_active_versioned();
            assert_eq!(version, value + 1);
            assert_eq!(*snapshot, value);
            let inactive = inactive_side(side);
            assert_eq!(
                lock.versions[inactive].load(Ordering::Acquire),
                version,
                "inactive side must be mirrored after drain"
            );
        }
    }

    #[test]
    fn diagnostics_track_slow_drains_without_false_positive_requirement() {
        let lock = StdArc::new(LeftRight::new(0u64));
        let reader_lock = StdArc::clone(&lock);

        let handle = thread::spawn(move || {
            let mut reader = reader_lock.reader();
            let _ = reader.read();
            thread::sleep(Duration::from_millis(1));
        });

        thread::sleep(Duration::from_millis(1));
        lock.write(|slot| *slot = 1);
        handle.join().expect("reader sleeper panicked");

        let diag = lock.diagnostics();
        assert!(diag.last_drain_wait_ns <= diag.max_drain_wait_ns);
        assert!(diag.writes >= 1);
    }
}
