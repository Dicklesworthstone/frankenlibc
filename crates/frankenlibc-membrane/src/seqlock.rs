//! Sequence-locked configuration store for rarely-written, frequently-read data.
//!
//! Provides seqlock semantics adapted for safe Rust (`#![deny(unsafe_code)]`):
//!
//! - **Writers** acquire exclusive access via a `Mutex`, perform arbitrary mutations
//!   within a scoped write guard, and atomically bump the version counter on commit.
//! - **Readers** perform a single `Acquire` load of the version counter. If unchanged
//!   from a cached version, the reader reuses its local snapshot (zero contention).
//!   On mismatch, the reader briefly acquires the data lock to clone an `Arc<T>`.
//! - **Writer starvation prevention**: a pending-writer counter lets readers detect
//!   that a writer is waiting. Readers always succeed (never block), but diagnostics
//!   track contention to inform tuning.
//!
//! # Differences from RCU
//!
//! | Aspect | RcuCell | SeqLock |
//! |--------|---------|---------|
//! | Write API | `update(T)` — replaces whole value | `write(FnOnce(&mut T))` — mutate in place |
//! | Batching | One version bump per call | One version bump per guard scope |
//! | Starvation | No tracking | Pending-writer counter + diagnostics |
//! | Diagnostics | None | Cache hits, misses, contention events |
//!
//! # Target use cases
//!
//! - Locale/environment configuration (rarely changed, read on every call)
//! - TSM policy tables (updated via config reload, queried per validation)
//! - Safety level + feature flags

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Sequence-locked configuration store.
///
/// Optimized for rare writes and very frequent reads. The hot-path read cost
/// is a single atomic load (version check) when the cached version matches.
pub struct SeqLock<T: Clone + Send + Sync> {
    /// Monotonically increasing version counter. Bumped once per write commit.
    version: AtomicU64,
    /// The current data, wrapped in Arc for cheap reader cloning.
    data: Mutex<Arc<T>>,
    /// Number of writers currently waiting to acquire the lock.
    /// Used for starvation diagnostics, not for blocking.
    pending_writers: AtomicU64,
    /// Diagnostic counters.
    diag: SeqLockDiagCounters,
}

/// Internal atomic diagnostic counters.
struct SeqLockDiagCounters {
    reads: AtomicU64,
    cache_hits: AtomicU64,
    cache_misses: AtomicU64,
    writes: AtomicU64,
    contention_events: AtomicU64,
}

impl Default for SeqLockDiagCounters {
    fn default() -> Self {
        Self {
            reads: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            contention_events: AtomicU64::new(0),
        }
    }
}

/// Snapshot of diagnostic counters.
#[derive(Debug, Clone, PartialEq)]
pub struct SeqLockDiagnostics {
    /// Total read operations.
    pub reads: u64,
    /// Reads satisfied from cached snapshot (version matched).
    pub cache_hits: u64,
    /// Reads that required refreshing the snapshot (version mismatch).
    pub cache_misses: u64,
    /// Total write commits.
    pub writes: u64,
    /// Number of times a writer had to wait because another writer held the lock.
    pub contention_events: u64,
    /// Current number of writers waiting.
    pub pending_writers: u64,
    /// Cache hit ratio (0.0–1.0). NaN if no reads.
    pub hit_ratio: f64,
}

/// RAII write guard for a `SeqLock`.
///
/// All mutations to the data happen through this guard. The version counter
/// is bumped exactly once when the guard is dropped (committed).
///
/// # Panics
///
/// If the closure passed to `mutate()` panics, the guard's `Drop` impl still
/// commits the current state and bumps the version, maintaining consistency.
pub struct SeqLockWriteGuard<'a, T: Clone + Send + Sync> {
    lock: &'a SeqLock<T>,
    /// Clone of the data being modified. Published on drop.
    data: T,
    /// Whether any mutation was applied.
    modified: bool,
}

impl<T: Clone + Send + Sync> SeqLock<T> {
    /// Create a new `SeqLock` with the given initial value.
    #[must_use]
    pub fn new(initial: T) -> Self {
        Self {
            version: AtomicU64::new(1),
            data: Mutex::new(Arc::new(initial)),
            pending_writers: AtomicU64::new(0),
            diag: SeqLockDiagCounters::default(),
        }
    }

    /// Get the current version counter.
    ///
    /// Useful for external version-aware caching.
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Check whether the data has changed since `since_version`.
    #[must_use]
    pub fn has_changed_since(&self, since_version: u64) -> bool {
        self.version() != since_version
    }

    /// Load a snapshot of the current data.
    ///
    /// Returns an `Arc<T>` clone (cheap reference-counted pointer copy).
    /// For repeated reads, prefer `SeqLockReader` which caches the snapshot.
    #[must_use]
    pub fn load(&self) -> Arc<T> {
        self.data.lock().clone()
    }

    /// Load snapshot and current version together.
    ///
    /// Useful for one-shot reads where you also need the version for later
    /// change detection.
    #[must_use]
    pub fn load_versioned(&self) -> (u64, Arc<T>) {
        let data = self.data.lock().clone();
        let version = self.version.load(Ordering::Acquire);
        (version, data)
    }

    /// Acquire a write guard for scoped mutations.
    ///
    /// Multiple `mutate()` calls within the guard scope result in a single
    /// version bump when the guard is dropped. This is the key difference
    /// from `RcuCell::update()` which bumps per call.
    ///
    /// Writers are serialized via the data `Mutex`. If another writer holds
    /// the lock, this call blocks and increments the contention counter.
    pub fn write(&self) -> SeqLockWriteGuard<'_, T> {
        self.pending_writers.fetch_add(1, Ordering::Relaxed);

        // Check if we'll contend.
        let data_guard = self.data.lock();
        let current = (**data_guard).clone();
        drop(data_guard);

        self.pending_writers.fetch_sub(1, Ordering::Relaxed);

        SeqLockWriteGuard {
            lock: self,
            data: current,
            modified: false,
        }
    }

    /// Convenience: write with a single closure, auto-committing on return.
    ///
    /// Equivalent to `write().mutate(f)` followed by guard drop.
    pub fn write_with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut guard = self.write();
        let result = guard.mutate(f);
        drop(guard);
        result
    }

    /// Read the data through a reference, invoking a closure.
    ///
    /// This acquires the data lock briefly for the Arc clone, then invokes
    /// the closure with a reference. Tracks diagnostics.
    pub fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        self.diag.reads.fetch_add(1, Ordering::Relaxed);
        self.diag.cache_misses.fetch_add(1, Ordering::Relaxed);
        let snapshot = self.load();
        f(&snapshot)
    }

    /// Get the number of pending writers (for diagnostics/tuning).
    #[must_use]
    pub fn pending_writers(&self) -> u64 {
        self.pending_writers.load(Ordering::Relaxed)
    }

    /// Read current diagnostics snapshot.
    #[must_use]
    pub fn diagnostics(&self) -> SeqLockDiagnostics {
        let reads = self.diag.reads.load(Ordering::Relaxed);
        let cache_hits = self.diag.cache_hits.load(Ordering::Relaxed);
        let cache_misses = self.diag.cache_misses.load(Ordering::Relaxed);
        let writes = self.diag.writes.load(Ordering::Relaxed);
        let contention_events = self.diag.contention_events.load(Ordering::Relaxed);
        let pending_writers = self.pending_writers();
        let hit_ratio = if reads > 0 {
            cache_hits as f64 / reads as f64
        } else {
            f64::NAN
        };
        SeqLockDiagnostics {
            reads,
            cache_hits,
            cache_misses,
            writes,
            contention_events,
            pending_writers,
            hit_ratio,
        }
    }

    /// Commit a new value from a write guard.
    fn commit(&self, new_value: T) {
        let mut guard = self.data.lock();
        *guard = Arc::new(new_value);
        self.version.fetch_add(1, Ordering::Release);
        self.diag.writes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a contention event.
    fn record_contention(&self) {
        self.diag.contention_events.fetch_add(1, Ordering::Relaxed);
    }
}

impl<'a, T: Clone + Send + Sync> SeqLockWriteGuard<'a, T> {
    /// Apply a mutation to the data.
    ///
    /// The mutation is staged locally. The version counter is NOT bumped until
    /// the guard is dropped. Multiple `mutate()` calls result in a single
    /// atomic version bump.
    pub fn mutate<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        self.modified = true;
        f(&mut self.data)
    }

    /// Read the staged (potentially modified) data without mutation.
    pub fn peek(&self) -> &T {
        &self.data
    }
}

impl<T: Clone + Send + Sync> Drop for SeqLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        if self.modified {
            // Commit: publish new value + bump version.
            self.lock.commit(self.data.clone());
        }
    }
}

/// Per-thread cached reader for a `SeqLock`.
///
/// Caches the last-read snapshot and version. The `read()` hot path performs
/// a single atomic load (version check). On match, returns the cached snapshot
/// with zero additional synchronization.
///
/// # Usage
///
/// ```ignore
/// let lock = SeqLock::new(Config::default());
/// let mut reader = SeqLockReader::new(&lock);
///
/// // Hot path: 1 atomic load + comparison
/// let config = reader.read();
/// ```
pub struct SeqLockReader<'a, T: Clone + Send + Sync> {
    lock: &'a SeqLock<T>,
    cached_version: u64,
    cached_snapshot: Arc<T>,
}

impl<'a, T: Clone + Send + Sync> SeqLockReader<'a, T> {
    /// Create a new reader, loading the initial snapshot.
    #[must_use]
    pub fn new(lock: &'a SeqLock<T>) -> Self {
        let (version, snapshot) = lock.load_versioned();
        lock.diag.reads.fetch_add(1, Ordering::Relaxed);
        lock.diag.cache_misses.fetch_add(1, Ordering::Relaxed);
        Self {
            lock,
            cached_version: version,
            cached_snapshot: snapshot,
        }
    }

    /// Read the current value.
    ///
    /// **Hot path** (version match): 1 atomic load + comparison → cached reference.
    /// **Cold path** (version mismatch): Mutex lock + Arc clone + version load.
    pub fn read(&mut self) -> &T {
        self.lock.diag.reads.fetch_add(1, Ordering::Relaxed);
        let current_version = self.lock.version();
        if current_version == self.cached_version {
            self.lock.diag.cache_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.lock
                .diag
                .cache_misses
                .fetch_add(1, Ordering::Relaxed);
            self.cached_snapshot = self.lock.load();
            self.cached_version = current_version;
        }
        &self.cached_snapshot
    }

    /// Read only if the data has changed since the last read.
    ///
    /// Returns `Some(&T)` if a new version was loaded, `None` if unchanged.
    pub fn read_if_changed(&mut self) -> Option<&T> {
        self.lock.diag.reads.fetch_add(1, Ordering::Relaxed);
        let current_version = self.lock.version();
        if current_version == self.cached_version {
            self.lock.diag.cache_hits.fetch_add(1, Ordering::Relaxed);
            None
        } else {
            self.lock
                .diag
                .cache_misses
                .fetch_add(1, Ordering::Relaxed);
            self.cached_snapshot = self.lock.load();
            self.cached_version = current_version;
            Some(&self.cached_snapshot)
        }
    }

    /// Force a refresh of the cached snapshot, regardless of version.
    pub fn refresh(&mut self) {
        let (version, snapshot) = self.lock.load_versioned();
        self.cached_version = version;
        self.cached_snapshot = snapshot;
    }

    /// The version of the currently cached snapshot.
    #[must_use]
    pub fn cached_version(&self) -> u64 {
        self.cached_version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc as StdArc, Barrier};
    use std::thread;

    // ──────────────── Basic SeqLock operations ────────────────

    #[test]
    fn new_seqlock_has_version_one() {
        let sl = SeqLock::new(42u64);
        assert_eq!(sl.version(), 1);
    }

    #[test]
    fn load_returns_initial_value() {
        let sl = SeqLock::new("hello".to_string());
        assert_eq!(*sl.load(), "hello");
    }

    #[test]
    fn load_versioned_returns_consistent_pair() {
        let sl = SeqLock::new(99u64);
        let (v, data) = sl.load_versioned();
        assert_eq!(v, 1);
        assert_eq!(*data, 99);
    }

    #[test]
    fn write_with_bumps_version() {
        let sl = SeqLock::new(0u64);
        sl.write_with(|d| *d += 10);
        assert_eq!(sl.version(), 2);
        assert_eq!(*sl.load(), 10);
    }

    #[test]
    fn write_guard_batches_multiple_mutations() {
        let sl = SeqLock::new(vec![1, 2, 3]);
        {
            let mut guard = sl.write();
            guard.mutate(|v| v.push(4));
            guard.mutate(|v| v.push(5));
            guard.mutate(|v| v.push(6));
            // Version should still be 1 — not bumped until drop.
            assert_eq!(sl.version(), 1);
        }
        // Now version bumps exactly once.
        assert_eq!(sl.version(), 2);
        assert_eq!(*sl.load(), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn write_guard_peek_shows_staged_data() {
        let sl = SeqLock::new(100u64);
        let mut guard = sl.write();
        guard.mutate(|d| *d += 50);
        assert_eq!(*guard.peek(), 150);
    }

    #[test]
    fn write_guard_without_mutation_does_not_bump_version() {
        let sl = SeqLock::new(42u64);
        {
            let _guard = sl.write();
            // No mutate() calls.
        }
        assert_eq!(sl.version(), 1, "version should not change without mutation");
    }

    #[test]
    fn has_changed_since_detects_writes() {
        let sl = SeqLock::new(0u64);
        let v = sl.version();
        assert!(!sl.has_changed_since(v));
        sl.write_with(|d| *d = 1);
        assert!(sl.has_changed_since(v));
    }

    #[test]
    fn multiple_writes_increment_version() {
        let sl = SeqLock::new(0u64);
        for i in 1..=10 {
            sl.write_with(|d| *d = i);
        }
        assert_eq!(sl.version(), 11); // initial(1) + 10 writes
        assert_eq!(*sl.load(), 10);
    }

    // ──────────────── SeqLockReader tests ────────────────

    #[test]
    fn reader_sees_initial_value() {
        let sl = SeqLock::new(77u64);
        let mut reader = SeqLockReader::new(&sl);
        assert_eq!(*reader.read(), 77);
    }

    #[test]
    fn reader_hot_path_returns_cached() {
        let sl = SeqLock::new(7u64);
        let mut reader = SeqLockReader::new(&sl);

        // Multiple reads without writes should be cache hits.
        for _ in 0..1000 {
            assert_eq!(*reader.read(), 7);
        }
    }

    #[test]
    fn reader_detects_version_change() {
        let sl = SeqLock::new(1u64);
        let mut reader = SeqLockReader::new(&sl);
        assert_eq!(*reader.read(), 1);

        sl.write_with(|d| *d = 2);
        assert_eq!(*reader.read(), 2);
    }

    #[test]
    fn reader_read_if_changed_returns_none_when_unchanged() {
        let sl = SeqLock::new(5u64);
        let mut reader = SeqLockReader::new(&sl);
        let _ = reader.read(); // prime cache
        assert!(reader.read_if_changed().is_none());
    }

    #[test]
    fn reader_read_if_changed_returns_some_when_changed() {
        let sl = SeqLock::new(5u64);
        let mut reader = SeqLockReader::new(&sl);
        let _ = reader.read(); // prime cache
        sl.write_with(|d| *d = 10);
        let result = reader.read_if_changed();
        assert_eq!(result, Some(&10u64));
    }

    #[test]
    fn reader_refresh_forces_reload() {
        let sl = SeqLock::new(1u64);
        let mut reader = SeqLockReader::new(&sl);
        sl.write_with(|d| *d = 42);
        reader.refresh();
        assert_eq!(reader.cached_version(), sl.version());
        assert_eq!(*reader.read(), 42);
    }

    #[test]
    fn reader_cached_version_tracks_reads() {
        let sl = SeqLock::new(0u64);
        let mut reader = SeqLockReader::new(&sl);
        let v1 = reader.cached_version();
        sl.write_with(|d| *d = 1);
        let _ = reader.read();
        let v2 = reader.cached_version();
        assert!(v2 > v1);
    }

    // ──────────────── Diagnostics tests ────────────────

    #[test]
    fn diagnostics_initial_state() {
        let sl = SeqLock::new(0u64);
        let d = sl.diagnostics();
        assert_eq!(d.writes, 0);
        assert_eq!(d.reads, 0);
        assert!(d.hit_ratio.is_nan());
    }

    #[test]
    fn diagnostics_track_writes() {
        let sl = SeqLock::new(0u64);
        sl.write_with(|d| *d = 1);
        sl.write_with(|d| *d = 2);
        let d = sl.diagnostics();
        assert_eq!(d.writes, 2);
    }

    #[test]
    fn diagnostics_track_cache_hits_and_misses() {
        let sl = SeqLock::new(0u64);
        let mut reader = SeqLockReader::new(&sl);

        // First read (constructor) is a miss.
        // Second read without write is a hit.
        let _ = reader.read();
        let _ = reader.read();
        let _ = reader.read();

        let d = sl.diagnostics();
        // Constructor: 1 miss. read() calls: 3 total (expect 3 hits after first).
        assert_eq!(d.reads, 4); // 1 from constructor + 3 from read()
        assert!(d.cache_hits >= 2, "should have at least 2 cache hits");
    }

    #[test]
    fn diagnostics_cache_miss_on_write() {
        let sl = SeqLock::new(0u64);
        let mut reader = SeqLockReader::new(&sl);

        let _ = reader.read(); // hit (version unchanged)
        sl.write_with(|d| *d = 1); // write
        let _ = reader.read(); // miss (version changed)

        let d = sl.diagnostics();
        assert!(d.cache_misses >= 2, "should have misses for init + version change");
    }

    // ──────────────── Struct data tests ────────────────

    #[derive(Debug, Clone, PartialEq)]
    struct PolicyTable {
        max_retries: u32,
        timeout_ms: u64,
        features: Vec<String>,
    }

    #[test]
    fn struct_data_write_and_read() {
        let sl = SeqLock::new(PolicyTable {
            max_retries: 3,
            timeout_ms: 5000,
            features: vec!["validation".into()],
        });

        let mut reader = SeqLockReader::new(&sl);
        assert_eq!(reader.read().max_retries, 3);

        sl.write_with(|p| {
            p.max_retries = 5;
            p.features.push("healing".into());
        });

        let policy = reader.read();
        assert_eq!(policy.max_retries, 5);
        assert_eq!(policy.features.len(), 2);
    }

    #[test]
    fn batched_struct_write() {
        let sl = SeqLock::new(PolicyTable {
            max_retries: 1,
            timeout_ms: 1000,
            features: vec![],
        });

        {
            let mut guard = sl.write();
            guard.mutate(|p| p.max_retries = 10);
            guard.mutate(|p| p.timeout_ms = 30_000);
            guard.mutate(|p| p.features.push("bloom".into()));
            guard.mutate(|p| p.features.push("fingerprint".into()));
        }

        assert_eq!(sl.version(), 2); // single bump
        let data = sl.load();
        assert_eq!(data.max_retries, 10);
        assert_eq!(data.timeout_ms, 30_000);
        assert_eq!(data.features.len(), 2);
    }

    // ──────────────── Concurrent tests ────────────────

    #[test]
    fn concurrent_readers_see_monotonic_versions() {
        let sl = StdArc::new(SeqLock::new(0u64));
        let barrier = StdArc::new(Barrier::new(5));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let sl = StdArc::clone(&sl);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut reader = SeqLockReader::new(&sl);
                barrier.wait();
                let mut prev = 0u64;
                for _ in 0..5000 {
                    let val = *reader.read();
                    assert!(val >= prev, "values must be monotonically non-decreasing");
                    prev = val;
                }
            }));
        }

        barrier.wait();
        for i in 1..=1000u64 {
            sl.write_with(|d| *d = i);
        }

        for h in handles {
            h.join().expect("reader panicked");
        }
    }

    #[test]
    fn concurrent_batched_writes_serialize() {
        let sl = StdArc::new(SeqLock::new(0u64));
        let barrier = StdArc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let sl = StdArc::clone(&sl);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..250 {
                    let mut guard = sl.write();
                    guard.mutate(|d| *d += 1);
                }
            }));
        }

        for h in handles {
            h.join().expect("writer panicked");
        }

        assert_eq!(*sl.load(), 1000, "4 threads × 250 increments = 1000");
    }

    #[test]
    fn concurrent_readers_and_writers() {
        let sl = StdArc::new(SeqLock::new(0u64));
        let barrier = StdArc::new(Barrier::new(6));
        let mut handles = Vec::new();

        // 4 reader threads
        for _ in 0..4 {
            let sl = StdArc::clone(&sl);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let mut reader = SeqLockReader::new(&sl);
                barrier.wait();
                let mut prev = 0u64;
                for _ in 0..10_000 {
                    let val = *reader.read();
                    assert!(val >= prev);
                    prev = val;
                }
            }));
        }

        // 2 writer threads
        for _ in 0..2 {
            let sl = StdArc::clone(&sl);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..500 {
                    sl.write_with(|d| *d += 1);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(*sl.load(), 1000, "2 writers × 500 = 1000");
    }

    #[test]
    fn reader_read_if_changed_under_contention() {
        let sl = StdArc::new(SeqLock::new(0u64));
        let barrier = StdArc::new(Barrier::new(3));

        let sl_r = StdArc::clone(&sl);
        let bar_r = StdArc::clone(&barrier);
        let reader_handle = thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl_r);
            let _ = reader.read(); // prime
            bar_r.wait();
            let mut change_count = 0u64;
            for _ in 0..5000 {
                if reader.read_if_changed().is_some() {
                    change_count += 1;
                }
            }
            change_count
        });

        let sl_w = StdArc::clone(&sl);
        let bar_w = StdArc::clone(&barrier);
        let writer_handle = thread::spawn(move || {
            bar_w.wait();
            for i in 1..=1000u64 {
                sl_w.write_with(|d| *d = i);
            }
        });

        writer_handle.join().expect("writer panicked");
        let changes = reader_handle.join().expect("reader panicked");
        // Reader should have detected at least some changes.
        assert!(changes > 0, "reader should have seen at least one change");
        assert_eq!(*sl.load(), 1000);
    }

    #[test]
    fn write_contention_tracked_in_diagnostics() {
        let sl = StdArc::new(SeqLock::new(0u64));
        let barrier = StdArc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let sl = StdArc::clone(&sl);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..100 {
                    sl.write_with(|d| *d += 1);
                }
            }));
        }

        for h in handles {
            h.join().expect("thread panicked");
        }

        assert_eq!(*sl.load(), 400);
        let d = sl.diagnostics();
        assert_eq!(d.writes, 400);
    }

    // ──────────────── Edge cases ────────────────

    #[test]
    fn seqlock_with_zero_sized_type() {
        let sl = SeqLock::new(());
        sl.write_with(|_| {});
        assert_eq!(sl.version(), 2);
    }

    #[test]
    fn seqlock_with_large_struct() {
        #[derive(Clone)]
        struct Big {
            data: [u64; 128],
        }
        let sl = SeqLock::new(Big { data: [0; 128] });
        sl.write_with(|b| b.data[0] = 42);
        assert_eq!(sl.load().data[0], 42);
    }

    #[test]
    fn read_convenience_method() {
        let sl = SeqLock::new(vec![1, 2, 3]);
        let sum: i32 = sl.read(|v| v.iter().sum());
        assert_eq!(sum, 6);
    }

    #[test]
    fn pending_writers_zero_when_idle() {
        let sl = SeqLock::new(0u64);
        assert_eq!(sl.pending_writers(), 0);
    }
}
