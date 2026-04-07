//! BRAVO-style reader-biased reader/writer lock for read-heavy metadata paths.
//!
//! BRAVO (Biased Locking for Reader-Optimized workloads) keeps a conventional
//! reader/writer lock for the slow path while allowing readers to bypass that
//! lock when reader bias is enabled. Readers advertise themselves in a visible
//! reader table; writers revoke the bias, acquire the underlying lock, then
//! wait for the visible readers to drain before mutating the protected value.
//!
//! This implementation is intentionally narrow:
//!
//! - fast-path readers avoid taking the base `RwLock`
//! - writers serialize through a small gate before revocation
//! - the unsafe boundary is isolated to dereferencing `UnsafeCell<T>` once the
//!   BRAVO invariants establish shared or exclusive access
//!
//! The lock is a natural fit for membrane metadata such as `PageOracle`, where
//! reads dominate and writes are comparatively rare.

#![allow(unsafe_code)]

use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use std::cell::UnsafeCell;
use std::hint::spin_loop;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

const DEFAULT_VISIBLE_READERS: usize = 2048;
const MIN_VISIBLE_READERS: usize = 32;
const EMPTY_SLOT: usize = 0;
const REVOCATION_YIELD_INTERVAL: u32 = 64;

static NEXT_THREAD_TOKEN: AtomicUsize = AtomicUsize::new(1);
static NEXT_LOCK_ID: AtomicUsize = AtomicUsize::new(1);

thread_local! {
    static THREAD_TOKEN: usize = NEXT_THREAD_TOKEN.fetch_add(1, Ordering::Relaxed).max(1);
}

/// BRAVO reader path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BravoReadPath {
    /// Visible-reader fast path; no base lock acquired.
    Fast,
    /// Conventional `RwLock` read path.
    Slow,
}

/// Public diagnostics for [`BravoRwLock`].
#[derive(Debug, Clone, PartialEq)]
pub struct BravoRwLockDiagnostics {
    /// Total reads completed through the lock.
    pub reads: u64,
    /// Reads that completed on the visible-reader fast path.
    pub fast_path_reads: u64,
    /// Reads that completed on the base `RwLock` slow path.
    pub slow_path_reads: u64,
    /// Reads that attempted the fast path.
    pub fast_path_attempts: u64,
    /// Reads that claimed a slot but had to abort because a writer revoked bias.
    pub fast_path_aborts: u64,
    /// Reads that collided in the visible-reader table and fell back.
    pub slot_collisions: u64,
    /// Total completed writes.
    pub writes: u64,
    /// Total bias revocations.
    pub revocations: u64,
    /// Number of writes that contended on the base lock.
    pub writer_contention_events: u64,
    /// Latest revocation drain wait in nanoseconds.
    pub last_revocation_wait_ns: u64,
    /// Maximum revocation drain wait observed.
    pub max_revocation_wait_ns: u64,
    /// Whether reader bias is currently enabled.
    pub reader_bias_enabled: bool,
    /// Whether a writer is currently pending or active.
    pub writer_pending: bool,
    /// Number of visible-reader slots in the table.
    pub visible_reader_slots: usize,
    /// Number of slots currently occupied.
    pub active_slots: usize,
    /// `slot_collisions / fast_path_attempts`.
    pub slot_collision_rate: f64,
}

struct BravoDiagCounters {
    reads: AtomicU64,
    fast_path_reads: AtomicU64,
    slow_path_reads: AtomicU64,
    fast_path_attempts: AtomicU64,
    fast_path_aborts: AtomicU64,
    slot_collisions: AtomicU64,
    writes: AtomicU64,
    revocations: AtomicU64,
    writer_contention_events: AtomicU64,
    last_revocation_wait_ns: AtomicU64,
    max_revocation_wait_ns: AtomicU64,
}

impl Default for BravoDiagCounters {
    fn default() -> Self {
        Self {
            reads: AtomicU64::new(0),
            fast_path_reads: AtomicU64::new(0),
            slow_path_reads: AtomicU64::new(0),
            fast_path_attempts: AtomicU64::new(0),
            fast_path_aborts: AtomicU64::new(0),
            slot_collisions: AtomicU64::new(0),
            writes: AtomicU64::new(0),
            revocations: AtomicU64::new(0),
            writer_contention_events: AtomicU64::new(0),
            last_revocation_wait_ns: AtomicU64::new(0),
            max_revocation_wait_ns: AtomicU64::new(0),
        }
    }
}

/// Reader-biased reader/writer lock for read-mostly metadata.
pub struct BravoRwLock<T: Send + Sync> {
    data: UnsafeCell<T>,
    base: RwLock<()>,
    writer_gate: Mutex<()>,
    reader_bias_enabled: AtomicBool,
    writer_pending: AtomicBool,
    visible_readers: Box<[AtomicUsize]>,
    lock_id: usize,
    diag: BravoDiagCounters,
}

struct WriterBiasReset<'a, T: Send + Sync> {
    lock: &'a BravoRwLock<T>,
}

/// Shared read guard returned by [`BravoRwLock::read`].
#[must_use]
pub struct BravoReadGuard<'a, T: Send + Sync> {
    lock: &'a BravoRwLock<T>,
    path: BravoReadPath,
    _slow_guard: Option<RwLockReadGuard<'a, ()>>,
    slot_index: Option<usize>,
}

impl<T: Send + Sync> BravoRwLock<T> {
    /// Create a BRAVO lock with the default visible-reader table size.
    #[must_use]
    pub fn new(initial: T) -> Self {
        Self::with_visible_readers(initial, DEFAULT_VISIBLE_READERS)
    }

    /// Create a BRAVO lock with a caller-provided visible-reader table size.
    #[must_use]
    pub fn with_visible_readers(initial: T, requested_slots: usize) -> Self {
        let visible_reader_slots = requested_slots.max(MIN_VISIBLE_READERS).next_power_of_two();
        let lock = Self {
            data: UnsafeCell::new(initial),
            base: RwLock::new(()),
            writer_gate: Mutex::new(()),
            reader_bias_enabled: AtomicBool::new(true),
            writer_pending: AtomicBool::new(false),
            visible_readers: (0..visible_reader_slots)
                .map(|_| AtomicUsize::new(EMPTY_SLOT))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            lock_id: NEXT_LOCK_ID.fetch_add(1, Ordering::Relaxed).max(1),
            diag: BravoDiagCounters::default(),
        };
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptActivated,
            1,
            "bravo_rwlock",
        );
        lock
    }

    /// Acquire a shared read guard.
    pub fn read(&self) -> BravoReadGuard<'_, T> {
        self.diag.reads.fetch_add(1, Ordering::Relaxed);

        if let Some(slot_index) = self.try_fast_path() {
            self.diag.fast_path_reads.fetch_add(1, Ordering::Relaxed);
            return BravoReadGuard {
                lock: self,
                path: BravoReadPath::Fast,
                _slow_guard: None,
                slot_index: Some(slot_index),
            };
        }

        let slow_guard = self.base.read();
        self.diag.slow_path_reads.fetch_add(1, Ordering::Relaxed);
        BravoReadGuard {
            lock: self,
            path: BravoReadPath::Slow,
            _slow_guard: Some(slow_guard),
            slot_index: None,
        }
    }

    /// Read through a closure.
    pub fn with_read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let guard = self.read();
        f(&guard)
    }

    /// Mutate the protected value with exclusive access.
    pub fn with_write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let _writer_gate = self.writer_gate.lock();
        self.writer_pending.store(true, Ordering::Release);
        self.reader_bias_enabled.store(false, Ordering::Release);
        let reset = WriterBiasReset { lock: self };

        let base_guard = if let Some(guard) = self.base.try_write() {
            guard
        } else {
            self.diag
                .writer_contention_events
                .fetch_add(1, Ordering::Relaxed);
            self.base.write()
        };

        let revocation_wait_ns = self.wait_for_visible_readers();
        self.diag.revocations.fetch_add(1, Ordering::Relaxed);
        self.diag
            .last_revocation_wait_ns
            .store(revocation_wait_ns, Ordering::Relaxed);
        update_max(&self.diag.max_revocation_wait_ns, revocation_wait_ns);

        let result = {
            // SAFETY: the writer has exclusive access because:
            // 1. `writer_gate` serializes all writers,
            // 2. `reader_bias_enabled=false` prevents new fast-path readers,
            // 3. the base write lock blocks slow-path readers, and
            // 4. `wait_for_visible_readers()` ensures prior fast-path readers drained.
            let data = unsafe { &mut *self.data.get() };
            f(data)
        };

        self.diag.writes.fetch_add(1, Ordering::Relaxed);
        drop(base_guard);
        drop(reset);
        result
    }

    /// Snapshot the current diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> BravoRwLockDiagnostics {
        let fast_path_attempts = self.diag.fast_path_attempts.load(Ordering::Relaxed);
        let slot_collisions = self.diag.slot_collisions.load(Ordering::Relaxed);
        let active_slots = self
            .visible_readers
            .iter()
            .filter(|slot| slot.load(Ordering::Acquire) != EMPTY_SLOT)
            .count();

        BravoRwLockDiagnostics {
            reads: self.diag.reads.load(Ordering::Relaxed),
            fast_path_reads: self.diag.fast_path_reads.load(Ordering::Relaxed),
            slow_path_reads: self.diag.slow_path_reads.load(Ordering::Relaxed),
            fast_path_attempts,
            fast_path_aborts: self.diag.fast_path_aborts.load(Ordering::Relaxed),
            slot_collisions,
            writes: self.diag.writes.load(Ordering::Relaxed),
            revocations: self.diag.revocations.load(Ordering::Relaxed),
            writer_contention_events: self.diag.writer_contention_events.load(Ordering::Relaxed),
            last_revocation_wait_ns: self.diag.last_revocation_wait_ns.load(Ordering::Relaxed),
            max_revocation_wait_ns: self.diag.max_revocation_wait_ns.load(Ordering::Relaxed),
            reader_bias_enabled: self.reader_bias_enabled.load(Ordering::Acquire),
            writer_pending: self.writer_pending.load(Ordering::Acquire),
            visible_reader_slots: self.visible_readers.len(),
            active_slots,
            slot_collision_rate: if fast_path_attempts == 0 {
                0.0
            } else {
                slot_collisions as f64 / fast_path_attempts as f64
            },
        }
    }

    fn try_fast_path(&self) -> Option<usize> {
        if !self.reader_bias_enabled.load(Ordering::Acquire)
            || self.writer_pending.load(Ordering::Acquire)
        {
            return None;
        }

        self.diag.fast_path_attempts.fetch_add(1, Ordering::Relaxed);
        let token = current_thread_token();
        let [primary, secondary] = self.slot_candidates(token);
        let mut collided = false;

        for slot_index in [primary, secondary] {
            match self.visible_readers[slot_index].compare_exchange(
                EMPTY_SLOT,
                token,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if !self.reader_bias_enabled.load(Ordering::Acquire)
                        || self.writer_pending.load(Ordering::Acquire)
                    {
                        self.visible_readers[slot_index].store(EMPTY_SLOT, Ordering::Release);
                        self.diag.fast_path_aborts.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                    return Some(slot_index);
                }
                Err(existing) if existing == token => {
                    collided = true;
                    break;
                }
                Err(_) => collided = true,
            }
        }

        if collided {
            self.diag.slot_collisions.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    fn slot_candidates(&self, token: usize) -> [usize; 2] {
        let mask = self.visible_readers.len() - 1;
        let mixed = mix(token ^ self.lock_id);
        let primary = mixed & mask;
        let mut secondary = mix(mixed.rotate_left(17) ^ self.visible_readers.len()) & mask;
        if secondary == primary {
            secondary = (secondary + 1) & mask;
        }
        [primary, secondary]
    }

    fn wait_for_visible_readers(&self) -> u64 {
        let start = Instant::now();
        let mut spins = 0_u32;

        loop {
            if self
                .visible_readers
                .iter()
                .all(|slot| slot.load(Ordering::Acquire) == EMPTY_SLOT)
            {
                return u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
            }

            spins = spins.saturating_add(1);
            if spins.is_multiple_of(REVOCATION_YIELD_INTERVAL) {
                std::thread::yield_now();
            } else {
                spin_loop();
            }
        }
    }
}

impl<'a, T: Send + Sync> BravoReadGuard<'a, T> {
    /// Whether this read completed on the BRAVO fast path or the base slow path.
    #[must_use]
    pub fn path(&self) -> BravoReadPath {
        self.path
    }
}

impl<T: Send + Sync> Deref for BravoReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: shared access is valid because either:
        // 1. `_slow_guard` holds the base read lock, or
        // 2. `slot_index` marks this reader visible in the BRAVO table while
        //    `reader_bias_enabled` remained true after slot acquisition.
        // Writers must revoke bias, acquire the base write lock, and wait for
        // the visible-reader table to drain before taking mutable access.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: Send + Sync> Drop for BravoReadGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(slot_index) = self.slot_index.take() {
            self.lock.visible_readers[slot_index].store(EMPTY_SLOT, Ordering::Release);
        }
    }
}

impl<T: Send + Sync> Drop for WriterBiasReset<'_, T> {
    fn drop(&mut self) {
        self.lock.writer_pending.store(false, Ordering::Release);
        self.lock.reader_bias_enabled.store(true, Ordering::Release);
    }
}

impl<T: Send + Sync> Default for BravoRwLock<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Send + Sync> Drop for BravoRwLock<T> {
    fn drop(&mut self) {
        crate::alien_cs_metrics::emit_alien_cs_event(
            crate::alien_cs_metrics::MetricEventKind::ConceptDeactivated,
            self.diag.writes.load(Ordering::Relaxed),
            "bravo_rwlock",
        );
    }
}

// SAFETY: interior access is synchronized by the BRAVO protocol:
// fast-path readers publish a visible slot, slow-path readers hold the base
// `RwLock`, and writers revoke bias, acquire the base write lock, and wait for
// visible readers to drain before taking `&mut T`.
unsafe impl<T: Send + Sync> Sync for BravoRwLock<T> {}

fn current_thread_token() -> usize {
    THREAD_TOKEN.with(|token| *token)
}

fn mix(mut x: usize) -> usize {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd_usize);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53_usize);
    x ^ (x >> 33)
}

fn update_max(target: &AtomicU64, candidate: u64) {
    let mut current = target.load(Ordering::Relaxed);
    while candidate > current {
        match target.compare_exchange(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::left_right::LeftRight;
    use crate::rcu::{RcuCell, RcuReader};
    use serde_json::json;
    use std::collections::HashMap;
    use std::fs;
    use std::hint::black_box;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Barrier;

    #[test]
    fn basic_cycle_prefers_fast_path() {
        let lock = BravoRwLock::new(41_u64);
        let guard = lock.read();
        assert_eq!(guard.path(), BravoReadPath::Fast);
        assert_eq!(*guard, 41);
        drop(guard);

        lock.with_write(|value| *value = 42);

        let guard = lock.read();
        assert_eq!(guard.path(), BravoReadPath::Fast);
        assert_eq!(*guard, 42);

        let diag = lock.diagnostics();
        assert_eq!(diag.reads, 2);
        assert_eq!(diag.fast_path_reads, 2);
        assert_eq!(diag.slow_path_reads, 0);
        assert_eq!(diag.writes, 1);
    }

    #[test]
    fn writer_does_not_starve_readers_under_32_reader_load() {
        let lock = Arc::new(BravoRwLock::new(0_usize));
        let barrier = Arc::new(Barrier::new(34));
        let stop = Arc::new(AtomicBool::new(false));
        let read_counts: Arc<[AtomicU64]> = (0..32)
            .map(|_| AtomicU64::new(0))
            .collect::<Vec<_>>()
            .into();

        let mut handles = Vec::new();
        for reader_idx in 0..32 {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            let stop = Arc::clone(&stop);
            let read_counts = Arc::clone(&read_counts);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                while !stop.load(Ordering::Relaxed) {
                    let guard = lock.read();
                    black_box(*guard);
                    read_counts[reader_idx].fetch_add(1, Ordering::Relaxed);
                }
            }));
        }

        let writer = {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                barrier.wait();
                for step in 1..=256 {
                    lock.with_write(|value| *value = step);
                    if step.is_multiple_of(8) {
                        std::thread::yield_now();
                    }
                }
                stop.store(true, Ordering::Relaxed);
            })
        };

        barrier.wait();
        writer.join().expect("writer thread should finish");
        for handle in handles {
            handle.join().expect("reader thread should finish");
        }

        let final_value = lock.with_read(|value| *value);
        let diag = lock.diagnostics();
        assert_eq!(final_value, 256);
        assert_eq!(diag.writes, 256);
        assert!(
            read_counts
                .iter()
                .all(|count| count.load(Ordering::Relaxed) > 0),
            "every reader should make progress under writer activity"
        );
    }

    #[test]
    fn slot_collision_rate_stays_below_five_percent_at_64_threads() {
        let lock = Arc::new(BravoRwLock::new(7_u64));
        let ready = Arc::new(Barrier::new(65));
        let release = Arc::new(Barrier::new(65));

        let mut handles = Vec::new();
        for _ in 0..64 {
            let lock = Arc::clone(&lock);
            let ready = Arc::clone(&ready);
            let release = Arc::clone(&release);
            handles.push(std::thread::spawn(move || {
                ready.wait();
                let guard = lock.read();
                black_box(*guard);
                release.wait();
            }));
        }

        ready.wait();
        release.wait();
        for handle in handles {
            handle.join().expect("reader should join");
        }

        let diag = lock.diagnostics();
        assert!(
            diag.slot_collision_rate < 0.05,
            "slot collision rate should stay <5%, got {}",
            diag.slot_collision_rate
        );
    }

    #[test]
    fn metadata_comparison_artifact_is_written() {
        let report = json!({
            "scenario": "metadata_read_heavy",
            "reader_threads": 8,
            "writer_threads": 1,
            "read_iterations_per_thread": 4096,
            "write_iterations": 256,
            "results": [
                run_bravo_metadata_workload(),
                run_rcu_metadata_workload(),
                run_left_right_metadata_workload(),
            ],
        });

        let artifact_path = workspace_target_path("bravo_vs_rcu_vs_leftright.json");
        fs::create_dir_all(
            artifact_path
                .parent()
                .expect("artifact path should have a parent"),
        )
        .expect("artifact directory should be created");
        let encoded =
            serde_json::to_vec_pretty(&report).expect("comparison report should serialize");
        fs::write(&artifact_path, encoded).expect("comparison artifact should be written");

        assert!(artifact_path.exists(), "artifact should exist after write");
    }

    fn run_bravo_metadata_workload() -> serde_json::Value {
        let lock = Arc::new(BravoRwLock::new(seed_metadata()));
        let barrier = Arc::new(Barrier::new(9));
        let start = Instant::now();
        let mut handles = Vec::new();

        for reader_idx in 0..8 {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for iter in 0..4096 {
                    let key = ((reader_idx * 131) + iter) & 255;
                    let guard = lock.read();
                    black_box(guard.get(&key).copied().unwrap_or_default());
                }
            }));
        }

        let writer = {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for iter in 0..256 {
                    let key = iter & 255;
                    lock.with_write(|state| {
                        state.insert(key, iter as u64);
                    });
                }
            })
        };

        writer.join().expect("writer should join");
        for handle in handles {
            handle.join().expect("reader should join");
        }

        json!({
            "primitive": "bravo_rwlock",
            "elapsed_ns": start.elapsed().as_nanos(),
            "diagnostics": {
                "reads": lock.diagnostics().reads,
                "fast_path_reads": lock.diagnostics().fast_path_reads,
                "slow_path_reads": lock.diagnostics().slow_path_reads,
                "writes": lock.diagnostics().writes,
                "slot_collision_rate": lock.diagnostics().slot_collision_rate,
            }
        })
    }

    fn run_rcu_metadata_workload() -> serde_json::Value {
        let cell = Arc::new(RcuCell::new(seed_metadata()));
        let barrier = Arc::new(Barrier::new(9));
        let start = Instant::now();
        let mut handles = Vec::new();

        for reader_idx in 0..8 {
            let cell = Arc::clone(&cell);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut reader = RcuReader::new(&cell);
                barrier.wait();
                for iter in 0..4096 {
                    let key = ((reader_idx * 131) + iter) & 255;
                    black_box(reader.read().get(&key).copied().unwrap_or_default());
                }
            }));
        }

        let writer = {
            let cell = Arc::clone(&cell);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for iter in 0..256 {
                    let key = iter & 255;
                    cell.update_with(|state| {
                        let mut next = state.clone();
                        next.insert(key, iter as u64);
                        next
                    });
                }
            })
        };

        writer.join().expect("writer should join");
        for handle in handles {
            handle.join().expect("reader should join");
        }

        json!({
            "primitive": "rcu",
            "elapsed_ns": start.elapsed().as_nanos(),
            "diagnostics": {
                "epoch": cell.epoch(),
                "reader_count": cell.reader_count(),
            }
        })
    }

    fn run_left_right_metadata_workload() -> serde_json::Value {
        let lock = Arc::new(LeftRight::new(seed_metadata()));
        let barrier = Arc::new(Barrier::new(9));
        let start = Instant::now();
        let mut handles = Vec::new();

        for reader_idx in 0..8 {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut reader = lock.reader();
                barrier.wait();
                for iter in 0..4096 {
                    let key = ((reader_idx * 131) + iter) & 255;
                    black_box(reader.read().get(&key).copied().unwrap_or_default());
                }
            }));
        }

        let writer = {
            let lock = Arc::clone(&lock);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                for iter in 0..256 {
                    let key = iter & 255;
                    lock.write(|state| {
                        state.insert(key, iter as u64);
                    });
                }
            })
        };

        writer.join().expect("writer should join");
        for handle in handles {
            handle.join().expect("reader should join");
        }

        let diag = lock.diagnostics();
        json!({
            "primitive": "left_right",
            "elapsed_ns": start.elapsed().as_nanos(),
            "diagnostics": {
                "reads": diag.reads,
                "cache_hits": diag.cache_hits,
                "cache_misses": diag.cache_misses,
                "writes": diag.writes,
                "slow_drains": diag.slow_drains,
            }
        })
    }

    fn seed_metadata() -> HashMap<usize, u64> {
        (0..256).map(|idx| (idx, idx as u64)).collect()
    }

    fn workspace_target_path(file_name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(file_name)
    }
}
