//! Integration tests for the SeqLock module.
//!
//! Covers: TSM configuration hot-path scenarios, batched policy table updates,
//! reader cache effectiveness under varying contention, and writer starvation
//! resistance.

use frankenlibc_membrane::seqlock::{SeqLock, SeqLockReader};
use std::sync::{Arc, Barrier};
use std::thread;

// ──────────────── Locale configuration scenario ────────────────

#[derive(Debug, Clone, PartialEq)]
struct LocaleConfig {
    lc_ctype: String,
    lc_numeric: String,
    lc_time: String,
    lc_collate: String,
    lc_messages: String,
    use_utf8: bool,
}

impl Default for LocaleConfig {
    fn default() -> Self {
        Self {
            lc_ctype: "C".into(),
            lc_numeric: "C".into(),
            lc_time: "C".into(),
            lc_collate: "C".into(),
            lc_messages: "C".into(),
            use_utf8: false,
        }
    }
}

#[test]
fn locale_config_single_thread_lifecycle() {
    let sl = SeqLock::new(LocaleConfig::default());
    let mut reader = SeqLockReader::new(&sl);

    // Initial read.
    assert_eq!(reader.read().lc_ctype, "C");
    assert!(!reader.read().use_utf8);

    // Batched locale update (one version bump for all fields).
    {
        let mut guard = sl.write();
        guard.mutate(|c| c.lc_ctype = "en_US.UTF-8".into());
        guard.mutate(|c| c.lc_numeric = "en_US.UTF-8".into());
        guard.mutate(|c| c.lc_time = "en_US.UTF-8".into());
        guard.mutate(|c| c.use_utf8 = true);
    }

    // Reader sees all changes atomically after one version bump.
    assert_eq!(sl.version(), 2);
    let config = reader.read();
    assert_eq!(config.lc_ctype, "en_US.UTF-8");
    assert_eq!(config.lc_numeric, "en_US.UTF-8");
    assert!(config.use_utf8);
    // Unchanged fields preserved.
    assert_eq!(config.lc_collate, "C");
}

#[test]
fn locale_config_concurrent_readers() {
    let sl = Arc::new(SeqLock::new(LocaleConfig::default()));
    let barrier = Arc::new(Barrier::new(9)); // 8 readers + 1 writer
    let mut handles = Vec::new();

    // 8 reader threads.
    for _ in 0..8 {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl);
            barrier.wait();
            let mut saw_utf8 = false;
            for _ in 0..2000 {
                let config = reader.read();
                // Must see consistent snapshots: if use_utf8 is true,
                // lc_ctype must also be updated.
                if config.use_utf8 {
                    assert_eq!(
                        config.lc_ctype, "en_US.UTF-8",
                        "must see atomic update: utf8 flag and ctype must agree"
                    );
                    saw_utf8 = true;
                }
            }
            saw_utf8
        }));
    }

    // Writer thread.
    barrier.wait();
    for _ in 0..100 {
        let mut guard = sl.write();
        guard.mutate(|c| {
            c.lc_ctype = "en_US.UTF-8".into();
            c.use_utf8 = true;
        });
    }

    for h in handles {
        h.join().expect("reader panicked");
    }
}

// ──────────────── TSM policy table scenario ────────────────

#[derive(Debug, Clone, PartialEq)]
struct TsmPolicyTable {
    max_heal_attempts: u32,
    quarantine_threshold: u64,
    bloom_false_positive_target_ppm: u32,
    arena_generation_limit: u32,
    validation_timeout_ns: u64,
    families_enabled: [bool; 20],
}

impl Default for TsmPolicyTable {
    fn default() -> Self {
        Self {
            max_heal_attempts: 3,
            quarantine_threshold: 1000,
            bloom_false_positive_target_ppm: 100,
            arena_generation_limit: 256,
            validation_timeout_ns: 1_000_000,
            families_enabled: [true; 20],
        }
    }
}

#[test]
fn policy_table_batched_update() {
    let sl = SeqLock::new(TsmPolicyTable::default());
    let mut reader = SeqLockReader::new(&sl);

    // Simulate a config reload that changes multiple policy knobs.
    {
        let mut guard = sl.write();
        guard.mutate(|p| p.max_heal_attempts = 5);
        guard.mutate(|p| p.quarantine_threshold = 5000);
        guard.mutate(|p| p.bloom_false_positive_target_ppm = 50);
        guard.mutate(|p| p.validation_timeout_ns = 500_000);
        // Disable two API families.
        guard.mutate(|p| {
            p.families_enabled[3] = false;
            p.families_enabled[7] = false;
        });
    }

    // Single version bump.
    assert_eq!(sl.version(), 2);

    let policy = reader.read();
    assert_eq!(policy.max_heal_attempts, 5);
    assert_eq!(policy.quarantine_threshold, 5000);
    assert_eq!(policy.bloom_false_positive_target_ppm, 50);
    assert!(!policy.families_enabled[3]);
    assert!(!policy.families_enabled[7]);
    assert!(policy.families_enabled[0]); // unchanged
}

#[test]
fn policy_table_read_if_changed_efficiency() {
    let sl = SeqLock::new(TsmPolicyTable::default());
    let mut reader = SeqLockReader::new(&sl);

    // First read to prime cache.
    let _ = reader.read();

    // 1000 reads without write: all should be "unchanged".
    let mut none_count = 0u32;
    for _ in 0..1000 {
        if reader.read_if_changed().is_none() {
            none_count += 1;
        }
    }
    assert_eq!(none_count, 1000, "all reads should be cache hits");

    // Now write, and next read_if_changed should return Some.
    sl.write_with(|p| p.max_heal_attempts = 10);
    let changed = reader.read_if_changed();
    assert!(changed.is_some());
    assert_eq!(changed.unwrap().max_heal_attempts, 10);
}

// ──────────────── Environment variable snapshot ────────────────

#[derive(Debug, Clone)]
struct EnvSnapshot {
    frankenlibc_mode: String,
    frankenlibc_log: String,
    _ld_preload: Option<String>,
    debug_flags: u64,
}

impl Default for EnvSnapshot {
    fn default() -> Self {
        Self {
            frankenlibc_mode: "strict".into(),
            frankenlibc_log: "warn".into(),
            _ld_preload: None,
            debug_flags: 0,
        }
    }
}

#[test]
fn env_snapshot_versioned_caching() {
    let sl = SeqLock::new(EnvSnapshot::default());
    let mut reader = SeqLockReader::new(&sl);

    // Simulate startup: read env.
    let env = reader.read();
    assert_eq!(env.frankenlibc_mode, "strict");

    // Simulate runtime config change.
    sl.write_with(|e| {
        e.frankenlibc_mode = "hardened".into();
        e.frankenlibc_log = "debug".into();
        e.debug_flags = 0xFF;
    });

    // Reader picks up change on next read.
    let env = reader.read();
    assert_eq!(env.frankenlibc_mode, "hardened");
    assert_eq!(env.frankenlibc_log, "debug");
    assert_eq!(env.debug_flags, 0xFF);
}

// ──────────────── Cache effectiveness scaling ────────────────

#[test]
fn cache_effectiveness_scales_with_read_write_ratio() {
    // High read/write ratio should yield high cache hit ratio.
    let sl = Arc::new(SeqLock::new(0u64));

    // 1 writer doing 10 writes.
    let sl_w = Arc::clone(&sl);
    let writer = thread::spawn(move || {
        for i in 1..=10u64 {
            sl_w.write_with(|d| *d = i);
            // Small pause to space out writes.
            thread::yield_now();
        }
    });

    // 4 readers doing 5000 reads each.
    let mut reader_handles = Vec::new();
    for _ in 0..4 {
        let sl = Arc::clone(&sl);
        reader_handles.push(thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl);
            for _ in 0..5000 {
                let _ = reader.read();
            }
        }));
    }

    writer.join().expect("writer panicked");
    for h in reader_handles {
        h.join().expect("reader panicked");
    }

    let d = sl.diagnostics();
    // With 10 writes and 20000+ reads, hit ratio should be high.
    assert!(d.reads > 0);
    assert!(d.cache_hits > d.cache_misses, "cache hits should dominate");
    assert!(
        d.hit_ratio > 0.95,
        "hit ratio should stay above 95% under read-heavy load, got {:.3}",
        d.hit_ratio
    );
}

// ──────────────── Writer starvation resistance ────────────────

#[test]
fn writers_complete_under_heavy_read_load() {
    let sl = Arc::new(SeqLock::new(0u64));
    let barrier = Arc::new(Barrier::new(9));
    let mut handles = Vec::new();

    // 8 aggressive reader threads.
    for _ in 0..8 {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl);
            barrier.wait();
            for _ in 0..50_000 {
                let _ = reader.read();
            }
        }));
    }

    // 1 writer thread that must complete all writes despite reader pressure.
    let sl_w = Arc::clone(&sl);
    let barrier_w = Arc::clone(&barrier);
    let writer = thread::spawn(move || {
        barrier_w.wait();
        for i in 1..=500u64 {
            sl_w.write_with(|d| *d = i);
        }
    });

    writer.join().expect("writer must complete (no starvation)");
    for h in handles {
        h.join().expect("reader panicked");
    }

    assert_eq!(*sl.load(), 500, "all writes must have completed");
}

// ──────────────── Multi-writer serialization ────────────────

#[test]
fn multi_writer_increments_are_exact() {
    let sl = Arc::new(SeqLock::new(0u64));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..500 {
                sl.write_with(|d| *d += 1);
            }
        }));
    }

    for h in handles {
        h.join().expect("writer panicked");
    }

    assert_eq!(*sl.load(), 4000, "8 writers × 500 = 4000");
    let d = sl.diagnostics();
    assert_eq!(d.writes, 4000);
}

// ──────────────── Diagnostics integration ────────────────

#[test]
fn diagnostics_comprehensive_under_mixed_load() {
    let sl = Arc::new(SeqLock::new(0u64));
    let barrier = Arc::new(Barrier::new(5));

    // 2 readers.
    let mut reader_handles = Vec::new();
    for _ in 0..2 {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        reader_handles.push(thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl);
            barrier.wait();
            for _ in 0..3000 {
                let _ = reader.read();
            }
        }));
    }

    // 2 writers.
    let mut writer_handles = Vec::new();
    for _ in 0..2 {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        writer_handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..200 {
                sl.write_with(|d| *d += 1);
            }
        }));
    }

    // 1 batched writer.
    let sl_b = Arc::clone(&sl);
    barrier.wait();
    for _ in 0..50 {
        let mut guard = sl_b.write();
        guard.mutate(|d| *d += 1);
        guard.mutate(|d| *d += 1);
    }

    for h in reader_handles {
        h.join().expect("reader panicked");
    }
    for h in writer_handles {
        h.join().expect("writer panicked");
    }

    let d = sl.diagnostics();
    // 2 writers × 200 + 50 batched = 450 writes.
    assert_eq!(d.writes, 450);
    // Reads should be significant.
    assert!(d.reads > 0);
    // Value: 2 × 200 + 50 × 2 = 500.
    assert_eq!(*sl.load(), 500);
}

// ──────────────── Snapshot consistency guarantee ────────────────

#[derive(Debug, Clone)]
struct ConsistencyProbe {
    field_a: u64,
    field_b: u64,
    /// Invariant: field_a + field_b == 1000.
    _invariant_sum: u64,
}

impl ConsistencyProbe {
    fn new() -> Self {
        Self {
            field_a: 500,
            field_b: 500,
            _invariant_sum: 1000,
        }
    }
}

#[test]
fn snapshot_consistency_invariant_never_violated() {
    let sl = Arc::new(SeqLock::new(ConsistencyProbe::new()));
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();

    // 4 readers checking invariant.
    for _ in 0..4 {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl);
            barrier.wait();
            for _ in 0..10_000 {
                let probe = reader.read();
                assert_eq!(
                    probe.field_a + probe.field_b,
                    1000,
                    "consistency invariant violated: {} + {} != 1000",
                    probe.field_a,
                    probe.field_b
                );
            }
        }));
    }

    // Writer shifts balance between fields while maintaining invariant.
    barrier.wait();
    for i in 0..500u64 {
        sl.write_with(|p| {
            p.field_a = i;
            p.field_b = 1000 - i;
        });
    }

    for h in handles {
        h.join().expect("reader panicked — invariant violated");
    }
}

// ──────────────── Version monotonicity ────────────────

#[test]
fn versions_are_strictly_monotonic() {
    let sl = Arc::new(SeqLock::new(0u64));
    let barrier = Arc::new(Barrier::new(2));

    let sl_r = Arc::clone(&sl);
    let bar_r = Arc::clone(&barrier);
    let reader = thread::spawn(move || {
        let mut reader = SeqLockReader::new(&sl_r);
        bar_r.wait();
        let mut prev_version = 0u64;
        for _ in 0..10_000 {
            let _ = reader.read();
            let v = reader.cached_version();
            assert!(v >= prev_version, "version must not go backward");
            prev_version = v;
        }
    });

    let sl_w = Arc::clone(&sl);
    let bar_w = Arc::clone(&barrier);
    let writer = thread::spawn(move || {
        bar_w.wait();
        for i in 1..=1000u64 {
            sl_w.write_with(|d| *d = i);
        }
    });

    writer.join().expect("writer panicked");
    reader.join().expect("reader panicked");
}
