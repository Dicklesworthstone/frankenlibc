//! Cross-concept integration tests for Alien CS concurrency primitives.
//!
//! Verifies that RCU, Flat Combining, SeqLock, and EBR work correctly
//! when composed together in realistic TSM pipeline scenarios.

use frankenlibc_membrane::ebr::{EbrCollector, QuarantineEbr};
use frankenlibc_membrane::flat_combining::FlatCombiner;
use frankenlibc_membrane::rcu::{RcuCell, RcuReader};
use frankenlibc_membrane::seqlock::{SeqLock, SeqLockReader};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ──────────────── RCU + SeqLock: config-driven snapshot ────────────────

/// Simulates TSM hot path: SeqLock holds policy config, RCU holds runtime state.
/// Config changes trigger RCU state rebuild.
#[derive(Debug, Clone, PartialEq)]
struct PolicyConfig {
    max_retries: u32,
    quarantine_depth: u64,
    bloom_capacity: u32,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            quarantine_depth: 4096,
            bloom_capacity: 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct RuntimeSnapshot {
    config_version: u64,
    risk_score: u64,
    active_healings: u32,
}

#[test]
fn rcu_snapshot_rebuilds_on_seqlock_config_change() {
    let config = SeqLock::new(PolicyConfig::default());
    let state = RcuCell::new(RuntimeSnapshot {
        config_version: config.version(),
        risk_score: 0,
        active_healings: 0,
    });

    let mut config_reader = SeqLockReader::new(&config);
    let mut state_reader = RcuReader::new(&state);

    // Verify initial consistency.
    let cfg = config_reader.read();
    let snap = state_reader.read();
    assert_eq!(snap.config_version, config.version());
    assert_eq!(cfg.max_retries, 3);

    // Update config → triggers state rebuild.
    config.write_with(|c| c.max_retries = 5);
    let new_version = config.version();

    state.update(RuntimeSnapshot {
        config_version: new_version,
        risk_score: 100,
        active_healings: 2,
    });

    // Both readers pick up changes.
    let cfg = config_reader.read();
    let snap = state_reader.read();
    assert_eq!(cfg.max_retries, 5);
    assert_eq!(snap.config_version, new_version);
    assert_eq!(snap.risk_score, 100);
}

#[test]
fn concurrent_rcu_and_seqlock_consistency() {
    let config = Arc::new(SeqLock::new(PolicyConfig::default()));
    let state = Arc::new(RcuCell::new(RuntimeSnapshot {
        config_version: 1,
        risk_score: 0,
        active_healings: 0,
    }));
    let barrier = Arc::new(Barrier::new(5));

    // 4 reader threads: each reads config + state and checks version consistency.
    let mut handles = Vec::new();
    for _ in 0..4 {
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut cfg_reader = SeqLockReader::new(&config);
            let mut state_reader = RcuReader::new(&state);
            barrier.wait();
            for _ in 0..5000 {
                let _cfg = cfg_reader.read();
                let snap = state_reader.read();
                // Risk score should always be non-negative (no torn reads).
                assert!(snap.risk_score <= 10000);
            }
        }));
    }

    // Writer thread: updates config and rebuilds state.
    barrier.wait();
    for i in 1..=500u64 {
        config.write_with(|c| c.max_retries = (i % 10) as u32);
        state.update(RuntimeSnapshot {
            config_version: config.version(),
            risk_score: i * 2,
            active_healings: (i % 5) as u32,
        });
    }

    for h in handles {
        h.join().expect("reader panicked");
    }
}

// ──────────────── Flat Combining + EBR: batched retirement ────────────────

/// FlatCombiner manages a shared counter. When the counter crosses thresholds,
/// old state is retired through EBR.
#[derive(Debug, Default)]
struct CounterState {
    value: u64,
    _retirements: u64,
}

#[derive(Debug)]
enum CounterOp {
    Increment(u64),
    GetValue,
}

#[test]
fn flat_combiner_retires_state_through_ebr() {
    let fc = FlatCombiner::new(CounterState::default(), 8);
    let collector = EbrCollector::new();
    let retired_count = Arc::new(AtomicU64::new(0));

    // Increment counter, retiring old state snapshots every 100 increments.
    for i in 0..500u64 {
        let value = fc.execute(CounterOp::Increment(1), |state, op| match op {
            CounterOp::Increment(n) => {
                state.value += n;
                state.value
            }
            CounterOp::GetValue => state.value,
        });

        if i.is_multiple_of(100) {
            let cnt = Arc::clone(&retired_count);
            let snapshot_value = value;
            collector.retire(move || {
                // Verify snapshot is still valid at reclamation time.
                assert!(snapshot_value > 0);
                cnt.fetch_add(1, Ordering::Relaxed);
            });
        }
    }

    // Reclaim all.
    for _ in 0..5 {
        collector.try_advance();
    }

    let final_value = fc.execute(CounterOp::GetValue, |state, op| match op {
        CounterOp::Increment(n) => {
            state.value += n;
            state.value
        }
        CounterOp::GetValue => state.value,
    });
    assert_eq!(final_value, 500);
    assert_eq!(retired_count.load(Ordering::Relaxed), 5); // 0, 100, 200, 300, 400
}

#[test]
fn concurrent_flat_combining_with_ebr_retirement() {
    let fc = Arc::new(FlatCombiner::new(0u64, 16));
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(4));
    let retired = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..4 {
        let fc = Arc::clone(&fc);
        let collector = Arc::clone(&collector);
        let barrier = Arc::clone(&barrier);
        let retired = Arc::clone(&retired);
        handles.push(thread::spawn(move || {
            let h = collector.register();
            barrier.wait();
            for _ in 0..200 {
                let g = h.pin();
                let val = fc.execute(1u64, |state, op| {
                    *state += op;
                    *state
                });
                if val.is_multiple_of(50) {
                    let r = Arc::clone(&retired);
                    g.retire(move || {
                        r.fetch_add(1, Ordering::Relaxed);
                    });
                }
                drop(g);
                collector.try_advance();
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    for _ in 0..10 {
        collector.try_advance();
    }

    assert_eq!(fc.with_state_ref(|s| *s), 800);
}

// ──────────────── SeqLock + EBR: config reload with old config cleanup ────────────────

#[test]
fn seqlock_config_reload_retires_old_through_ebr() {
    let config = SeqLock::new(PolicyConfig::default());
    let collector = EbrCollector::new();
    let cleanup_count = Arc::new(AtomicU64::new(0));

    for i in 0..10 {
        // Snapshot old config before replacing.
        let old = (*config.load()).clone();
        let cnt = Arc::clone(&cleanup_count);
        collector.retire(move || {
            // Old config cleanup — verify it was valid.
            assert!(old.max_retries <= 20);
            cnt.fetch_add(1, Ordering::Relaxed);
        });

        config.write_with(|c| c.max_retries = i + 1);
    }

    for _ in 0..5 {
        collector.try_advance();
    }

    assert_eq!(cleanup_count.load(Ordering::Relaxed), 10);
    assert_eq!(config.load().max_retries, 10);
}

// ──────────────── RCU + Flat Combining: snapshot-driven batch ops ────────────────

#[derive(Debug, Clone)]
struct BatchConfig {
    max_batch_size: usize,
    _timeout_ms: u64,
}

#[test]
fn rcu_config_drives_flat_combiner_behavior() {
    let config = RcuCell::new(BatchConfig {
        max_batch_size: 4,
        _timeout_ms: 100,
    });
    let fc = FlatCombiner::new(Vec::<u64>::new(), 8);

    // Add items, reading config for batch-size awareness.
    let mut reader = RcuReader::new(&config);
    for i in 0..20u64 {
        let batch_size = reader.read().max_batch_size;
        fc.execute(i, |state, op| {
            state.push(op);
            if state.len() > batch_size * 10 {
                state.truncate(batch_size);
            }
            state.len()
        });
    }

    // Update config to larger batch size.
    config.update(BatchConfig {
        max_batch_size: 16,
        _timeout_ms: 200,
    });
    let new_batch = reader.read().max_batch_size;
    assert_eq!(new_batch, 16);

    let final_len = fc.execute(999u64, |state, op| {
        state.push(op);
        state.len()
    });
    assert!(final_len > 0);
}

// ──────────────── QuarantineEbr + RCU: UAF detection in state transitions ────────────────

#[test]
fn quarantine_ebr_detects_stale_rcu_snapshots() {
    let state = RcuCell::new(42u64);
    let qebr = QuarantineEbr::new(2);
    let probe = Arc::new(AtomicBool::new(false));

    // Take a snapshot, then retire the "old state reference."
    let old_snapshot = state.load();
    assert_eq!(*old_snapshot, 42);

    state.update(99);

    // Retire old snapshot marker through quarantine.
    let p = Arc::clone(&probe);
    let old_val = *old_snapshot;
    qebr.retire_quarantined(move || {
        // At reclamation time, verify old value was correct.
        assert_eq!(old_val, 42);
        p.store(true, Ordering::Relaxed);
    });

    // Quarantine holds for 2 extra epochs.
    qebr.try_advance(); // epoch 1
    assert!(!probe.load(Ordering::Relaxed));
    qebr.try_advance(); // epoch 2
    assert!(!probe.load(Ordering::Relaxed));
    qebr.try_advance(); // epoch 3
    assert!(!probe.load(Ordering::Relaxed));
    qebr.try_advance(); // epoch 4 — should release
    assert!(probe.load(Ordering::Relaxed));

    // Current state is 99.
    assert_eq!(*state.load(), 99);
}

// ──────────────── All four concepts: full TSM pipeline simulation ────────────────

#[derive(Debug, Clone)]
struct TsmConfig {
    safety_level: u8, // 0=off, 1=strict, 2=hardened
    heal_enabled: bool,
}

impl Default for TsmConfig {
    fn default() -> Self {
        Self {
            safety_level: 1,
            heal_enabled: false,
        }
    }
}

#[derive(Debug, Clone)]
struct ValidationState {
    total_validations: u64,
    _total_heals: u64,
    risk_ppm: u64,
}

#[test]
fn full_tsm_pipeline_four_concepts() {
    // SeqLock: TSM configuration (rarely changed).
    let config = Arc::new(SeqLock::new(TsmConfig::default()));

    // RCU: Validation pipeline state (read on every call).
    let state = Arc::new(RcuCell::new(ValidationState {
        total_validations: 0,
        _total_heals: 0,
        risk_ppm: 0,
    }));

    // FlatCombiner: Metrics aggregation under contention.
    let metrics = Arc::new(FlatCombiner::new(0u64, 16));

    // EBR: Old state snapshots retired safely.
    let collector = Arc::new(EbrCollector::new());

    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();

    // 4 "validation pipeline" threads.
    for tid in 0..4u64 {
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let metrics = Arc::clone(&metrics);
        let collector = Arc::clone(&collector);
        let barrier = Arc::clone(&barrier);

        handles.push(thread::spawn(move || {
            let h = collector.register();
            let mut cfg_reader = SeqLockReader::new(&config);
            let mut state_reader = RcuReader::new(&state);
            barrier.wait();

            for i in 0..500u64 {
                // 1. Pin EBR epoch.
                let guard = h.pin();

                // 2. Read config via SeqLock (1 atomic load hot path).
                let cfg = cfg_reader.read();

                // 3. Read state via RCU (1 atomic load hot path).
                let snap = state_reader.read();

                // 4. Simulate validation decision.
                let should_heal = cfg.heal_enabled && snap.risk_ppm > 500;

                // 5. Record metric via Flat Combining.
                metrics.execute(1u64, |total, op| {
                    *total += op;
                    *total
                });

                // 6. Periodically retire old state.
                if i.is_multiple_of(100) {
                    let val = snap.total_validations;
                    guard.retire(move || {
                        std::hint::black_box(val);
                    });
                }

                // 7. Periodically advance EBR.
                if i.is_multiple_of(50) {
                    collector.try_advance();
                }

                drop(guard);

                // Suppress unused variable warning.
                std::hint::black_box(should_heal);
                std::hint::black_box(tid);
            }
        }));
    }

    // Main thread: periodically update config and state.
    barrier.wait();
    for i in 0..50 {
        // Update config.
        config.write_with(|c| {
            c.heal_enabled = i > 25;
            c.safety_level = if i > 40 { 2 } else { 1 };
        });

        // Update state.
        state.update(ValidationState {
            total_validations: i as u64 * 100,
            _total_heals: if i > 25 { i as u64 * 10 } else { 0 },
            risk_ppm: i as u64 * 20,
        });

        thread::yield_now();
    }

    for h in handles {
        h.join().expect("pipeline thread panicked");
    }

    // Final cleanup.
    for _ in 0..10 {
        collector.try_advance();
    }

    // Verify aggregate metrics.
    let total_ops = metrics.with_state_ref(|s| *s);
    assert_eq!(total_ops, 2000, "4 threads × 500 ops = 2000");

    // Verify diagnostics.
    let metrics_diag = metrics.diagnostics();
    assert_eq!(metrics_diag.total_ops, 2000);
    assert!(metrics_diag.total_passes > 0);
    assert_eq!(metrics_diag.active_slots, 0);
    assert!(
        metrics_diag.avg_batch_size >= 1.0,
        "flat combining average batch size must remain valid"
    );

    let ebr_diag = collector.diagnostics();
    assert_eq!(ebr_diag.total_retired, 20); // 4 threads × 5 retirements each
    assert!(
        ebr_diag.total_reclaimed <= ebr_diag.total_retired,
        "EBR cannot reclaim more entries than were retired"
    );
    assert_eq!(ebr_diag.active_threads, 0);

    let config_diag = config.diagnostics();
    assert!(config_diag.reads >= 2000);
    assert!(config_diag.cache_hits > config_diag.cache_misses);
    assert!(
        config_diag.hit_ratio > 0.5,
        "SeqLock hit ratio should remain above 50% even with periodic reloads, got {:.3}",
        config_diag.hit_ratio
    );
    assert_eq!(config_diag.writes, 50);
    assert_eq!(
        state.reader_count(),
        0,
        "all RCU readers should release cached snapshots after the pipeline run"
    );
}
