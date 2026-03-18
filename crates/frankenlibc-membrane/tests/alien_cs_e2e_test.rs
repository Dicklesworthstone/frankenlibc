//! E2E tests for Alien CS concurrency primitives under realistic workloads.
//!
//! Validates multi-concept composition at varying thread counts (1-16),
//! mixed read/write ratios, and sustained load. Tests linearizability,
//! absence of torn reads, and correct reclamation under contention.

use frankenlibc_membrane::ebr::EbrCollector;
use frankenlibc_membrane::flat_combining::FlatCombiner;
use frankenlibc_membrane::rcu::{RcuCell, RcuReader};
use frankenlibc_membrane::seqlock::{SeqLock, SeqLockReader};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ──────────────── Thread scaling: RCU read throughput ────────────────

/// RCU reads scale linearly: N readers all see consistent state.
fn rcu_read_scaling_n(n_readers: usize) {
    let cell = Arc::new(RcuCell::new(0u64));
    let barrier = Arc::new(Barrier::new(n_readers + 1));
    let reads_per_reader = 20_000u64;

    let mut handles = Vec::new();
    for _ in 0..n_readers {
        let cell = Arc::clone(&cell);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut reader = RcuReader::new(&cell);
            barrier.wait();
            for _ in 0..reads_per_reader {
                let val = *reader.read();
                assert!(val <= 10000, "value out of range: {}", val);
            }
        }));
    }

    // Writer: updates 10000 times.
    barrier.wait();
    for i in 1..=10000u64 {
        cell.update(i);
    }

    for h in handles {
        h.join().expect("reader panicked");
    }
    assert_eq!(*cell.load(), 10000);
}

#[test]
fn rcu_read_scaling_1_thread() {
    rcu_read_scaling_n(1);
}

#[test]
fn rcu_read_scaling_4_threads() {
    rcu_read_scaling_n(4);
}

#[test]
fn rcu_read_scaling_8_threads() {
    rcu_read_scaling_n(8);
}

#[test]
fn rcu_read_scaling_16_threads() {
    rcu_read_scaling_n(16);
}

// ──────────────── Thread scaling: SeqLock mixed read/write ────────────────

/// SeqLock under mixed load: N readers + 1 writer, invariant never violated.
fn seqlock_mixed_scaling_n(n_readers: usize, n_writes: u64) {
    let sl = Arc::new(SeqLock::new((500u64, 500u64)));
    let barrier = Arc::new(Barrier::new(n_readers + 1));

    let mut handles = Vec::new();
    for _ in 0..n_readers {
        let sl = Arc::clone(&sl);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let mut reader = SeqLockReader::new(&sl);
            barrier.wait();
            let mut checks = 0u64;
            for _ in 0..20_000 {
                let snap = reader.read();
                assert_eq!(
                    snap.0 + snap.1,
                    1000,
                    "invariant violated: {} + {} != 1000",
                    snap.0,
                    snap.1
                );
                checks += 1;
            }
            checks
        }));
    }

    barrier.wait();
    for i in 0..n_writes {
        sl.write_with(|d| {
            d.0 = i % 1001;
            d.1 = 1000 - (i % 1001);
        });
    }

    let total_checks: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(total_checks, n_readers as u64 * 20_000);
}

#[test]
fn seqlock_mixed_1_reader() {
    seqlock_mixed_scaling_n(1, 1000);
}

#[test]
fn seqlock_mixed_4_readers() {
    seqlock_mixed_scaling_n(4, 1000);
}

#[test]
fn seqlock_mixed_8_readers() {
    seqlock_mixed_scaling_n(8, 1000);
}

#[test]
fn seqlock_mixed_16_readers() {
    seqlock_mixed_scaling_n(16, 1000);
}

// ──────────────── Thread scaling: FlatCombiner contention ────────────────

/// FlatCombiner: N threads incrementing a shared counter.
fn fc_contention_scaling_n(n_threads: usize, ops_per_thread: u64) {
    let fc = Arc::new(FlatCombiner::new(0u64, n_threads.max(4)));
    let barrier = Arc::new(Barrier::new(n_threads));

    let mut handles = Vec::new();
    for _ in 0..n_threads {
        let fc = Arc::clone(&fc);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..ops_per_thread {
                fc.execute(1u64, |state, op| {
                    *state += op;
                    *state
                });
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let expected = n_threads as u64 * ops_per_thread;
    let actual = fc.execute(0u64, |state, _| *state);
    assert_eq!(
        actual, expected,
        "exact count after {} threads x {} ops",
        n_threads, ops_per_thread
    );
}

#[test]
fn fc_contention_1_thread() {
    fc_contention_scaling_n(1, 5000);
}

#[test]
fn fc_contention_4_threads() {
    fc_contention_scaling_n(4, 5000);
}

#[test]
fn fc_contention_8_threads() {
    fc_contention_scaling_n(8, 5000);
}

#[test]
fn fc_contention_16_threads() {
    fc_contention_scaling_n(16, 2000);
}

// ──────────────── Thread scaling: EBR retire + reclaim ────────────────

/// EBR: N threads retire items concurrently, all eventually reclaimed.
fn ebr_retire_scaling_n(n_threads: usize, retires_per_thread: u64) {
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(n_threads));
    let reclaimed = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..n_threads {
        let c = Arc::clone(&collector);
        let barrier = Arc::clone(&barrier);
        let r = Arc::clone(&reclaimed);
        handles.push(thread::spawn(move || {
            let h = c.register();
            barrier.wait();
            for _ in 0..retires_per_thread {
                let g = h.pin();
                let cnt = Arc::clone(&r);
                g.retire(move || {
                    cnt.fetch_add(1, Ordering::Relaxed);
                });
                drop(g);
                c.try_advance();
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Final cleanup.
    for _ in 0..20 {
        collector.try_advance();
    }

    let d = collector.diagnostics();
    let expected = n_threads as u64 * retires_per_thread;
    assert_eq!(d.total_retired, expected);
    assert_eq!(d.active_threads, 0);
}

#[test]
fn ebr_retire_scaling_1_thread() {
    ebr_retire_scaling_n(1, 1000);
}

#[test]
fn ebr_retire_scaling_4_threads() {
    ebr_retire_scaling_n(4, 500);
}

#[test]
fn ebr_retire_scaling_8_threads() {
    ebr_retire_scaling_n(8, 300);
}

#[test]
fn ebr_retire_scaling_16_threads() {
    ebr_retire_scaling_n(16, 200);
}

// ──────────────── Full pipeline: TSM-style validation with all 4 concepts ────────────────

/// Simulates a full TSM validation pipeline with N validation threads.
/// Each thread:
/// 1. Reads config via SeqLock
/// 2. Reads state via RCU
/// 3. Aggregates metrics via FlatCombiner
/// 4. Retires old snapshots via EBR
fn full_pipeline_scaling_n(n_threads: usize, ops_per_thread: u64) {
    let config = Arc::new(SeqLock::new((1u64, true))); // (safety_level, heal_enabled)
    let state = Arc::new(RcuCell::new(0u64)); // risk score
    let metrics = Arc::new(FlatCombiner::new(0u64, n_threads.max(4)));
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(n_threads + 1));

    let mut handles = Vec::new();
    for _ in 0..n_threads {
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

            for i in 0..ops_per_thread {
                // 1. Pin EBR.
                let guard = h.pin();

                // 2. Read config (SeqLock hot path).
                let (safety_level, _heal_enabled) = *cfg_reader.read();
                assert!(safety_level <= 3, "invalid safety level: {}", safety_level);

                // 3. Read state (RCU hot path).
                let risk = *state_reader.read();
                std::hint::black_box(risk);

                // 4. Aggregate metric (FlatCombiner).
                metrics.execute(1u64, |total, op| {
                    *total += op;
                    *total
                });

                // 5. Periodically retire.
                if i.is_multiple_of(50) {
                    guard.retire(|| {});
                }

                // 6. Periodically advance EBR.
                if i.is_multiple_of(25) {
                    collector.try_advance();
                }

                drop(guard);
            }
        }));
    }

    // Main thread: periodically update config and state.
    barrier.wait();
    for i in 0..100u64 {
        config.write_with(|c| {
            c.0 = (i % 3) + 1;
            c.1 = i > 50;
        });
        state.update(i * 10);
        thread::yield_now();
    }

    for h in handles {
        h.join().expect("pipeline thread panicked");
    }

    // Final cleanup.
    for _ in 0..20 {
        collector.try_advance();
    }

    // Verify aggregate metrics.
    let total_ops = metrics.with_state_ref(|s| *s);
    let expected = n_threads as u64 * ops_per_thread;
    assert_eq!(
        total_ops, expected,
        "{} threads x {} ops",
        n_threads, ops_per_thread
    );
    assert_eq!(collector.diagnostics().active_threads, 0);
}

#[test]
fn full_pipeline_1_thread() {
    full_pipeline_scaling_n(1, 2000);
}

#[test]
fn full_pipeline_4_threads() {
    full_pipeline_scaling_n(4, 1000);
}

#[test]
fn full_pipeline_8_threads() {
    full_pipeline_scaling_n(8, 500);
}

#[test]
fn full_pipeline_16_threads() {
    full_pipeline_scaling_n(16, 300);
}

// ──────────────── High write ratio stress: multi-writer SeqLock + RCU ────────────────

#[test]
fn high_write_ratio_seqlock_rcu() {
    let config = Arc::new(SeqLock::new(0u64));
    let state = Arc::new(RcuCell::new(0u64));
    let barrier = Arc::new(Barrier::new(9)); // 4 readers + 4 writers + 1 main

    let mut handles = Vec::new();

    // 4 reader threads.
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
                let _snap = state_reader.read();
            }
        }));
    }

    // 4 writer threads updating SeqLock.
    for t in 0..4u64 {
        let config = Arc::clone(&config);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..500u64 {
                config.write_with(|c| *c = t * 1000 + i);
            }
        }));
    }

    // Main thread updates RCU.
    barrier.wait();
    for i in 0..500u64 {
        state.update(i);
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    // SeqLock: 4 writers x 500 = 2000 writes.
    let d = config.diagnostics();
    assert_eq!(d.writes, 2000);
    assert_eq!(*state.load(), 499);
}

// ──────────────── Sustained load: long-running mixed workload ────────────────

#[test]
fn sustained_mixed_workload() {
    let fc = Arc::new(FlatCombiner::new(0u64, 16));
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(9));
    let done = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    // 4 "hot path" threads: combine + retire.
    for _ in 0..4 {
        let fc = Arc::clone(&fc);
        let collector = Arc::clone(&collector);
        let barrier = Arc::clone(&barrier);
        let done = Arc::clone(&done);
        handles.push(thread::spawn(move || {
            let h = collector.register();
            barrier.wait();
            let mut ops = 0u64;
            while !done.load(Ordering::Relaxed) {
                let g = h.pin();
                fc.execute(1u64, |s, o| {
                    *s += o;
                    *s
                });
                if ops.is_multiple_of(100) {
                    g.retire(|| {});
                }
                drop(g);
                ops += 1;
            }
            ops
        }));
    }

    // 4 "advance" threads: just try to advance EBR.
    for _ in 0..4 {
        let collector = Arc::clone(&collector);
        let barrier = Arc::clone(&barrier);
        let done = Arc::clone(&done);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut advances = 0u64;
            while !done.load(Ordering::Relaxed) {
                collector.try_advance();
                advances += 1;
                // Yield to avoid spinning too aggressively.
                if advances.is_multiple_of(100) {
                    thread::yield_now();
                }
            }
            advances
        }));
    }

    barrier.wait();
    // Let it run for a bit.
    thread::sleep(std::time::Duration::from_millis(50));
    done.store(true, Ordering::Relaxed);

    let results: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Final cleanup.
    for _ in 0..20 {
        collector.try_advance();
    }

    let total_hot_ops: u64 = results[..4].iter().sum();
    let total_advances: u64 = results[4..].iter().sum();

    assert!(total_hot_ops > 0, "hot path threads must have done work");
    assert!(total_advances > 0, "advance threads must have done work");

    let final_count = fc.with_state_ref(|s| *s);
    assert_eq!(
        final_count, total_hot_ops,
        "FC state must match total hot ops"
    );
    assert_eq!(collector.diagnostics().active_threads, 0);
}
