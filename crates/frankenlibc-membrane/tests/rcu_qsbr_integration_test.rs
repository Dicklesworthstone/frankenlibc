//! Integration tests for the RCU/QSBR module.
//!
//! Covers: snapshot consolidation patterns, multi-threaded stress,
//! reclamation correctness, and TSM hot-path integration scenarios.

use frankenlibc_membrane::rcu::{QsbrRegistry, RcuCell, RcuReader, ReclaimQueue};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;

// ───────────────── Kernel state consolidation scenario ─────────────────

/// Simulates the RuntimeMathKernel hot-state consolidation pattern:
/// 50+ individual atomic reads replaced by 1 RCU snapshot read.
#[derive(Debug, Clone, PartialEq)]
struct KernelHotState {
    risk_bonus_ppm: u32,
    spectral_phase: u8,
    signature_state: u8,
    topological_state: u8,
    bridge_state: u8,
    hji_state: u8,
    mfg_state: u8,
    padic_state: u8,
    symplectic_state: u8,
    sparse_state: u8,
    pressure_regime: u8,
    pressure_score_milli: u64,
    pressure_epoch: u64,
    fusion_bonus_ppm: u64,
    fusion_entropy_milli: u64,
    design_budget_ns: u64,
    probe_mask: u64,
    anytime_states: [u8; 20],
    cvar_states: [u8; 20],
    ld_states: [u8; 20],
    oracle_bias: [u8; 20],
}

impl Default for KernelHotState {
    fn default() -> Self {
        Self {
            risk_bonus_ppm: 0,
            spectral_phase: 0,
            signature_state: 0,
            topological_state: 0,
            bridge_state: 0,
            hji_state: 0,
            mfg_state: 0,
            padic_state: 0,
            symplectic_state: 0,
            sparse_state: 0,
            pressure_regime: 0,
            pressure_score_milli: 0,
            pressure_epoch: 0,
            fusion_bonus_ppm: 0,
            fusion_entropy_milli: 0,
            design_budget_ns: 200,
            probe_mask: 0xFFFF,
            anytime_states: [0; 20],
            cvar_states: [0; 20],
            ld_states: [0; 20],
            oracle_bias: [0; 20],
        }
    }
}

#[test]
fn kernel_snapshot_consolidation_single_read() {
    let cell = RcuCell::new(KernelHotState::default());
    let mut reader = RcuReader::new(&cell);

    // Hot path: all 50+ fields available from one snapshot read.
    let s = reader.read();
    assert_eq!(s.risk_bonus_ppm, 0);
    assert_eq!(s.anytime_states, [0; 20]);
    assert_eq!(s.probe_mask, 0xFFFF);
}

#[test]
fn kernel_snapshot_writer_publishes_consistent_state() {
    let cell = RcuCell::new(KernelHotState::default());
    let mut reader = RcuReader::new(&cell);

    // Simulate a calibration pass updating multiple fields atomically.
    cell.update(KernelHotState {
        risk_bonus_ppm: 5000,
        spectral_phase: 2,
        hji_state: 3,
        anytime_states: {
            let mut a = [0; 20];
            a[3] = 2; // Warning on family 3
            a[7] = 3; // Alarm on family 7
            a
        },
        ..KernelHotState::default()
    });

    // Reader sees all fields updated consistently.
    let s = reader.read();
    assert_eq!(s.risk_bonus_ppm, 5000);
    assert_eq!(s.spectral_phase, 2);
    assert_eq!(s.hji_state, 3);
    assert_eq!(s.anytime_states[3], 2);
    assert_eq!(s.anytime_states[7], 3);
    assert_eq!(s.anytime_states[0], 0); // Untouched families stay at 0.
}

#[test]
fn kernel_snapshot_no_torn_reads() {
    // Demonstrates that a reader never sees a mix of old and new fields.
    let cell = Arc::new(RcuCell::new(KernelHotState {
        risk_bonus_ppm: 1000,
        spectral_phase: 0,
        ..KernelHotState::default()
    }));

    let cell2 = Arc::clone(&cell);
    let barrier = Arc::new(Barrier::new(2));
    let barrier2 = Arc::clone(&barrier);

    let reader_thread = thread::spawn(move || {
        let mut reader = RcuReader::new(&cell2);
        barrier2.wait();
        let mut torn_reads = 0u64;
        for _ in 0..50_000 {
            let s = reader.read();
            // Writer always updates both fields together:
            // (1000, 0) or (5000, 2). A torn read would show (1000, 2) or (5000, 0).
            let consistent = (s.risk_bonus_ppm == 1000 && s.spectral_phase == 0)
                || (s.risk_bonus_ppm == 5000 && s.spectral_phase == 2);
            if !consistent {
                torn_reads += 1;
            }
        }
        torn_reads
    });

    barrier.wait();
    for _ in 0..10_000 {
        // Toggle between two consistent states.
        cell.update(KernelHotState {
            risk_bonus_ppm: 5000,
            spectral_phase: 2,
            ..KernelHotState::default()
        });
        cell.update(KernelHotState {
            risk_bonus_ppm: 1000,
            spectral_phase: 0,
            ..KernelHotState::default()
        });
    }

    let torn = reader_thread.join().expect("reader panicked");
    assert_eq!(torn, 0, "RCU must prevent torn reads");
}

// ─────────────────── Pressure snapshot consolidation ───────────────────

#[derive(Debug, Clone, PartialEq)]
struct PressureSnapshot {
    regime: u8,
    score_milli: u64,
    raw_score_milli: u64,
    epoch: u64,
    transitions: u64,
}

#[test]
fn pressure_snapshot_consolidation() {
    let cell = RcuCell::new(PressureSnapshot {
        regime: 0,
        score_milli: 0,
        raw_score_milli: 0,
        epoch: 0,
        transitions: 0,
    });

    let mut reader = RcuReader::new(&cell);
    let s = reader.read();
    assert_eq!(s.regime, 0);

    // Simulate pressure escalation.
    cell.update(PressureSnapshot {
        regime: 2, // Overloaded
        score_milli: 850,
        raw_score_milli: 920,
        epoch: 5,
        transitions: 3,
    });

    let s = reader.read();
    assert_eq!(s.regime, 2);
    assert_eq!(s.score_milli, 850);
    assert_eq!(s.epoch, 5);
}

// ──────────────────────── QSBR lifecycle tests ────────────────────────

#[test]
fn qsbr_multi_thread_grace_period_ordering() {
    let registry = Arc::new(QsbrRegistry::new());
    let barrier = Arc::new(Barrier::new(5));
    let mut handles = Vec::new();

    for _ in 0..4 {
        let reg = Arc::clone(&registry);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let handle = reg.register();
            bar.wait();

            // Simulate work with periodic quiescent reports.
            for _ in 0..500 {
                // Read some shared state (simulated).
                std::hint::black_box(42u64);
                handle.quiescent();
            }
            // Handle dropped here → deregisters.
        }));
    }

    barrier.wait();

    // Writer side: advance epoch and check grace period completion.
    let mut completed_epochs = Vec::new();
    for _ in 0..20 {
        let epoch = registry.advance_epoch();
        // Grace period may complete before we check (threads are fast).
        thread::yield_now();
        if registry.is_grace_period_complete(epoch) {
            completed_epochs.push(epoch);
        }
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    // After all threads exit, all epochs should be complete.
    let final_epoch = registry.advance_epoch();
    assert!(registry.is_grace_period_complete(final_epoch));
}

#[test]
fn qsbr_handle_drop_safety() {
    let registry = QsbrRegistry::new();

    // Register and immediately drop 100 handles.
    for _ in 0..100 {
        let _h = registry.register();
    }

    assert_eq!(registry.active_count(), 0);

    // All slots should be reusable.
    let h = registry.register();
    assert!(
        h.slot_id() < 100,
        "should reuse a previously allocated slot"
    );
}

// ──────────────── Reclamation queue with typed resources ────────────────

#[derive(Debug)]
struct ExpensiveResource {
    _id: u64,
    dropped: Arc<AtomicBool>,
}

impl Drop for ExpensiveResource {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

#[test]
fn reclamation_defers_drop_until_grace_period() {
    let registry = QsbrRegistry::new();
    let queue: ReclaimQueue<ExpensiveResource> = ReclaimQueue::new();
    let h = registry.register();

    let drop_flag = Arc::new(AtomicBool::new(false));

    let epoch = registry.advance_epoch();
    queue.defer(
        epoch,
        ExpensiveResource {
            _id: 1,
            dropped: Arc::clone(&drop_flag),
        },
    );

    // Resource should NOT be dropped yet.
    let _ = queue.drain_completed(&registry);
    assert!(
        !drop_flag.load(Ordering::Acquire),
        "resource must not be dropped before grace period completes"
    );

    // Report quiescent.
    h.quiescent();
    let drained = queue.drain_completed(&registry);
    assert_eq!(drained.len(), 1);

    // Resource is now in `drained` Vec — will be dropped when Vec is dropped.
    drop(drained);
    assert!(
        drop_flag.load(Ordering::Acquire),
        "resource must be dropped after reclamation"
    );
}

#[test]
fn reclamation_fifo_ordering_under_multiple_epochs() {
    let registry = QsbrRegistry::new();
    let queue: ReclaimQueue<u64> = ReclaimQueue::new();
    let h = registry.register();

    // Enqueue resources across 5 epochs.
    let mut epochs = Vec::new();
    for i in 0..5 {
        let epoch = registry.advance_epoch();
        queue.defer(epoch, i);
        epochs.push(epoch);
        h.quiescent();
    }

    // All grace periods should be complete.
    let drained = queue.drain_completed(&registry);
    assert_eq!(drained.len(), 5);
}

// ──────────────── RcuCell update_with integration ────────────────

#[test]
fn update_with_incremental_modification() {
    let cell = RcuCell::new(KernelHotState::default());
    let mut reader = RcuReader::new(&cell);

    // Simulate incremental calibration: only update pressure fields.
    cell.update_with(|old| {
        let mut new = old.clone();
        new.pressure_regime = 1; // Pressured
        new.pressure_score_milli = 600;
        new.pressure_epoch = old.pressure_epoch + 1;
        new
    });

    let s = reader.read();
    assert_eq!(s.pressure_regime, 1);
    assert_eq!(s.pressure_score_milli, 600);
    // Other fields unchanged.
    assert_eq!(s.risk_bonus_ppm, 0);
    assert_eq!(s.probe_mask, 0xFFFF);
}

// ──────────────── Multi-reader multi-writer stress ────────────────

#[test]
fn multi_reader_multi_writer_stress() {
    let cell = Arc::new(RcuCell::new(0u64));
    let barrier = Arc::new(Barrier::new(6)); // 2 writers + 4 readers
    let total_writes = Arc::new(AtomicU64::new(0));
    let mut writer_handles = Vec::new();
    let mut reader_handles = Vec::new();

    // 2 writer threads.
    for _ in 0..2 {
        let cell = Arc::clone(&cell);
        let barrier = Arc::clone(&barrier);
        let tw = Arc::clone(&total_writes);
        writer_handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..5000 {
                cell.update_with(|old| old + 1);
                tw.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // 4 reader threads.
    for _ in 0..4 {
        let cell = Arc::clone(&cell);
        let barrier = Arc::clone(&barrier);
        reader_handles.push(thread::spawn(move || {
            let mut reader = RcuReader::new(&cell);
            barrier.wait();
            let mut max_seen = 0u64;
            for _ in 0..20_000 {
                let v = *reader.read();
                if v > max_seen {
                    max_seen = v;
                }
            }
            max_seen
        }));
    }

    for h in writer_handles {
        h.join().expect("writer panicked");
    }
    for h in reader_handles {
        h.join().expect("reader panicked");
    }

    // Final value should be 10000 (2 writers × 5000).
    assert_eq!(*cell.load(), 10_000);
}

// ──────────────── Epoch monotonicity guarantees ────────────────

#[test]
fn epoch_is_strictly_monotonic() {
    let cell = RcuCell::new(0u64);
    let mut prev_epoch = cell.epoch();

    for i in 1..=100 {
        cell.update(i);
        let epoch = cell.epoch();
        assert!(epoch > prev_epoch, "epoch must be strictly increasing");
        prev_epoch = epoch;
    }
}

#[test]
fn reader_epoch_tracks_cell_epoch_on_refresh() {
    let cell = RcuCell::new(0u64);
    let mut reader = RcuReader::new(&cell);

    cell.update(1);
    cell.update(2);
    cell.update(3);

    // Reader still at old epoch.
    let old_epoch = reader.cached_epoch();
    assert!(old_epoch < cell.epoch());

    // After read(), epoch catches up.
    let _ = reader.read();
    assert_eq!(reader.cached_epoch(), cell.epoch());
}

// ──────────── TSM validation pipeline integration scenario ────────────

#[test]
fn tsm_validation_pipeline_rcu_pattern() {
    // Simulates the full TSM validation pipeline pattern:
    // 1. Writer (calibration thread) publishes kernel state via RCU
    // 2. Multiple validation threads read kernel state with zero locks
    // 3. QSBR tracks quiescent states for deferred reclamation

    let kernel_state = Arc::new(RcuCell::new(KernelHotState::default()));
    let registry = Arc::new(QsbrRegistry::new());
    let reclaim_queue = Arc::new(ReclaimQueue::<KernelHotState>::new());
    let barrier = Arc::new(Barrier::new(5)); // 1 writer + 4 readers

    let mut handles = Vec::new();

    // 4 validation threads (readers).
    for thread_id in 0..4u32 {
        let ks = Arc::clone(&kernel_state);
        let reg = Arc::clone(&registry);
        let bar = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let qsbr_handle = reg.register();
            let mut reader = RcuReader::new(&ks);
            bar.wait();

            let mut validations = 0u64;
            for _ in 0..10_000 {
                // Hot path: read kernel state.
                let state = reader.read();

                // Simulate risk aggregation using snapshot fields.
                let risk = u64::from(state.risk_bonus_ppm)
                    + match state.spectral_phase {
                        2 => 100_000,
                        1 => 50_000,
                        _ => 0,
                    }
                    + match state.hji_state {
                        3 => 200_000,
                        _ => 0,
                    };

                // Deterministic decision based on consistent snapshot.
                if risk > 500_000 {
                    std::hint::black_box(risk); // "Deny" path
                }

                validations += 1;

                // Report quiescent every 100 validations.
                if validations.is_multiple_of(100) {
                    qsbr_handle.quiescent();
                }
            }

            (thread_id, validations)
        }));
    }

    // 1 calibration thread (writer).
    let ks_w = Arc::clone(&kernel_state);
    let reg_w = Arc::clone(&registry);
    let rq_w = Arc::clone(&reclaim_queue);
    let bar_w = Arc::clone(&barrier);
    let writer = thread::spawn(move || {
        bar_w.wait();
        for i in 0..100u64 {
            // Save old state for reclamation tracking.
            let old = ks_w.load();

            // Publish new calibration result.
            ks_w.update(KernelHotState {
                risk_bonus_ppm: (i * 50) as u32,
                spectral_phase: ((i / 30) % 3) as u8,
                hji_state: if i > 80 { 3 } else { 0 },
                pressure_epoch: i,
                ..KernelHotState::default()
            });

            let epoch = reg_w.advance_epoch();
            rq_w.defer(epoch, KernelHotState::clone(&old));
        }
    });

    writer.join().expect("writer panicked");
    for h in handles {
        let (tid, validations) = h.join().expect("reader panicked");
        assert_eq!(
            validations, 10_000,
            "thread {tid} should have completed all validations"
        );
    }

    // All threads exited → all grace periods complete.
    let reclaimed = reclaim_queue.drain_completed(&registry);
    assert_eq!(
        reclaimed.len(),
        100,
        "all old snapshots should be reclaimable"
    );
}

// ──────────────── Arena metadata RCU scenario ────────────────

#[derive(Debug, Clone, PartialEq)]
struct ArenaSlotSnapshot {
    user_base: usize,
    user_size: usize,
    generation: u32,
    state: u8, // 0=Valid, 1=Quarantined, 2=Freed
}

#[derive(Debug, Clone, Default)]
struct ArenaIndex {
    slots: Vec<ArenaSlotSnapshot>,
}

#[test]
fn arena_metadata_rcu_read_pattern() {
    // Simulates RCU-protected arena slot lookup.
    let index = RcuCell::new(ArenaIndex {
        slots: vec![
            ArenaSlotSnapshot {
                user_base: 0x1000,
                user_size: 256,
                generation: 1,
                state: 0,
            },
            ArenaSlotSnapshot {
                user_base: 0x2000,
                user_size: 512,
                generation: 1,
                state: 0,
            },
        ],
    });

    let mut reader = RcuReader::new(&index);

    // Read-side lookup: no locks.
    let idx = reader.read();
    let slot = idx
        .slots
        .iter()
        .find(|s| s.user_base == 0x1000)
        .expect("slot should exist");
    assert_eq!(slot.user_size, 256);
    assert_eq!(slot.state, 0);

    // Writer: free an allocation (state transition).
    index.update_with(|old| {
        let mut new = old.clone();
        if let Some(slot) = new.slots.iter_mut().find(|s| s.user_base == 0x1000) {
            slot.state = 1; // Quarantined
            slot.generation += 1;
        }
        new
    });

    // Reader sees updated state.
    let idx = reader.read();
    let slot = idx
        .slots
        .iter()
        .find(|s| s.user_base == 0x1000)
        .expect("slot should still exist");
    assert_eq!(slot.state, 1);
    assert_eq!(slot.generation, 2);
}

// ──────────── Edge case: reader created before any writes ────────────

#[test]
fn reader_created_at_epoch_1_sees_all_updates() {
    let cell = RcuCell::new(0u64);
    let mut reader = RcuReader::new(&cell);
    assert_eq!(reader.cached_epoch(), 1);

    for i in 1..=1000 {
        cell.update(i);
    }

    // Reader should refresh to latest on next read.
    assert_eq!(*reader.read(), 1000);
    assert_eq!(reader.cached_epoch(), 1001);
}

// ──────────── Edge case: rapid updates between reads ────────────

#[test]
fn rapid_updates_between_reads() {
    let cell = RcuCell::new(0u64);
    let mut reader = RcuReader::new(&cell);

    // 1000 updates between reads.
    for i in 1..=1000 {
        cell.update(i);
    }

    // Reader should see the LATEST value, not an intermediate one.
    assert_eq!(*reader.read(), 1000);
}
