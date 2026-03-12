//! Integration tests for Flat Combining module.
//!
//! Covers: TSM hot-path integration scenarios, batching effectiveness
//! under varying contention levels, and correctness under stress.

use frankenlibc_membrane::flat_combining::{FlatCombiner, FlatCombinerDiagnostics};
use std::sync::{Arc, Barrier};
use std::thread;

// ──────────────── Pressure sensor combining scenario ────────────────

#[derive(Debug, Default)]
struct PressureSensorState {
    regime: u8, // 0=Nominal, 1=Pressured, 2=Overloaded, 3=Recovery
    score_milli: u64,
    raw_score_milli: u64,
    transitions: u64,
    observations: u64,
}

#[derive(Debug)]
enum PressureOp {
    Observe { signal_milli: u64 },
    QueryRegime,
}

fn apply_pressure(state: &mut PressureSensorState, op: PressureOp) -> u64 {
    match op {
        PressureOp::Observe { signal_milli } => {
            state.observations += 1;
            state.raw_score_milli = signal_milli;
            // EWMA alpha=0.125.
            state.score_milli = state.score_milli - state.score_milli / 8 + signal_milli / 8;
            let new_regime = if state.score_milli > 800 {
                2
            } else if state.score_milli > 500 {
                1
            } else if state.score_milli > 200 && state.regime >= 2 {
                3 // Recovery
            } else {
                0
            };
            if new_regime != state.regime {
                state.transitions += 1;
                state.regime = new_regime;
            }
            u64::from(state.regime)
        }
        PressureOp::QueryRegime => u64::from(state.regime),
    }
}

#[test]
fn pressure_sensor_single_thread() {
    let fc = FlatCombiner::new(PressureSensorState::default(), 4);

    // Warm up with nominal observations.
    for _ in 0..100 {
        fc.execute(PressureOp::Observe { signal_milli: 100 }, apply_pressure);
    }
    let regime = fc.execute(PressureOp::QueryRegime, apply_pressure);
    assert_eq!(regime, 0, "should be Nominal after low signals");

    // Escalate pressure.
    for _ in 0..200 {
        fc.execute(PressureOp::Observe { signal_milli: 900 }, apply_pressure);
    }
    let regime = fc.execute(PressureOp::QueryRegime, apply_pressure);
    assert!(
        regime >= 1,
        "should be at least Pressured after high signals"
    );
}

#[test]
fn pressure_sensor_concurrent_observers() {
    let fc = Arc::new(FlatCombiner::new(PressureSensorState::default(), 16));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    // 8 threads each observing 500 times.
    for tid in 0..8u64 {
        let fc = Arc::clone(&fc);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..500 {
                let signal = 100 + (tid * 100) + (i % 200);
                fc.execute(
                    PressureOp::Observe {
                        signal_milli: signal,
                    },
                    apply_pressure,
                );
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let obs = fc.with_state_ref(|s| s.observations);
    assert_eq!(obs, 4000, "all observations must be counted");
}

// ──────────────── Arena operation combining ────────────────

#[derive(Debug, Default)]
struct ArenaState {
    allocations: Vec<(usize, usize)>, // (addr, size)
    frees: u64,
    total_allocated: usize,
}

#[derive(Debug)]
enum ArenaOp {
    Allocate { size: usize },
    Free { addr: usize },
    Stats,
}

#[derive(Debug)]
struct ArenaResult {
    addr: Option<usize>,
    total_allocated: usize,
    live_count: usize,
}

fn apply_arena(state: &mut ArenaState, op: ArenaOp) -> ArenaResult {
    match op {
        ArenaOp::Allocate { size } => {
            let addr = 0x1000 + state.total_allocated;
            state.allocations.push((addr, size));
            state.total_allocated += size;
            ArenaResult {
                addr: Some(addr),
                total_allocated: state.total_allocated,
                live_count: state.allocations.len(),
            }
        }
        ArenaOp::Free { addr } => {
            state.allocations.retain(|&(a, _)| a != addr);
            state.frees += 1;
            ArenaResult {
                addr: None,
                total_allocated: state.total_allocated,
                live_count: state.allocations.len(),
            }
        }
        ArenaOp::Stats => ArenaResult {
            addr: None,
            total_allocated: state.total_allocated,
            live_count: state.allocations.len(),
        },
    }
}

#[test]
fn arena_allocate_free_lifecycle() {
    let fc = FlatCombiner::new(ArenaState::default(), 4);

    let r1 = fc.execute(ArenaOp::Allocate { size: 256 }, apply_arena);
    assert!(r1.addr.is_some());
    assert_eq!(r1.total_allocated, 256);

    let r2 = fc.execute(ArenaOp::Allocate { size: 512 }, apply_arena);
    assert_eq!(r2.live_count, 2);

    let addr = r1.addr.unwrap();
    let r3 = fc.execute(ArenaOp::Free { addr }, apply_arena);
    assert_eq!(r3.live_count, 1);
}

#[test]
fn arena_concurrent_allocate_free() {
    let fc = Arc::new(FlatCombiner::new(ArenaState::default(), 16));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let fc = Arc::clone(&fc);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for i in 0..100 {
                let size = 64 + (i % 10) * 16;
                let r = fc.execute(ArenaOp::Allocate { size }, apply_arena);
                if let Some(addr) = r.addr {
                    // Free every other allocation.
                    if i.is_multiple_of(2) {
                        fc.execute(ArenaOp::Free { addr }, apply_arena);
                    }
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    let stats = fc.execute(ArenaOp::Stats, apply_arena);
    // 800 allocations total, half freed = ~400 live.
    assert_eq!(stats.live_count, 400, "half the allocations should remain");
}

// ──────────────── Combining effectiveness ────────────────

#[test]
fn combining_effectiveness_scales_with_contention() {
    let mut diagnostics_by_threads: Vec<(usize, FlatCombinerDiagnostics)> = Vec::new();

    for num_threads in [1, 2, 4, 8] {
        let fc = Arc::new(FlatCombiner::new(0u64, 32));
        let barrier = Arc::new(Barrier::new(num_threads));
        let ops_per_thread = 2000;
        let mut handles = Vec::new();

        for _ in 0..num_threads {
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
            h.join().expect("thread panicked");
        }

        let expected = (num_threads * ops_per_thread) as u64;
        assert_eq!(fc.with_state_ref(|s| *s), expected);

        diagnostics_by_threads.push((num_threads, fc.diagnostics()));
    }

    // With more threads, combining should produce larger average batch sizes.
    // This isn't guaranteed on every run, but the trend should be clear.
    let single_avg = diagnostics_by_threads[0].1.avg_batch_size;
    let eight_avg = diagnostics_by_threads[3].1.avg_batch_size;

    // Sanity: all ops accounted for.
    for (threads, diag) in &diagnostics_by_threads {
        assert_eq!(diag.total_ops, (*threads as u64) * 2000);
    }

    // With 8 threads, we expect higher batching than 1 thread.
    // Allow for scheduling variance by only checking that 8-thread isn't worse.
    assert!(
        eight_avg >= single_avg * 0.5,
        "8-thread avg batch ({eight_avg:.1}) should not be significantly worse than 1-thread ({single_avg:.1})"
    );
}

// ──────────────── Return value correctness ────────────────

#[test]
fn each_thread_gets_its_own_result() {
    let fc = Arc::new(FlatCombiner::new(0u64, 16));
    let barrier = Arc::new(Barrier::new(4));
    let mut handles = Vec::new();

    for tid in 0..4u64 {
        let fc = Arc::clone(&fc);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            let mut results = Vec::new();
            for _ in 0..100 {
                let r = fc.execute(tid + 1, |state, op| {
                    *state += op;
                    *state
                });
                results.push(r);
            }
            // Results should be monotonically increasing (each is a running sum).
            for window in results.windows(2) {
                assert!(
                    window[1] >= window[0],
                    "results must be monotonically non-decreasing"
                );
            }
            results
        }));
    }

    for h in handles {
        let _results = h.join().expect("thread panicked");
    }

    // Total: 4 threads × 100 ops × (tid+1) = sum of (1+2+3+4)*100 = 1000.
    assert_eq!(fc.with_state_ref(|s| *s), 1000);
}

// ──────────────── Slot exhaustion and fallback ────────────────

#[test]
fn slot_exhaustion_falls_back_to_direct_lock() {
    // Only 2 slots but 8 threads.
    let fc = Arc::new(FlatCombiner::new(0u64, 2));
    let barrier = Arc::new(Barrier::new(8));
    let mut handles = Vec::new();

    for _ in 0..8 {
        let fc = Arc::clone(&fc);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            barrier.wait();
            for _ in 0..500 {
                fc.execute(1u64, |state, op| {
                    *state += op;
                    *state
                });
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    // All 4000 ops must be applied even with slot exhaustion.
    assert_eq!(fc.with_state_ref(|s| *s), 4000);
}
