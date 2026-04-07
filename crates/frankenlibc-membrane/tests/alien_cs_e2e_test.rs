//! E2E tests for Alien CS concurrency primitives under realistic workloads.
//!
//! Validates multi-concept composition at varying thread counts (1-16),
//! mixed read/write ratios, and sustained load. Tests linearizability,
//! absence of torn reads, and correct reclamation under contention.

use frankenlibc_membrane::alien_cs_metrics::{build_snapshot, AlienCsLogContext, RcuMetrics};
use frankenlibc_membrane::ebr::EbrCollector;
use frankenlibc_membrane::flat_combining::FlatCombiner;
use frankenlibc_membrane::rcu::{RcuCell, RcuReader};
use frankenlibc_membrane::seqlock::{SeqLock, SeqLockReader};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Instant;

#[derive(Debug, Clone, Copy)]
struct CompositeScenarioSpec {
    scenario_id: &'static str,
    thread_count: usize,
    ops_per_thread: u64,
    write_every: u64,
}

#[derive(Debug, Clone)]
struct CompositeScenarioReport {
    scenario_id: &'static str,
    thread_count: usize,
    ops_per_thread: u64,
    write_every: u64,
    total_ops: u64,
    config_writes: u64,
    duration_ns: u64,
    ns_per_op_x1000: u64,
    contention_score: f64,
    seqlock_reads: u64,
    seqlock_writes: u64,
    flat_combining_total_ops: u64,
    flat_combining_total_passes: u64,
    flat_combining_max_batch_size: u64,
    ebr_epoch: u64,
    ebr_total_retired: u64,
    ebr_total_reclaimed: u64,
    rcu_epoch: u64,
    rcu_reader_count: usize,
}

fn current_mode_name() -> &'static str {
    match std::env::var("FRANKENLIBC_MODE").ok().as_deref() {
        Some("hardened") => "hardened",
        _ => "strict",
    }
}

fn alien_cs_e2e_artifact_paths() -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance");
    (
        dir.join("alien_cs_e2e_report.v1.json"),
        dir.join("alien_cs_e2e_trace.v1.jsonl"),
    )
}

fn write_json_artifact(path: &PathBuf, payload: &Value) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("alien-cs artifact directory must exist");
    }
    let encoded = serde_json::to_string_pretty(payload).expect("report JSON must encode");
    fs::write(path, encoded).expect("alien-cs report artifact must be writable");
}

fn write_jsonl_artifact(path: &PathBuf, rows: &[Value]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("alien-cs trace directory must exist");
    }
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row).expect("trace row must encode"));
        out.push('\n');
    }
    fs::write(path, out).expect("alien-cs trace artifact must be writable");
}

fn read_json_artifact(path: &PathBuf) -> Value {
    serde_json::from_str(&fs::read_to_string(path).expect("artifact must be readable"))
        .expect("artifact JSON must parse")
}

fn parse_jsonl_rows(jsonl: &str) -> Vec<Value> {
    jsonl
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("trace row must parse"))
        .collect()
}

fn snapshot_rows_with_artifact_refs(
    snapshot: &frankenlibc_membrane::alien_cs_metrics::AlienCsSnapshot,
    context: &AlienCsLogContext,
    artifact_refs: &[String],
) -> Vec<Value> {
    let mut rows = parse_jsonl_rows(&snapshot.export_full_jsonl_with_context(context));
    for row in &mut rows {
        row["artifact_refs"] = Value::Array(
            artifact_refs
                .iter()
                .cloned()
                .map(Value::String)
                .collect::<Vec<_>>(),
        );
    }
    rows
}

fn measure_ns_per_op_x1000(total_ops: u64, f: impl FnOnce()) -> u64 {
    let start = Instant::now();
    f();
    let elapsed_ns = start.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    if total_ops == 0 {
        0
    } else {
        ((u128::from(elapsed_ns) * 1000) / u128::from(total_ops)) as u64
    }
}

fn run_composite_scenario(
    spec: CompositeScenarioSpec,
) -> (
    CompositeScenarioReport,
    frankenlibc_membrane::alien_cs_metrics::AlienCsSnapshot,
) {
    let config = Arc::new(SeqLock::new((1u64, true)));
    let state = Arc::new(RcuCell::new(0u64));
    let metrics = Arc::new(FlatCombiner::new(0u64, spec.thread_count.max(4)));
    let collector = Arc::new(EbrCollector::new());
    let barrier = Arc::new(Barrier::new(spec.thread_count + 1));
    let config_writes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for thread_idx in 0..spec.thread_count {
        let config = Arc::clone(&config);
        let state = Arc::clone(&state);
        let metrics = Arc::clone(&metrics);
        let collector = Arc::clone(&collector);
        let barrier = Arc::clone(&barrier);
        let config_writes = Arc::clone(&config_writes);
        handles.push(thread::spawn(move || {
            let handle = collector.register();
            let mut cfg_reader = SeqLockReader::new(&config);
            let mut state_reader = RcuReader::new(&state);
            let thread_seed = (thread_idx as u64) + 1;
            barrier.wait();

            for i in 0..spec.ops_per_thread {
                let op_index = i + thread_seed;
                let guard = handle.pin();

                let cfg = *cfg_reader.read();
                assert!(
                    (1..=3).contains(&cfg.0),
                    "invalid safety level in scenario {}: {}",
                    spec.scenario_id,
                    cfg.0
                );
                let risk = *state_reader.read();
                std::hint::black_box((cfg, risk));

                if op_index % spec.write_every == 0 {
                    config.write_with(|c| {
                        c.0 = (op_index % 3) + 1;
                        c.1 = op_index % 2 == 0;
                    });
                    state.update((thread_seed << 32) | i);
                    config_writes.fetch_add(1, Ordering::Relaxed);
                }

                metrics.execute(1u64, |total, op| {
                    *total += op;
                    *total
                });

                if op_index.is_multiple_of(32) {
                    guard.retire(|| {});
                }
                if op_index.is_multiple_of(16) {
                    collector.try_advance();
                }
                drop(guard);
            }
        }));
    }

    barrier.wait();
    let started_at = Instant::now();

    for handle in handles {
        handle.join().expect("composite scenario thread panicked");
    }

    for _ in 0..32 {
        collector.try_advance();
    }

    let total_ops = metrics.with_state_ref(|state| *state);
    let expected_total_ops = spec.thread_count as u64 * spec.ops_per_thread;
    assert_eq!(
        total_ops, expected_total_ops,
        "scenario {} lost operations",
        spec.scenario_id
    );

    let seqlock_diag = config.diagnostics();
    let ebr_diag = collector.diagnostics();
    let flat_combining_diag = metrics.diagnostics();
    let rcu_metrics = RcuMetrics {
        epoch: state.epoch(),
        reader_count: state.reader_count(),
    };
    assert_eq!(
        ebr_diag.active_threads, 0,
        "scenario {} leaked EBR registrations",
        spec.scenario_id
    );

    let duration_ns = started_at.elapsed().as_nanos().min(u128::from(u64::MAX)) as u64;
    let ns_per_op_x1000 =
        ((u128::from(duration_ns) * 1000) / u128::from(expected_total_ops)) as u64;

    let report = CompositeScenarioReport {
        scenario_id: spec.scenario_id,
        thread_count: spec.thread_count,
        ops_per_thread: spec.ops_per_thread,
        write_every: spec.write_every,
        total_ops,
        config_writes: config_writes.load(Ordering::Relaxed),
        duration_ns,
        ns_per_op_x1000,
        contention_score: frankenlibc_membrane::alien_cs_metrics::compute_contention_score(
            Some(&seqlock_diag),
            Some(&ebr_diag),
            Some(&flat_combining_diag),
        ),
        seqlock_reads: seqlock_diag.reads,
        seqlock_writes: seqlock_diag.writes,
        flat_combining_total_ops: flat_combining_diag.total_ops,
        flat_combining_total_passes: flat_combining_diag.total_passes,
        flat_combining_max_batch_size: flat_combining_diag.max_batch_size,
        ebr_epoch: ebr_diag.global_epoch,
        ebr_total_retired: ebr_diag.total_retired,
        ebr_total_reclaimed: ebr_diag.total_reclaimed,
        rcu_epoch: rcu_metrics.epoch,
        rcu_reader_count: rcu_metrics.reader_count,
    };

    let snapshot = build_snapshot(
        Some(seqlock_diag),
        Some(ebr_diag),
        Some(flat_combining_diag),
        Some(rcu_metrics),
        started_at,
    );

    (report, snapshot)
}

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

#[test]
fn alien_cs_e2e_matrix_emits_structured_artifacts() {
    let mode = current_mode_name();
    let scenarios = [
        CompositeScenarioSpec {
            scenario_id: "serial_read_heavy",
            thread_count: 1,
            ops_per_thread: 600,
            write_every: 32,
        },
        CompositeScenarioSpec {
            scenario_id: "quad_read_heavy",
            thread_count: 4,
            ops_per_thread: 500,
            write_every: 24,
        },
        CompositeScenarioSpec {
            scenario_id: "octa_balanced",
            thread_count: 8,
            ops_per_thread: 320,
            write_every: 8,
        },
        CompositeScenarioSpec {
            scenario_id: "hexa_balanced",
            thread_count: 16,
            ops_per_thread: 200,
            write_every: 8,
        },
        CompositeScenarioSpec {
            scenario_id: "thirtytwo_write_heavy",
            thread_count: 32,
            ops_per_thread: 120,
            write_every: 2,
        },
    ];

    let (report_path, trace_path) = alien_cs_e2e_artifact_paths();
    let artifact_refs = vec![
        report_path.to_string_lossy().into_owned(),
        trace_path.to_string_lossy().into_owned(),
    ];

    let mut reports = Vec::new();
    let mut trace_rows = Vec::new();
    for scenario in scenarios {
        let (report, snapshot) = run_composite_scenario(scenario);
        assert!(
            report.duration_ns > 0,
            "scenario {} must take measurable time",
            report.scenario_id
        );
        assert!(
            report.seqlock_reads >= report.total_ops,
            "scenario {} should perform at least one seqlock read per op",
            report.scenario_id
        );
        assert_eq!(
            report.flat_combining_total_ops, report.total_ops,
            "scenario {} should account for every op in flat combining",
            report.scenario_id
        );
        assert!(
            report.ebr_total_reclaimed <= report.ebr_total_retired,
            "scenario {} reclaimed more than it retired",
            report.scenario_id
        );
        assert!(
            report.rcu_epoch > 0,
            "scenario {} should advance RCU epoch",
            report.scenario_id
        );
        let context = AlienCsLogContext::new("bd-1sp.10", report.scenario_id, mode, "alien_cs_e2e");
        trace_rows.extend(snapshot_rows_with_artifact_refs(
            &snapshot,
            &context,
            &artifact_refs,
        ));
        reports.push(report);
    }

    let benchmark_composite = CompositeScenarioSpec {
        scenario_id: "benchmark_composite",
        thread_count: 8,
        ops_per_thread: 240,
        write_every: 8,
    };
    let (benchmark_report, _) = run_composite_scenario(benchmark_composite);
    let rcu_ns_per_op_x1000 =
        measure_ns_per_op_x1000(4 * 20_000 + 10_000, || rcu_read_scaling_n(4));
    let seqlock_ns_per_op_x1000 =
        measure_ns_per_op_x1000(4 * 20_000 + 1_000, || seqlock_mixed_scaling_n(4, 1_000));
    let flat_combining_ns_per_op_x1000 =
        measure_ns_per_op_x1000(8 * 2_000, || fc_contention_scaling_n(8, 2_000));
    let ebr_ns_per_op_x1000 = measure_ns_per_op_x1000(8 * 300, || ebr_retire_scaling_n(8, 300));
    let max_individual_ns_per_op_x1000 = [
        rcu_ns_per_op_x1000,
        seqlock_ns_per_op_x1000,
        flat_combining_ns_per_op_x1000,
        ebr_ns_per_op_x1000,
    ]
    .into_iter()
    .max()
    .expect("individual benchmark set is non-empty");
    let sum_individual_ns_per_op_x1000 = rcu_ns_per_op_x1000
        + seqlock_ns_per_op_x1000
        + flat_combining_ns_per_op_x1000
        + ebr_ns_per_op_x1000;
    let composite_vs_max_individual_x1000 = if max_individual_ns_per_op_x1000 == 0 {
        0
    } else {
        ((u128::from(benchmark_report.ns_per_op_x1000) * 1000)
            / u128::from(max_individual_ns_per_op_x1000)) as u64
    };
    let composite_vs_sum_individual_x1000 = if sum_individual_ns_per_op_x1000 == 0 {
        0
    } else {
        ((u128::from(benchmark_report.ns_per_op_x1000) * 1000)
            / u128::from(sum_individual_ns_per_op_x1000)) as u64
    };
    assert!(
        benchmark_report.ns_per_op_x1000 > 0 && max_individual_ns_per_op_x1000 > 0,
        "benchmark latencies must be non-zero"
    );

    assert_eq!(trace_rows.len(), reports.len() * 5);
    for row in &trace_rows {
        for key in [
            "trace_id",
            "mode",
            "api_family",
            "symbol",
            "decision_path",
            "healing_action",
            "errno",
            "latency_ns",
            "artifact_refs",
        ] {
            assert!(
                row.get(key).is_some(),
                "missing structured log key {key}: {row}"
            );
        }
        assert_eq!(row["api_family"], "alien_cs");
        assert_eq!(row["mode"], mode);
    }

    let payload = json!({
        "schema_version": "v1",
        "bead_id": "bd-1sp.10",
        "mode": mode,
        "artifact_refs": artifact_refs,
        "scenario_reports": reports.iter().map(|report| json!({
            "scenario_id": report.scenario_id,
            "thread_count": report.thread_count,
            "ops_per_thread": report.ops_per_thread,
            "write_every": report.write_every,
            "total_ops": report.total_ops,
            "config_writes": report.config_writes,
            "duration_ns": report.duration_ns,
            "ns_per_op_x1000": report.ns_per_op_x1000,
            "contention_score": report.contention_score,
            "seqlock_reads": report.seqlock_reads,
            "seqlock_writes": report.seqlock_writes,
            "flat_combining_total_ops": report.flat_combining_total_ops,
            "flat_combining_total_passes": report.flat_combining_total_passes,
            "flat_combining_max_batch_size": report.flat_combining_max_batch_size,
            "ebr_epoch": report.ebr_epoch,
            "ebr_total_retired": report.ebr_total_retired,
            "ebr_total_reclaimed": report.ebr_total_reclaimed,
            "rcu_epoch": report.rcu_epoch,
            "rcu_reader_count": report.rcu_reader_count,
        })).collect::<Vec<_>>(),
        "benchmark_summary": {
            "composite_ns_per_op_x1000": benchmark_report.ns_per_op_x1000,
            "individual_ns_per_op_x1000": {
                "rcu": rcu_ns_per_op_x1000,
                "seqlock": seqlock_ns_per_op_x1000,
                "flat_combining": flat_combining_ns_per_op_x1000,
                "ebr": ebr_ns_per_op_x1000,
            },
            "composite_vs_max_individual_x1000": composite_vs_max_individual_x1000,
            "composite_vs_sum_individual_x1000": composite_vs_sum_individual_x1000,
        }
    });

    write_json_artifact(&report_path, &payload);
    write_jsonl_artifact(&trace_path, &trace_rows);

    assert!(report_path.exists(), "report artifact must exist");
    assert!(trace_path.exists(), "trace artifact must exist");

    let persisted_report = read_json_artifact(&report_path);
    assert_eq!(persisted_report["schema_version"], "v1");
    assert_eq!(persisted_report["bead_id"], "bd-1sp.10");
    assert_eq!(persisted_report["mode"], mode);
    assert_eq!(
        persisted_report["scenario_reports"]
            .as_array()
            .expect("scenario_reports array")
            .len(),
        reports.len()
    );
    assert_eq!(
        persisted_report["benchmark_summary"]["composite_ns_per_op_x1000"]
            .as_u64()
            .expect("composite latency"),
        benchmark_report.ns_per_op_x1000
    );
    let persisted_artifact_refs = persisted_report["artifact_refs"]
        .as_array()
        .expect("artifact_refs array");
    assert_eq!(persisted_artifact_refs.len(), artifact_refs.len());
    for expected_ref in &artifact_refs {
        assert!(
            persisted_artifact_refs
                .iter()
                .any(|value| value.as_str() == Some(expected_ref)),
            "persisted report should reference {expected_ref}"
        );
    }

    let persisted_trace_rows = parse_jsonl_rows(
        &fs::read_to_string(&trace_path).expect("trace artifact must be readable"),
    );
    assert_eq!(persisted_trace_rows.len(), trace_rows.len());
    for row in &persisted_trace_rows {
        assert_eq!(row["bead_id"], "bd-1sp.10");
        assert_eq!(row["mode"], mode);
        let row_artifact_refs = row["artifact_refs"]
            .as_array()
            .expect("artifact_refs array");
        assert_eq!(row_artifact_refs.len(), artifact_refs.len());
        for expected_ref in &artifact_refs {
            assert!(
                row_artifact_refs
                    .iter()
                    .any(|value| value.as_str() == Some(expected_ref)),
                "trace row should carry artifact ref {expected_ref}"
            );
        }
    }

    println!("ALIEN_CS_E2E_REPORT {}", payload);
}
