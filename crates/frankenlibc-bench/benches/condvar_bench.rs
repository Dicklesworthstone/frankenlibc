//! Condvar hot-path microbenchmarks for bd-2nzx.
//!
//! Captures condvar operation overhead with deterministic per-mode metadata
//! (`FRANKENLIBC_MODE`) and percentile summaries. Benchmarks cover:
//! - init/destroy cycle (uncontended)
//! - signal with no waiters (no-op fast path)
//! - broadcast with no waiters (no-op fast path)
//! - wait + signal roundtrip (single waiter, single signaler)
//! - timedwait with past deadline (ETIMEDOUT fast path)
//! - broadcast wake-all (4 waiters)

use std::cell::RefCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use frankenlibc_core::pthread::CondvarData;

#[derive(Default)]
struct BenchStats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl BenchStats {
    fn record(&mut self, iters: u64, dur: Duration) {
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, mode_label: &str, bench_label: &str) {
        let mut samples = self.samples_ns_per_op.clone();
        if samples.is_empty() {
            return;
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p50 = percentile_sorted(&samples, 0.50);
        let p95 = percentile_sorted(&samples, 0.95);
        let p99 = percentile_sorted(&samples, 0.99);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let throughput_ops_s = if self.total_ns == 0 {
            0.0
        } else {
            (self.total_iters as f64) / (self.total_ns as f64 / 1e9)
        };

        println!(
            "CONDVAR_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
            mode_label,
            bench_label,
            samples.len(),
            p50,
            p95,
            p99,
            mean,
            throughput_ops_s
        );
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn mode_label() -> &'static str {
    match std::env::var("FRANKENLIBC_MODE").ok().as_deref() {
        Some("hardened") => "hardened",
        Some("strict") => "strict",
        _ => "strict",
    }
}

fn print_env_metadata_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mode_raw = std::env::var("FRANKENLIBC_MODE").unwrap_or_else(|_| "<unset>".to_string());
        println!("CONDVAR_BENCH_META frankenlibc_mode_env={mode_raw}");
    });
}

/// Benchmark condvar init + destroy cycle (no waiters, no contention).
fn bench_condvar_init_destroy(c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();

    // Warm up: run a few cycles to ensure code is hot.
    let mut cv = CondvarData {
        seq: AtomicU32::new(0),
        nwaiters: AtomicU32::new(0),
        assoc_mutex: std::sync::atomic::AtomicUsize::new(0),
        clock_id: AtomicU32::new(0),
    };
    for _ in 0..1_000 {
        unsafe {
            frankenlibc_core::pthread::condvar_init(&mut cv as *mut CondvarData, 0);
            frankenlibc_core::pthread::condvar_destroy(&mut cv as *mut CondvarData);
        }
    }

    let stats = RefCell::new(BenchStats::default());
    let mut group = c.benchmark_group("condvar_hotpath");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("init_destroy", mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                unsafe {
                    frankenlibc_core::pthread::condvar_init(&mut cv as *mut CondvarData, 0);
                    black_box(cv.seq.load(Ordering::Relaxed));
                    frankenlibc_core::pthread::condvar_destroy(&mut cv as *mut CondvarData);
                }
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    group.finish();
    stats.borrow().report(mode, "init_destroy");
}

/// Benchmark signal with no waiters (should be fast no-op path).
fn bench_condvar_signal_no_waiters(c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();

    let mut cv = CondvarData {
        seq: AtomicU32::new(0),
        nwaiters: AtomicU32::new(0),
        assoc_mutex: std::sync::atomic::AtomicUsize::new(0),
        clock_id: AtomicU32::new(0),
    };
    unsafe {
        frankenlibc_core::pthread::condvar_init(&mut cv as *mut CondvarData, 0);
    }

    let stats = RefCell::new(BenchStats::default());
    let mut group = c.benchmark_group("condvar_hotpath");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("signal_no_waiters", mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                unsafe {
                    black_box(frankenlibc_core::pthread::condvar_signal(
                        &mut cv as *mut CondvarData,
                    ));
                }
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    group.finish();
    stats.borrow().report(mode, "signal_no_waiters");
}

/// Benchmark broadcast with no waiters (should skip futex_wake syscall).
fn bench_condvar_broadcast_no_waiters(c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();

    let mut cv = CondvarData {
        seq: AtomicU32::new(0),
        nwaiters: AtomicU32::new(0),
        assoc_mutex: std::sync::atomic::AtomicUsize::new(0),
        clock_id: AtomicU32::new(0),
    };
    unsafe {
        frankenlibc_core::pthread::condvar_init(&mut cv as *mut CondvarData, 0);
    }

    let stats = RefCell::new(BenchStats::default());
    let mut group = c.benchmark_group("condvar_hotpath");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("broadcast_no_waiters", mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                unsafe {
                    black_box(frankenlibc_core::pthread::condvar_broadcast(
                        &mut cv as *mut CondvarData,
                    ));
                }
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    group.finish();
    stats.borrow().report(mode, "broadcast_no_waiters");
}

/// Benchmark timedwait with past deadline (ETIMEDOUT fast path).
/// Measures the overhead of the timeout detection path without actual blocking.
fn bench_condvar_timedwait_past_deadline(c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();

    let mut cv = CondvarData {
        seq: AtomicU32::new(0),
        nwaiters: AtomicU32::new(0),
        assoc_mutex: std::sync::atomic::AtomicUsize::new(0),
        clock_id: AtomicU32::new(0),
    };
    unsafe {
        frankenlibc_core::pthread::condvar_init(&mut cv as *mut CondvarData, 0);
    }

    // Mutex word: simulate locked-by-caller state.
    let mutex_word = AtomicU32::new(1);
    let mutex_ptr = &mutex_word as *const AtomicU32 as *const u32;

    let stats = RefCell::new(BenchStats::default());
    let mut group = c.benchmark_group("condvar_hotpath");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("timedwait_past_deadline", mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                // Ensure mutex is "locked" before each call.
                mutex_word.store(1, Ordering::Release);
                let ret = unsafe {
                    frankenlibc_core::pthread::condvar_timedwait(
                        &mut cv as *mut CondvarData,
                        mutex_ptr,
                        0, // tv_sec = epoch
                        0, // tv_nsec = 0
                    )
                };
                black_box(ret);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    group.finish();
    stats.borrow().report(mode, "timedwait_past_deadline");
}

/// Manual threaded benchmark: wait + signal roundtrip (1 waiter, 1 signaler).
/// Not driven by criterion (thread-heavy benchmarks don't suit criterion warmup).
/// Runs a fixed number of roundtrips and emits structured stats.
fn bench_condvar_wait_signal_roundtrip(_c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();
    let rounds = 20;
    let iters_per_round: u64 = 500;
    let mut stats = BenchStats::default();

    for _ in 0..rounds {
        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: std::sync::atomic::AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        });
        unsafe {
            frankenlibc_core::pthread::condvar_init(Arc::as_ptr(&cv) as *mut CondvarData, 0);
        }
        let mutex_word = Arc::new(AtomicU32::new(0));
        let go_flag = Arc::new(AtomicU32::new(0));

        let cv2 = cv.clone();
        let go2 = go_flag.clone();

        let signaler = std::thread::spawn(move || {
            let cv_ptr = Arc::as_ptr(&cv2) as *mut CondvarData;
            for _ in 0..iters_per_round {
                while cv2.nwaiters.load(Ordering::Acquire) == 0 {
                    std::hint::spin_loop();
                }
                unsafe {
                    frankenlibc_core::pthread::condvar_signal(cv_ptr);
                }
                while go2.load(Ordering::Acquire) == 0 {
                    std::hint::spin_loop();
                }
                go2.store(0, Ordering::Release);
            }
        });

        let cv_ptr = Arc::as_ptr(&cv) as *mut CondvarData;
        let mutex_ptr = Arc::as_ptr(&mutex_word) as *const AtomicU32 as *const u32;

        let start = Instant::now();
        for _ in 0..iters_per_round {
            mutex_word.store(1, Ordering::Release);
            unsafe {
                frankenlibc_core::pthread::condvar_wait(cv_ptr, mutex_ptr);
            }
            go_flag.store(1, Ordering::Release);
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        signaler.join().expect("signaler thread panicked");
        stats.record(iters_per_round, dur);
    }
    stats.report(mode, "wait_signal_roundtrip");
}

/// Manual threaded benchmark: broadcast wake-all with 4 waiters.
/// Each waiter acquires mutex then calls condvar_wait (which releases it),
/// allowing the next waiter to acquire. Once all 4 are waiting, broadcaster fires.
fn bench_condvar_broadcast_4_waiters(_c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();
    let rounds = 20;
    let mut stats = BenchStats::default();

    for _ in 0..rounds {
        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: std::sync::atomic::AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        });
        unsafe {
            frankenlibc_core::pthread::condvar_init(Arc::as_ptr(&cv) as *mut CondvarData, 0);
        }
        let mutex_word = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let cv_c = cv.clone();
            let mw_c = mutex_word.clone();
            handles.push(std::thread::spawn(move || {
                let cv_ptr = Arc::as_ptr(&cv_c) as *mut CondvarData;
                let mutex_ptr = Arc::as_ptr(&mw_c) as *const AtomicU32 as *const u32;
                // Acquire mutex via CAS spin.
                loop {
                    if mw_c
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                    std::hint::spin_loop();
                }
                // condvar_wait atomically releases mutex and blocks.
                unsafe {
                    frankenlibc_core::pthread::condvar_wait(cv_ptr, mutex_ptr);
                }
                // Release mutex after waking so next waiter can proceed.
                mw_c.store(0, Ordering::Release);
            }));
        }

        // Spin until all 4 waiters are blocked in futex_wait.
        while cv.nwaiters.load(Ordering::Acquire) < 4 {
            std::hint::spin_loop();
        }

        let start = Instant::now();
        unsafe {
            frankenlibc_core::pthread::condvar_broadcast(Arc::as_ptr(&cv) as *mut CondvarData);
        }
        for h in handles {
            h.join().expect("waiter thread panicked");
        }
        let dur = start.elapsed().max(Duration::from_nanos(1));
        stats.record(1, dur);
    }
    stats.report(mode, "broadcast_4_waiters");
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(3))
        .sample_size(50);
    targets =
        bench_condvar_init_destroy,
        bench_condvar_signal_no_waiters,
        bench_condvar_broadcast_no_waiters,
        bench_condvar_timedwait_past_deadline,
        bench_condvar_wait_signal_roundtrip,
        bench_condvar_broadcast_4_waiters
);
criterion_main!(benches);
