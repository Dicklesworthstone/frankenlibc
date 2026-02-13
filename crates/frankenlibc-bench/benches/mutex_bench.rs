//! Mutex hot-path microbenchmarks for bd-300.
//!
//! Captures uncontended lock/unlock and try_lock overhead with deterministic
//! per-mode metadata (`FRANKENLIBC_MODE`) and percentile summaries.

use std::cell::RefCell;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

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
            "MUTEX_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
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
        println!("MUTEX_BENCH_META frankenlibc_mode_env={mode_raw}");
    });
}

fn bench_mutex_lock_unlock(c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();
    let lock = Mutex::new(0u64);
    for _ in 0..10_000 {
        let mut guard = lock.lock().expect("mutex lock");
        *guard = guard.wrapping_add(1);
    }

    let stats = RefCell::new(BenchStats::default());
    let mut group = c.benchmark_group("mutex_hotpath");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("lock_unlock", mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut guard = lock.lock().expect("mutex lock");
                *guard = guard.wrapping_add(1);
                black_box(*guard);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    group.finish();
    stats.borrow().report(mode, "lock_unlock");
}

fn bench_mutex_try_lock(c: &mut Criterion) {
    print_env_metadata_once();
    let mode = mode_label();
    let lock = Mutex::new(1u64);
    for _ in 0..10_000 {
        let guard = lock.try_lock().expect("mutex try_lock");
        black_box(*guard);
    }

    let stats = RefCell::new(BenchStats::default());
    let mut group = c.benchmark_group("mutex_hotpath");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("try_lock", mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let guard = lock.try_lock().expect("mutex try_lock");
                black_box(*guard);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    group.finish();
    stats.borrow().report(mode, "try_lock");
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(80);
    targets = bench_mutex_lock_unlock, bench_mutex_try_lock
);
criterion_main!(benches);
