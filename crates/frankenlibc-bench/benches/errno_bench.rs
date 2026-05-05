//! Harness-backed TLS errno accessor benchmarks (bd-hiogf).
//!
//! The target is intentionally a tiny `harness = false` binary instead of a
//! Criterion suite. Linking `frankenlibc-abi` into a release benchmark exports
//! libc ABI symbols, including `__errno_location`; keeping the benchmark runner
//! minimal avoids interposing on Criterion internals while still emitting the
//! same structured p50/p95/p99 rows consumed by `perf_gate.sh`.

use std::ffi::c_int;
use std::hint::black_box;
use std::time::{Duration, Instant};

use frankenlibc_abi::errno_abi;

const HOT_SAMPLES: usize = 100;
const HOT_ITERS_PER_SAMPLE: u64 = 100_000;

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
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };

        println!(
            "ERRNO_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
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
    let label = std::env::var("FRANKENLIBC_ERRNO_BENCH_MODE")
        .ok()
        .or_else(|| std::env::var("FRANKENLIBC_MODE").ok());
    match label.as_deref() {
        Some("hardened") => "hardened",
        Some("strict") => "strict",
        _ => "raw",
    }
}

fn warm_errno_slot() {
    // SAFETY: `__errno_location` returns the current thread's errno slot.
    let _ = unsafe { errno_abi::__errno_location() };
}

fn measure<F>(bench_label: &str, samples: usize, iters_per_sample: u64, mut op: F)
where
    F: FnMut(),
{
    let mut stats = BenchStats {
        samples_ns_per_op: Vec::with_capacity(samples),
        total_iters: 0,
        total_ns: 0,
    };

    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..iters_per_sample {
            op();
        }
        stats.record(
            iters_per_sample,
            start.elapsed().max(Duration::from_nanos(1)),
        );
    }

    stats.report(mode_label(), bench_label);
}

fn bench_errno_location_fastpath() {
    warm_errno_slot();
    measure(
        "errno_location_fastpath",
        HOT_SAMPLES,
        HOT_ITERS_PER_SAMPLE,
        || {
            // SAFETY: `__errno_location` returns the current thread's errno slot.
            let p = unsafe { errno_abi::__errno_location() };
            black_box(p);
        },
    );
}

fn bench_errno_set_then_read_roundtrip() {
    warm_errno_slot();
    measure(
        "errno_set_then_read_roundtrip",
        HOT_SAMPLES,
        HOT_ITERS_PER_SAMPLE,
        || {
            // SAFETY: `__errno_location` returns writable thread-local errno storage.
            let p = unsafe { errno_abi::__errno_location() };
            // SAFETY: `p` points to this thread's errno storage for the duration of the call.
            unsafe {
                std::ptr::write_volatile(p, black_box(42 as c_int));
            }
            // SAFETY: `p` points to initialized errno storage written immediately above.
            let v = unsafe { std::ptr::read_volatile(p) };
            black_box(v);
        },
    );
}

fn main() {
    for _ in 0..10_000 {
        warm_errno_slot();
    }
    bench_errno_location_fastpath();
    bench_errno_set_then_read_roundtrip();
}
