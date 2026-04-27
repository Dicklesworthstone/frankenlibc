//! String function benchmarks.

use std::cell::RefCell;
use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::string::{
    memcmp, memcpy, strchr, strchrnul, strcmp, strcspn, strlen, strrchr,
};

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
            "STRING_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
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
        _ => "raw",
    }
}

fn bench_memcpy_sizes(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096, 65536];
    let mode = mode_label();
    let mut group = c.benchmark_group("memcpy");

    for &size in sizes {
        let src = vec![0xABu8; size];
        let mut dst = vec![0u8; size];
        let bench_label = format!("memcpy_{size}");
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(memcpy(&mut dst, &src, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(memcpy(&mut dst, &src, sz));
                    black_box(dst[0]);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strlen(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strlen");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strlen_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strlen(&s));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strlen(&s));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_memcmp_sizes(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("memcmp");

    for &size in sizes {
        let left = vec![0x5Au8; size];
        let right = vec![0x5Au8; size];
        let bench_label = format!("memcmp_{size}");
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(memcmp(&left, &right, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(memcmp(&left, &right, sz));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strcmp(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strcmp");

    for &size in sizes {
        let mut left = vec![b'Q'; size];
        let mut right = vec![b'Q'; size];
        let bench_label = format!("strcmp_{size}");
        left.push(0);
        right.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strcmp(&left, &right));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strcmp(&left, &right));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strchr_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strchr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strchr(&s, b'Z'));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strchr(&s, b'Z'));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strrchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strrchr_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strrchr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strrchr(&s, b'Z'));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strrchr(&s, b'Z'));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strcspn_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let reject = b"Z\0";
    let mut group = c.benchmark_group("strcspn_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strcspn_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strcspn(&s, reject));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strcspn(&s, reject));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strchrnul_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strchrnul_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strchrnul_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strchrnul(&s, b'Z'));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strchrnul(&s, b'Z'));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = bench_memcpy_sizes, bench_strlen, bench_memcmp_sizes, bench_strcmp, bench_strchr_absent, bench_strrchr_absent, bench_strcspn_absent, bench_strchrnul_absent
);
criterion_main!(benches);
