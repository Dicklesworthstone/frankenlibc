//! Membrane overhead benchmarks.
//!
//! Measures the per-call overhead of pointer validation at each
//! pipeline stage.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use frankenlibc_membrane::config::safety_level;
use frankenlibc_membrane::ptr_validator::ValidationPipeline;

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
            "MEMBRANE_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
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

fn maybe_pin_thread() {
    if std::env::var("GLIBC_RUST_BENCH_PIN").ok().as_deref() != Some("1") {
        return;
    }

    #[cfg(target_os = "linux")]
    unsafe {
        // SAFETY: Best-effort pinning for benchmarking determinism. Failure is not fatal.
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(0, &mut set);
        let rc = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if rc != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            eprintln!("MEMBRANE_BENCH_META pinning_failed errno={errno}");
        } else {
            println!("MEMBRANE_BENCH_META pinned_to_cpu=0");
        }
    }
}

fn bench_membrane(c: &mut Criterion) {
    maybe_pin_thread();

    let mode = safety_level();
    let mode_label = match mode {
        frankenlibc_membrane::SafetyLevel::Strict => "strict",
        frankenlibc_membrane::SafetyLevel::Hardened => "hardened",
        frankenlibc_membrane::SafetyLevel::Off => "off",
    };

    let mut group = c.benchmark_group("membrane");
    group.throughput(Throughput::Elements(1));

    // validate_null
    {
        let pipeline = ValidationPipeline::new();
        for _ in 0..10_000 {
            black_box(pipeline.validate(0));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_function(BenchmarkId::new("validate_null", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(pipeline.validate(0));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode_label, "validate_null");
    }

    // validate_foreign
    {
        let pipeline = ValidationPipeline::new();
        let addr = 0xDEAD_BEEF_0000usize;
        for _ in 0..10_000 {
            black_box(pipeline.validate(addr));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_function(BenchmarkId::new("validate_foreign", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(pipeline.validate(addr));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode_label, "validate_foreign");
    }

    // validate_known
    {
        let pipeline = ValidationPipeline::new();
        let ptr = pipeline.arena.allocate(256).expect("alloc");
        let addr = ptr as usize;
        pipeline.register_allocation(addr, 256);

        for _ in 0..10_000 {
            black_box(pipeline.validate(addr));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_function(BenchmarkId::new("validate_known", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(pipeline.validate(addr));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode_label, "validate_known");

        pipeline.arena.free(ptr);
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = bench_membrane
);
criterion_main!(benches);
