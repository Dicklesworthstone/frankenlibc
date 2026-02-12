//! Runtime math kernel microbenchmarks.
//!
//! This benchmark is intended to measure the per-call overhead of:
//! - `RuntimeMathKernel::decide(...)`
//! - `RuntimeMathKernel::observe_validation_result(...)`
//! - the combined decide+observe loop
//!
//! Notes:
//! - `GLIBC_RUST_MODE=strict|hardened` is read once (cached) by the membrane config.
//!   To collect both strict and hardened numbers, run this bench twice:
//!   `GLIBC_RUST_MODE=strict cargo bench -p glibc-rs-bench --bench runtime_math_bench`
//!   `GLIBC_RUST_MODE=hardened cargo bench -p glibc-rs-bench --bench runtime_math_bench`
//! - Optional CPU pinning: set `GLIBC_RUST_BENCH_PIN=1` (Linux only).

use std::cell::RefCell;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use frankenlibc_membrane::config::safety_level;
use frankenlibc_membrane::{ApiFamily, MembraneAction, RuntimeContext, RuntimeMathKernel};

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
            "RUNTIME_MATH_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
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

fn print_env_metadata_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let mode_raw = std::env::var("GLIBC_RUST_MODE").unwrap_or_else(|_| "<unset>".to_string());
        let rustflags = std::env::var("RUSTFLAGS").unwrap_or_else(|_| "<unset>".to_string());
        let cpu = cpu_model().unwrap_or_else(|| "<unknown>".to_string());
        println!("RUNTIME_MATH_BENCH_META glibc_rust_mode_env={mode_raw}");
        println!("RUNTIME_MATH_BENCH_META rustflags={rustflags}");
        println!("RUNTIME_MATH_BENCH_META cpu_model={cpu}");
    });
}

fn cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("model name") {
            let rest = rest.trim_start_matches(':').trim();
            if !rest.is_empty() {
                return Some(rest.to_string());
            }
        }
    }
    None
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
            // Intentionally do not panic; benches should still run.
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            eprintln!("RUNTIME_MATH_BENCH_META pinning_failed errno={errno}");
        } else {
            println!("RUNTIME_MATH_BENCH_META pinned_to_cpu=0");
        }
    }
}

fn bench_runtime_math(c: &mut Criterion) {
    maybe_pin_thread();
    print_env_metadata_once();

    let mode = safety_level();
    let mode_label = match mode {
        frankenlibc_membrane::SafetyLevel::Strict => "strict",
        frankenlibc_membrane::SafetyLevel::Hardened => "hardened",
        frankenlibc_membrane::SafetyLevel::Off => "off",
    };

    // Fixed input context (deterministic).
    let ctx = RuntimeContext::pointer_validation(0x1234_5678, false);

    // --- decide() ---
    {
        let kernel = RuntimeMathKernel::new();
        // Deterministic warmup to stabilize caches/branches.
        for _ in 0..10_000 {
            black_box(kernel.decide(mode, ctx));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("decide", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(kernel.decide(mode, ctx));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "decide");
    }

    // --- observe_validation_result() ---
    {
        let kernel = RuntimeMathKernel::new();
        // Warmup: ensure any internal caches/tables initialize deterministically.
        for _ in 0..10_000 {
            kernel.observe_validation_result(
                ApiFamily::PointerValidation,
                frankenlibc_membrane::ValidationProfile::Fast,
                12,
                false,
            );
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("observe_fast", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    kernel.observe_validation_result(
                        ApiFamily::PointerValidation,
                        frankenlibc_membrane::ValidationProfile::Fast,
                        12,
                        false,
                    );
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "observe_fast");
    }

    // --- decide()+observe_validation_result() ---
    {
        let kernel = RuntimeMathKernel::new();
        for _ in 0..10_000 {
            let d = kernel.decide(mode, ctx);
            let cost = if d.profile.requires_full() { 120 } else { 12 };
            let adverse = matches!(d.action, MembraneAction::Repair(_) | MembraneAction::Deny);
            kernel.observe_validation_result(ctx.family, d.profile, cost, adverse);
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("decide_observe", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let d = kernel.decide(mode, ctx);
                    let cost = if d.profile.requires_full() { 120 } else { 12 };
                    let adverse =
                        matches!(d.action, MembraneAction::Repair(_) | MembraneAction::Deny);
                    kernel.observe_validation_result(ctx.family, d.profile, cost, adverse);
                    black_box(d.policy_id);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "decide_observe");
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        // Criterion requires a non-zero warmup duration; we still do our own fixed warmup loops.
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = bench_runtime_math
);
criterion_main!(benches);
