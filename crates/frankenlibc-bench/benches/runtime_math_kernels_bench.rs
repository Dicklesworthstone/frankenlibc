//! Per-kernel runtime_math microbenchmarks.
//!
//! Purpose:
//! - Attribute overhead to individual runtime_math kernels/controllers.
//! - Catch regressions when a kernel implementation changes.
//!
//! Usage (run twice; mode is read once by membrane config):
//! - `FRANKENLIBC_MODE=strict cargo bench -p frankenlibc-bench --bench runtime_math_kernels_bench`
//! - `FRANKENLIBC_MODE=hardened cargo bench -p frankenlibc-bench --bench runtime_math_kernels_bench`
//!
//! Output:
//! - Machine-readable `RUNTIME_MATH_KERNEL_BENCH ... p50_ns_op=...` lines for perf gating.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use frankenlibc_membrane::config::safety_level;
use frankenlibc_membrane::runtime_math::approachability::ApproachabilityController;
use frankenlibc_membrane::runtime_math::bandit::ConstrainedBanditRouter;
use frankenlibc_membrane::runtime_math::barrier::BarrierOracle;
use frankenlibc_membrane::runtime_math::control::ControlLimits;
use frankenlibc_membrane::runtime_math::design::OptimalDesignController;
use frankenlibc_membrane::runtime_math::pareto::ParetoController;
use frankenlibc_membrane::runtime_math::risk::ConformalRiskEngine;
use frankenlibc_membrane::runtime_math::sos_barrier::{
    evaluate_fragmentation_barrier, evaluate_provenance_barrier, evaluate_quarantine_barrier,
};
use frankenlibc_membrane::{ApiFamily, RuntimeContext, SafetyLevel, ValidationProfile};

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
            "RUNTIME_MATH_KERNEL_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
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
        let mode_raw = std::env::var("FRANKENLIBC_MODE").unwrap_or_else(|_| "<unset>".to_string());
        let rustflags = std::env::var("RUSTFLAGS").unwrap_or_else(|_| "<unset>".to_string());
        let cpu = cpu_model().unwrap_or_else(|| "<unknown>".to_string());
        println!("RUNTIME_MATH_KERNEL_BENCH_META frankenlibc_mode_env={mode_raw}");
        println!("RUNTIME_MATH_KERNEL_BENCH_META rustflags={rustflags}");
        println!("RUNTIME_MATH_KERNEL_BENCH_META cpu_model={cpu}");
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
    if std::env::var("FRANKENLIBC_BENCH_PIN").ok().as_deref() != Some("1") {
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
            eprintln!("RUNTIME_MATH_KERNEL_BENCH_META pinning_failed errno={errno}");
        } else {
            println!("RUNTIME_MATH_KERNEL_BENCH_META pinned_to_cpu=0");
        }
    }
}

fn bench_runtime_math_kernels(c: &mut Criterion) {
    maybe_pin_thread();
    print_env_metadata_once();

    let mode = safety_level();
    let mode_label = match mode {
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
        SafetyLevel::Off => "off",
    };

    // Fixed context for barrier tests.
    let ctx = RuntimeContext::pointer_validation(0x1234_5678, false);

    // --- risk::upper_bound_ppm (steady-state path) ---
    {
        let risk = ConformalRiskEngine::default();
        for i in 0..256 {
            risk.observe(ApiFamily::PointerValidation, i % 127 == 0);
        }
        for _ in 0..10_000 {
            black_box(risk.upper_bound_ppm(ApiFamily::PointerValidation));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("risk_upper_bound_ppm", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(risk.upper_bound_ppm(ApiFamily::PointerValidation));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "risk_upper_bound_ppm");
    }

    // --- bandit::select_profile (steady-state path) ---
    {
        let router = ConstrainedBanditRouter::new();
        for i in 0..128 {
            let profile = if i % 2 == 0 {
                ValidationProfile::Fast
            } else {
                ValidationProfile::Full
            };
            router.observe(ApiFamily::PointerValidation, profile, 12, i % 17 == 0);
        }
        for _ in 0..10_000 {
            black_box(router.select_profile(ApiFamily::PointerValidation, mode, 55_000, 8));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("bandit_select_profile", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(router.select_profile(ApiFamily::PointerValidation, mode, 55_000, 8));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "bandit_select_profile");
    }

    // --- barrier::admissible ---
    {
        let barrier = BarrierOracle::new();
        let limits = ControlLimits {
            full_validation_trigger_ppm: 50_000,
            repair_trigger_ppm: 80_000,
            max_request_bytes: 4096,
        };
        for _ in 0..10_000 {
            black_box(barrier.admissible(&ctx, mode, ValidationProfile::Fast, 10_000, limits));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("barrier_admissible", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(barrier.admissible(
                        &ctx,
                        mode,
                        ValidationProfile::Fast,
                        10_000,
                        limits,
                    ));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "barrier_admissible");
    }

    // --- pareto::recommend_profile (steady-state path) ---
    {
        let pareto = ParetoController::new();
        for i in 0..256 {
            let chosen = if i % 3 == 0 {
                ValidationProfile::Full
            } else {
                ValidationProfile::Fast
            };
            pareto.observe(
                mode,
                ApiFamily::PointerValidation,
                chosen,
                12,
                i % 29 == 0,
                20_000,
            );
        }
        for _ in 0..10_000 {
            black_box(pareto.recommend_profile(
                mode,
                ApiFamily::PointerValidation,
                30_000,
                55_000,
                85_000,
            ));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(
            BenchmarkId::new("pareto_recommend_profile", mode_label),
            |b| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(pareto.recommend_profile(
                            mode,
                            ApiFamily::PointerValidation,
                            30_000,
                            55_000,
                            85_000,
                        ));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        group.finish();
        stats
            .borrow()
            .report(mode_label, "pareto_recommend_profile");
    }

    // --- design::choose_plan (cadence kernel) ---
    {
        let mut design = OptimalDesignController::new();
        for _ in 0..512 {
            black_box(design.choose_plan(mode, 20_000, false, false));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("design_choose_plan", mode_label), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(design.choose_plan(mode, 20_000, false, false));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        group.finish();
        stats.borrow().report(mode_label, "design_choose_plan");
    }

    // --- approachability::observe (steady-state, post-calibration) ---
    {
        let mut appr = ApproachabilityController::new(mode);
        // Pre-fill past calibration threshold so benches measure hot-path.
        for i in 0..512u64 {
            let lat = (i * 7919) % 1000;
            let risk = (i * 1013) % 1000;
            let cov = (i * 2027) % 1000;
            appr.observe(lat, risk, cov);
        }
        // Warm up.
        for _ in 0..10_000 {
            appr.observe(black_box(300), black_box(200), black_box(600));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(
            BenchmarkId::new("approachability_observe", mode_label),
            |b| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for i in 0..iters {
                        let lat = (i * 7919) % 1000;
                        let risk = (i * 1013) % 1000;
                        let cov = (i * 2027) % 1000;
                        appr.observe(black_box(lat), black_box(risk), black_box(cov));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        group.finish();
        stats.borrow().report(mode_label, "approachability_observe");
    }

    // --- approachability::state + summary (read-only snapshot) ---
    {
        let mut appr = ApproachabilityController::new(mode);
        for i in 0..512u64 {
            appr.observe((i * 41) % 1000, (i * 67) % 1000, (i * 89) % 1000);
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(
            BenchmarkId::new("approachability_summary", mode_label),
            |b| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(appr.state());
                        black_box(appr.summary());
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        group.finish();
        stats.borrow().report(mode_label, "approachability_summary");
    }

    // --- sos_barrier::evaluate_provenance_barrier (hot-path certificate) ---
    {
        for _ in 0..10_000 {
            black_box(evaluate_provenance_barrier(50_000, 0, 100_000, 200_000));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(
            BenchmarkId::new("sos_barrier_provenance_eval", mode_label),
            |b| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(evaluate_provenance_barrier(50_000, 0, 100_000, 200_000));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        group.finish();
        stats
            .borrow()
            .report(mode_label, "sos_barrier_provenance_eval");
    }

    // --- sos_barrier::evaluate_quarantine_barrier (cadence certificate) ---
    {
        for _ in 0..10_000 {
            black_box(evaluate_quarantine_barrier(4_096, 4, 1_000, 0));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(
            BenchmarkId::new("sos_barrier_quarantine_eval", mode_label),
            |b| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(evaluate_quarantine_barrier(4_096, 4, 1_000, 0));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        group.finish();
        stats
            .borrow()
            .report(mode_label, "sos_barrier_quarantine_eval");
    }

    // --- sos_barrier::evaluate_fragmentation_barrier (sawtooth profile) ---
    {
        // Precompute a deterministic 10K-cycle sawtooth sequence to avoid
        // per-iteration branch noise in timing samples.
        let mut sawtooth_profile = Vec::with_capacity(10_000);
        let mut alloc_count = 0u32;
        let mut free_count = 0u32;
        for i in 0..10_000u32 {
            if i % 2 == 0 {
                alloc_count = alloc_count.saturating_add(1);
            } else {
                free_count = free_count.saturating_add(1);
            }
            let dispersion_ppm = 120_000 + (i % 64) * 500;
            let arena_utilization_ppm = 450_000 + (i % 128) * 500;
            sawtooth_profile.push((
                alloc_count,
                free_count,
                dispersion_ppm.min(300_000),
                arena_utilization_ppm.min(700_000),
            ));
        }

        for &(a, f, d, u) in &sawtooth_profile {
            black_box(evaluate_fragmentation_barrier(a, f, d, u));
        }

        let stats = RefCell::new(BenchStats::default());
        let mut group = c.benchmark_group("runtime_math_kernels");
        group.throughput(Throughput::Elements(1));
        group.bench_function(
            BenchmarkId::new("sos_barrier_fragmentation_eval", mode_label),
            |b| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    let len = sawtooth_profile.len() as u64;
                    for i in 0..iters {
                        let idx = (i % len) as usize;
                        let (a, f, d, u) = sawtooth_profile[idx];
                        black_box(evaluate_fragmentation_barrier(a, f, d, u));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        group.finish();
        stats
            .borrow()
            .report(mode_label, "sos_barrier_fragmentation_eval");
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = bench_runtime_math_kernels
);
criterion_main!(benches);
