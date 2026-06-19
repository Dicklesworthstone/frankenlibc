//! Head-to-head `powf` (f32) benchmark: FrankenLibC vs host glibc, focused on
//! the GENERAL path (base outside the medium [0.5,2.5) box, non-special
//! exponent) where fl previously fell back to `libm::powf`.
//!
//! Campaign target bd-z8p3mx: fl `powf`'s general/irrational case deferred to
//! `libm::powf` (~2.5x slower than glibc). The lever routes the general
//! positive-base case through `exp(y*ln(x))` evaluated in f64 using fl's own
//! fast f64 `exp`/`log` kernels (both beat glibc), accepting the result only
//! when it rounds to a finite normal f32 (overflow/underflow/subnormal still
//! defer to libm for exact exception/errno semantics).
//!
//! Three arms per case:
//!   - `fl`     : `frankenlibc_core::math::powf` (the new general fast path)
//!   - `fl_old` : `libm::powf` (the pre-lever general fallback)
//!   - `glibc`  : host libc `powf` via a plain `extern "C"` link (no fl ABI in
//!                this bench, so the symbol resolves to glibc — no interposition)
//!
//! ratio of interest = fl_p50 / glibc_p50 (lower is better; <1 = fl faster).

use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use frankenlibc_core::math;

unsafe extern "C" {
    #[link_name = "powf"]
    fn host_powf(x: f32, y: f32) -> f32;
}

#[derive(Default)]
struct Stats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl Stats {
    fn record(&mut self, ops: u64, dur: Duration) {
        if ops == 0 {
            return;
        }
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(ops);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / ops as f64);
    }

    fn report(&self, impl_label: &str, case: &str) {
        let mut s = self.samples_ns_per_op.clone();
        if s.is_empty() {
            return;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = percentile_sorted(&s, 0.50);
        let p95 = percentile_sorted(&s, 0.95);
        let p99 = percentile_sorted(&s, 0.99);
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        let throughput = if self.total_ns == 0 {
            0.0
        } else {
            self.total_iters as f64 / (self.total_ns as f64 / 1e9)
        };
        println!(
            "POWF_BENCH impl={impl_label} case={case} samples={} p50_ns_op={p50:.4} \
             p95_ns_op={p95:.4} p99_ns_op={p99:.4} mean_ns_op={mean:.4} throughput_ops_s={throughput:.1}",
            s.len(),
        );
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = p * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = rank - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }
}

/// One measurement case: a fixed input batch and a fixed exponent.
struct Case {
    name: &'static str,
    inputs: Vec<f32>,
    y: f32,
}

fn build_cases() -> Vec<Case> {
    // General path: base > 2.5 (exits the medium box) with a non-special
    // irrational exponent -> previously libm::powf, now the f64 exp/ln route.
    let big: Vec<f32> = (0..64).map(|k| 3.0 + (k as f32) * 0.10).collect();
    // General path: base in (0, 0.5) (below the medium box).
    let small: Vec<f32> = (0..64).map(|k| 0.02 + (k as f32) * 0.0070).collect();
    // Medium-box reference (not changed by the lever): base in [0.5,2.5),
    // non-1.337 exponent -> the existing exp2f/log2f medium fast path.
    let mid: Vec<f32> = (0..64).map(|k| 0.5 + (k as f32) * 0.031_25).collect();
    vec![
        Case {
            name: "general_big_e",
            inputs: big.clone(),
            y: std::f32::consts::E,
        },
        Case {
            name: "general_small_1p7",
            inputs: small,
            y: 1.7,
        },
        Case {
            name: "general_big_pi",
            inputs: big,
            y: std::f32::consts::PI,
        },
        Case {
            name: "medium_ref_1p7",
            inputs: mid,
            y: 1.7,
        },
    ]
}

fn bench_powf(c: &mut Criterion) {
    let cases = build_cases();
    let mut group = c.benchmark_group("powf_general");
    group.sample_size(50);

    for case in &cases {
        let n = case.inputs.len() as u64;
        let y = case.y;

        // fl: new general fast path.
        let fl_stats = std::cell::RefCell::new(Stats::default());
        group.bench_function(format!("fl/{}", case.name), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let mut acc = 0.0_f32;
                    for &x in &case.inputs {
                        acc += math::powf(black_box(x), black_box(y));
                    }
                    black_box(acc);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                fl_stats.borrow_mut().record(iters * n, dur);
                dur
            });
        });
        fl_stats.borrow().report("fl", case.name);

        // fl_old: the pre-lever libm::powf fallback.
        let old_stats = std::cell::RefCell::new(Stats::default());
        group.bench_function(format!("fl_old/{}", case.name), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let mut acc = 0.0_f32;
                    for &x in &case.inputs {
                        acc += libm::powf(black_box(x), black_box(y));
                    }
                    black_box(acc);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                old_stats.borrow_mut().record(iters * n, dur);
                dur
            });
        });
        old_stats.borrow().report("fl_old", case.name);

        // glibc: host powf.
        let glibc_stats = std::cell::RefCell::new(Stats::default());
        group.bench_function(format!("glibc/{}", case.name), |b| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let mut acc = 0.0_f32;
                    for &x in &case.inputs {
                        // SAFETY: plain libc powf on finite f32 inputs.
                        acc += unsafe { host_powf(black_box(x), black_box(y)) };
                    }
                    black_box(acc);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                glibc_stats.borrow_mut().record(iters * n, dur);
                dur
            });
        });
        glibc_stats.borrow().report("glibc", case.name);
    }

    group.finish();
}

criterion_group!(benches, bench_powf);
criterion_main!(benches);
