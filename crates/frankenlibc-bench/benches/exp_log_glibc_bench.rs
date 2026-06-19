//! Head-to-head benchmark for the fused f32 `exp2f` / `log2f` / `expf` kernels
//! vs host glibc (bd-fused-f32-exp-log-kernels).
//!
//! Each function previously delegated its general case to `libm` (~1.5–2.5x
//! slower than glibc). The lever ports the ARM optimized-routines fused kernels
//! (the same algorithms glibc ships). Three arms per function:
//!   - `fl`     : `frankenlibc_core::math::*` (new fused kernel)
//!   - `fl_old` : `libm::*` (the pre-lever fallback)
//!   - `glibc`  : host libc symbol via a plain `extern "C"` link (no fl ABI in
//!                this bench, so it resolves to glibc — no interposition)
//!
//! `expf` is sampled in [6, 80) — above fl's existing [-5,5] fast path, so the
//! new kernel is exercised; `exp2f`/`log2f` over their general ranges.

use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use frankenlibc_core::math;

unsafe extern "C" {
    #[link_name = "exp2f"]
    fn host_exp2f(x: f32) -> f32;
    #[link_name = "log2f"]
    fn host_log2f(x: f32) -> f32;
    #[link_name = "expf"]
    fn host_expf(x: f32) -> f32;
}

#[derive(Default)]
struct Stats {
    s: Vec<f64>,
    iters: u64,
    ns: u128,
}
impl Stats {
    fn record(&mut self, ops: u64, dur: Duration) {
        if ops == 0 {
            return;
        }
        self.iters += ops;
        self.ns += dur.as_nanos();
        self.s.push(dur.as_nanos() as f64 / ops as f64);
    }
    fn report(&self, impl_label: &str, case: &str) {
        let mut s = self.s.clone();
        if s.is_empty() {
            return;
        }
        s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p = |q: f64| {
            let r = q * (s.len() - 1) as f64;
            let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
            if lo == hi {
                s[lo]
            } else {
                s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
            }
        };
        let mean = s.iter().sum::<f64>() / s.len() as f64;
        let tput = if self.ns == 0 {
            0.0
        } else {
            self.iters as f64 / (self.ns as f64 / 1e9)
        };
        println!(
            "EXPLOG_BENCH impl={impl_label} case={case} samples={} p50_ns_op={:.4} \
             p95_ns_op={:.4} p99_ns_op={:.4} mean_ns_op={mean:.4} throughput_ops_s={tput:.1}",
            s.len(),
            p(0.50),
            p(0.95),
            p(0.99),
        );
    }
}

fn run<F: Fn(f32) -> f32>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    label: &str,
    case: &str,
    inputs: &[f32],
    f: F,
) {
    let stats = std::cell::RefCell::new(Stats::default());
    let n = inputs.len() as u64;
    group.bench_function(format!("{label}/{case}"), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut acc = 0.0_f32;
                for &x in inputs {
                    acc += f(black_box(x));
                }
                black_box(acc);
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters * n, dur);
            dur
        });
    });
    stats.borrow().report(label, case);
}

fn bench(c: &mut Criterion) {
    let exp2_in: Vec<f32> = (0..64).map(|k| -10.0 + k as f32 * 0.3125).collect();
    let log2_in: Vec<f32> = (0..64).map(|k| 1.5 + k as f32 * 1.5).collect();
    let exp_in: Vec<f32> = (0..64).map(|k| 6.0 + k as f32 * 1.15).collect(); // > 5, hits the kernel

    let mut group = c.benchmark_group("exp_log");
    group.sample_size(50);

    run(&mut group, "fl", "exp2f", &exp2_in, |x| math::exp2f(x));
    run(&mut group, "fl_old", "exp2f", &exp2_in, |x| libm::exp2f(x));
    run(&mut group, "glibc", "exp2f", &exp2_in, |x| unsafe {
        host_exp2f(x)
    });

    run(&mut group, "fl", "log2f", &log2_in, |x| math::log2f(x));
    run(&mut group, "fl_old", "log2f", &log2_in, |x| libm::log2f(x));
    run(&mut group, "glibc", "log2f", &log2_in, |x| unsafe {
        host_log2f(x)
    });

    run(&mut group, "fl", "expf", &exp_in, |x| math::expf(x));
    run(&mut group, "fl_old", "expf", &exp_in, |x| libm::expf(x));
    run(&mut group, "glibc", "expf", &exp_in, |x| unsafe {
        host_expf(x)
    });

    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
