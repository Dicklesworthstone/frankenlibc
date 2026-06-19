//! Head-to-head benchmark for the fused f64 `exp2` kernel vs host glibc
//! (bd-fused-f64-pow-exp-log-kernels). fl's f64 `exp2` previously delegated to
//! `libm::exp2`. Arms: `fl` (`frankenlibc_core::math::exp2`, new ARM/glibc
//! table kernel), `fl_old` (`libm::exp2`), `glibc` (host `exp2` via plain
//! `extern "C"` — no fl ABI linked, so no interposition).

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "exp2"]
    fn host_exp2(x: f64) -> f64;
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
    fn report(&self, label: &str) {
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
            "EXP2F64_BENCH impl={label} samples={} p50_ns_op={:.4} p95_ns_op={:.4} \
             p99_ns_op={:.4} mean_ns_op={mean:.4} throughput_ops_s={tput:.1}",
            s.len(),
            p(0.50),
            p(0.95),
            p(0.99),
        );
    }
}

fn run<F: Fn(f64) -> f64>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    label: &str,
    inputs: &[f64],
    f: F,
) {
    let stats = std::cell::RefCell::new(Stats::default());
    let n = inputs.len() as u64;
    group.bench_function(label, |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                let mut acc = 0.0_f64;
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
    stats.borrow().report(label);
}

fn bench(c: &mut Criterion) {
    let inputs: Vec<f64> = (0..64).map(|k| -10.0 + k as f64 * 0.3125).collect();
    let mut group = c.benchmark_group("exp2_f64");
    group.sample_size(50);
    run(&mut group, "fl", &inputs, |x| math::exp2(x));
    run(&mut group, "fl_old", &inputs, |x| libm::exp2(x));
    run(&mut group, "glibc", &inputs, |x| unsafe { host_exp2(x) });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
