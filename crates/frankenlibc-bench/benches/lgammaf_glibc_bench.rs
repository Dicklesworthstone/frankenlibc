//! Head-to-head f32 `lgammaf` benchmark: frankenlibc_core vs host glibc (cc/BoldFalcon).
//!
//! Sibling of `lgamma_glibc_bench`. `lgammaf` is a `libm` passthrough; libm's f32
//! gamma family is slow (the in-tree `tgammaf` already routes through the f64 Cephes
//! `tgamma` because `libm::tgammaf` is ~7x glibc). Candidate: `log(tgamma(x as f64))
//! as f32` over the no-cancellation/no-overflow band [3,13). No `abi-bench` → bare
//! `extern "C" lgammaf` resolves to host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench lgammaf_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "lgammaf"]
    fn host_lgammaf(x: f32) -> f32;
}

#[derive(Default)]
struct Stats {
    s: Vec<f64>,
}
impl Stats {
    fn record(&mut self, ops: u64, dur: Duration) {
        if ops > 0 {
            self.s.push(dur.as_nanos() as f64 / ops as f64);
        }
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
        println!(
            "LGAMMAF_BENCH impl={label} samples={} p50_ns_op={:.4} p95_ns_op={:.4} mean_ns_op={mean:.4}",
            s.len(),
            p(0.50),
            p(0.95),
        );
    }
}

fn run<F: Fn(f32) -> f32>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    label: &str,
    inputs: &[f32],
    f: F,
) {
    let stats = std::cell::RefCell::new(Stats::default());
    let n = inputs.len() as u64;
    group.bench_function(label, |b| {
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
    stats.borrow().report(label);
}

#[inline]
fn lgammaf_via_tgamma(x: f32) -> f32 {
    (math::log(math::tgamma(x as f64)) as f32)
}

fn bench(c: &mut Criterion) {
    let inputs: Vec<f32> = (0..64).map(|k| 3.0 + k as f32 * (10.0 / 64.0)).collect();

    // ULP: candidate vs glibc lgammaf across [3,13).
    let mut worst = 0u64;
    for &x in &inputs {
        let g = unsafe { host_lgammaf(x) };
        let cand = lgammaf_via_tgamma(x);
        let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
        worst = worst.max(u);
    }
    eprintln!("lgammaf_via_tgamma vs glibc worst ULP over [3,13) = {worst}");

    let mut group = c.benchmark_group("lgammaf_f32");
    group.sample_size(60);
    run(&mut group, "fl_libm", &inputs, |x| math::lgammaf(x));
    run(
        &mut group,
        "candidate_log_tgamma",
        &inputs,
        lgammaf_via_tgamma,
    );
    run(&mut group, "glibc", &inputs, |x| unsafe { host_lgammaf(x) });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
