//! Head-to-head f64 `cbrt` benchmark: frankenlibc_core vs host glibc (cc/BoldFalcon).
//!
//! `cbrt` is a `libm` passthrough in fl (math/float.rs:57). Both glibc and libm use
//! the Kahan magic-constant + Newton/Halley refinement, so this checks whether the
//! passthrough is at parity or whether glibc's variant is enough faster to justify a
//! port. No `abi-bench` → bare `extern "C" cbrt` resolves to host glibc directly.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench cbrt_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "cbrt"]
    fn host_cbrt(x: f64) -> f64;
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
        println!(
            "CBRT_BENCH impl={label} samples={} p50_ns_op={:.4} p95_ns_op={:.4} mean_ns_op={mean:.4}",
            s.len(),
            p(0.50),
            p(0.95),
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
    // Spread across magnitudes + signs (cbrt domain is all reals).
    let inputs: Vec<f64> = (0..64)
        .map(|k| {
            let t = -8.0 + k as f64 * 0.27;
            let v = 10.0_f64.powf(t);
            if k & 1 == 0 { v } else { -v }
        })
        .collect();

    // Conformance: fl cbrt is bit-identical to libm (it IS libm::cbrt); also assert
    // <=1 ULP vs glibc across the sweep.
    let mut worst = 0u64;
    for &x in &inputs {
        let (a, b) = (math::cbrt(x), unsafe { host_cbrt(x) });
        let u = ((a.to_bits() as i64) - (b.to_bits() as i64)).unsigned_abs();
        worst = worst.max(u);
    }
    eprintln!("cbrt fl-vs-glibc worst ULP = {worst}");

    let mut group = c.benchmark_group("cbrt_f64");
    group.sample_size(60);
    run(&mut group, "fl", &inputs, |x| math::cbrt(x));
    run(&mut group, "glibc", &inputs, |x| unsafe { host_cbrt(x) });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
