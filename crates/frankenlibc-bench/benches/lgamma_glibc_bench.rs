//! Head-to-head f64 `lgamma` benchmark: frankenlibc_core vs host glibc (cc/BoldFalcon).
//!
//! `lgamma` is a `libm` passthrough (math/special.rs) never measured vs glibc. If the
//! passthrough loses, a candidate lever is `log(tgamma(x))` reusing fl's fast Cephes
//! `tgamma` + fused `log` over the no-cancellation range (x not near 1/2). This bench
//! both checks the passthrough gap AND measures that candidate so the decision is
//! data-driven. No `abi-bench` → bare `extern "C" lgamma` resolves to host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench lgamma_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "lgamma"]
    fn host_lgamma(x: f64) -> f64;
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
            "LGAMMA_BENCH impl={label} samples={} p50_ns_op={:.4} p95_ns_op={:.4} mean_ns_op={mean:.4}",
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

// Candidate lever: log(tgamma(x)) over the no-cancellation range. tgamma is fl's fast
// Cephes rational; log is fl's fused kernel. Only valid where lgamma is not near 0
// (x>~2.5) and tgamma does not overflow (x<=~13). Caller gates the range.
#[inline]
fn lgamma_via_tgamma(x: f64) -> f64 {
    math::log(math::tgamma(x))
}

fn bench(c: &mut Criterion) {
    // No-cancellation, no-overflow range: x in [3, 13). lgamma > 0.69 here, tgamma finite.
    let inputs: Vec<f64> = (0..64).map(|k| 3.0 + k as f64 * (10.0 / 64.0)).collect();

    // ULP: candidate vs glibc (the passthrough fl==libm is the reference baseline).
    let mut worst_cand = 0u64;
    for &x in &inputs {
        let g = unsafe { host_lgamma(x) };
        let c2 = lgamma_via_tgamma(x);
        let u = ((c2.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
        worst_cand = worst_cand.max(u);
    }
    eprintln!("lgamma_via_tgamma vs glibc worst ULP over [3,13) = {worst_cand}");

    let mut group = c.benchmark_group("lgamma_f64");
    group.sample_size(60);
    run(&mut group, "fl_libm", &inputs, |x| math::lgamma(x));
    run(
        &mut group,
        "candidate_log_tgamma",
        &inputs,
        lgamma_via_tgamma,
    );
    run(&mut group, "glibc", &inputs, |x| unsafe { host_lgamma(x) });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
