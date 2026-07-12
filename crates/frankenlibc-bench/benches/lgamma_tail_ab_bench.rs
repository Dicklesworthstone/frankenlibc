//! f64 `lgamma` large-x tail [13,∞): deployed (libm::lgamma) vs a Stirling-asymptotic
//! candidate (extended-precision (x-0.5)·ln(x) + Bernoulli series, fl fused log) vs host
//! glibc lgamma — same process. The deployed fast path only covers [3,13) (tgamma+log);
//! [13,∞) falls to libm. No `abi-bench` → bare `extern lgamma` = host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench lgamma_tail_ab_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "lgamma"]
    fn host_lgamma(x: f64) -> f64;
}

const HALF_LN_2PI: f64 = 0.918_938_533_204_672_74;
// ln(x) extended-precision split helpers reuse fl's fused log; we recover the product
// rounding error of (x-0.5)*ln(x) with an fma.
#[inline]
fn candidate(x: f64) -> f64 {
    // Stirling: lgamma(x) = (x-0.5)·ln(x) - x + 0.5·ln(2π) + Σ B_{2k}/(2k(2k-1) x^{2k-1}).
    let lnx = math::log(x);
    let a = x - 0.5;
    // (x-0.5)·ln(x) carried with the fma residual to keep the big leading term tight.
    let hi = a * lnx;
    let lo = a.mul_add(lnx, -hi);
    // Bernoulli series in w = 1/x², factored 1/x out front (Horner).
    let inv = 1.0 / x;
    let w = inv * inv;
    let mut s = 1.0_f64 / 1188.0; // B10 term coeff
    s = s.mul_add(w, -1.0 / 1680.0);
    s = s.mul_add(w, 1.0 / 1260.0);
    s = s.mul_add(w, -1.0 / 360.0);
    s = s.mul_add(w, 1.0 / 12.0);
    s *= inv;
    ((hi - x) + (HALF_LN_2PI + s)) + lo
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if s.is_empty() {
        return 0.0;
    }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

fn run<F: Fn(f64) -> f64>(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    inp: &[f64],
    f: F,
) {
    let one = || {
        let mut a = 0.0f64;
        for &x in inp {
            a += f(black_box(x));
        }
        a
    };
    for _ in 0..50 {
        black_box(one());
    }
    let mut s = Vec::new();
    for _ in 0..200 {
        let t = Instant::now();
        black_box(one());
        s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / inp.len() as f64);
    }
    println!("LGAMMA_TAIL_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // ULP sweep over [13, 1e6) vs glibc.
    let mut worst = 0u64;
    let mut wx = 13.0f64;
    for k in 0..200000u32 {
        let t = k as f64 / 200000.0;
        let x = 13.0 * 10.0_f64.powf(t * 13.886); // 13 .. ~1e15 (deployed fast-band cap)
        let cand = candidate(x);
        let g = unsafe { host_lgamma(x) };
        let u = ((cand.to_bits() as i128) - (g.to_bits() as i128)).unsigned_abs() as u64;
        if u > worst {
            worst = u;
            wx = x;
        }
    }
    eprintln!("lgamma candidate vs glibc worst ULP over [13,1e15) = {worst} at x={wx}");
    assert!(
        worst <= 2,
        "lgamma Stirling candidate exceeds 2 ULP vs glibc (worst {worst} at x={wx})"
    );

    let inp: Vec<f64> = (0..64).map(|k| 13.0 + k as f64 * (100.0 / 64.0)).collect();
    let mut g = c.benchmark_group("lgamma_tail");
    g.sample_size(40);
    run(&mut g, "old_libm", &inp, libm::lgamma);
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_lgamma(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
