//! f64 `asinh` x>=16: current asymptotic (log(ax)+LN_2+z·p, 1-ULP-off, gate RED) vs
//! the correctly-rounded sqrt-formula log(x+sqrt(x²+1)) [both with fl's `log`] vs glibc.
//! Decides whether option (a) (fix correctness via sqrt-formula) is FREE — i.e.
//! bit-exact-vs-glibc with fl's log AND not slower than the asymptotic.
//! No `abi-bench` → bare `extern asinh` = host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench asinh_fix_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "asinh"] fn h_asinh(x: f64) -> f64;
}

// Current deployed asymptotic (replicated).
#[inline]
fn asymptotic(x: f64) -> f64 {
    let ax = x.abs();
    let z = 1.0 / (ax * ax);
    let mut p: f64 = 63.0 / 2560.0;
    p = p.mul_add(z, -35.0 / 1024.0);
    p = p.mul_add(z, 5.0 / 96.0);
    p = p.mul_add(z, -3.0 / 32.0);
    p = p.mul_add(z, 0.25);
    let r = math::log(ax) + core::f64::consts::LN_2 + z * p;
    if x.is_sign_negative() { -r } else { r }
}

// Candidate: correctly-rounded sqrt-formula with fl's log; asymptotic only for the
// overflow tail where x²+1 overflows.
#[inline]
fn sqrt_formula(x: f64) -> f64 {
    let ax = x.abs();
    let r = if ax < 1.0e154 {
        math::log(ax + (ax * ax + 1.0).sqrt())
    } else {
        math::log(ax) + core::f64::consts::LN_2
    };
    if x.is_sign_negative() { -r } else { r }
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if s.is_empty() { return 0.0; }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

fn run(g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>, name: &str, inp: &[f64], f: impl Fn(f64) -> f64) {
    let one = || { let mut a = 0.0; for &x in inp { a += f(black_box(x)); } a };
    for _ in 0..50 { black_box(one()); }
    let mut s = Vec::new();
    for _ in 0..200 { let t = Instant::now(); black_box(one()); s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / inp.len() as f64); }
    println!("ASINH_FIX impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // bit-exact (with FL's log) vs glibc over the x>=16 range (both signs).
    let mut worst_asym = 0u64; let mut worst_sqrt = 0u64; let mut wa = 0.0; let mut ws = 0.0;
    let mut k = 0u64;
    let mut x = 16.0f64;
    while x < 1.0e154 {
        for &xx in &[x, -x] {
            let g = unsafe { h_asinh(xx) };
            let da = ((asymptotic(xx).to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
            let ds = ((sqrt_formula(xx).to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
            if da > worst_asym { worst_asym = da; wa = xx; }
            if ds > worst_sqrt { worst_sqrt = ds; ws = xx; }
        }
        x *= 1.0009; k += 1;
        if k > 800_000 { break; }
    }
    eprintln!("asinh x>=16 worst ULP vs glibc: asymptotic={worst_asym} (at {wa}), sqrt_formula={worst_sqrt} (at {ws}) over {k} pts");

    let inp: Vec<f64> = (0..64).map(|i| 16.0 + i as f64 * 1.0e4).collect();
    let mut g = c.benchmark_group("asinh_fix");
    g.sample_size(20);
    run(&mut g, "asymptotic_current", &inp, asymptotic);
    run(&mut g, "sqrt_formula_candidate", &inp, sqrt_formula);
    run(&mut g, "glibc", &inp, |x| unsafe { h_asinh(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
