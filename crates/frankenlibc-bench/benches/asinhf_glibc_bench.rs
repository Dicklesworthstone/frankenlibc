//! f32 `asinhf` candidate bench: deployed (f64 log+sqrt formula) vs a fast-f32 kernel
//! (use fl's fused `logf` directly for |x|>=1 where there is no cancellation; keep f64
//! only for the small-|x| cancellation region) vs host glibc. Survey showed deployed
//! asinhf 1.51x slower than glibc. No `abi-bench` → bare `extern asinhf` = host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench asinhf_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "asinhf"]
    fn host_asinhf(x: f32) -> f32;
}

#[inline]
fn candidate(x: f32) -> f32 {
    let ax = x.abs();
    let r = if ax >= 1.0 {
        // |x| >= 1: x + sqrt(x^2+1) >= 1+sqrt(2), no cancellation — pure f32 with the
        // fused fast logf.
        math::logf(ax + (ax * ax + 1.0).sqrt())
    } else {
        // small |x|: cancellation in x + sqrt(x^2+1) ≈ 1; widen to f64 (rare branch).
        let fx = x as f64;
        let axd = fx.abs();
        math::log(axd + (axd * axd + 1.0).sqrt()) as f32
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

fn run<F: Fn(f32) -> f32>(g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>, name: &str, inp: &[f32], f: F) {
    let one = || { let mut a = 0.0f32; for &x in inp { a += f(black_box(x)); } a };
    for _ in 0..50 { black_box(one()); }
    let mut s = Vec::new();
    for _ in 0..200 { let t = Instant::now(); black_box(one()); s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / inp.len() as f64); }
    println!("ASINHF_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // Dense ULP sweep over [-20,20] incl the small-|x| region.
    let mut worst = 0u64;
    let mut wx = 0.0f32;
    for k in 0..40000u32 {
        let x = -20.0 + (k as f32) * (40.0 / 40000.0);
        let cand = candidate(x);
        let g = unsafe { host_asinhf(x) };
        let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
        if u > worst { worst = u; wx = x; }
    }
    eprintln!("asinhf candidate vs glibc worst ULP over [-20,20] = {worst} at x={wx}");
    // special cases
    for &(x, _name) in &[(f32::INFINITY, "inf"), (f32::NEG_INFINITY, "-inf"), (0.0f32, "+0"), (-0.0f32, "-0")] {
        let (cand, g) = (candidate(x), unsafe { host_asinhf(x) });
        assert_eq!(cand.to_bits(), g.to_bits(), "asinhf special case x={x} cand={cand} glibc={g}");
    }
    assert!(worst <= 4, "asinhf candidate exceeds 4 ULP vs glibc (worst {worst} at x={wx})");

    let inp: Vec<f32> = (0..64).map(|k| -20.0 + k as f32 * 0.625).collect();
    let mut g = c.benchmark_group("asinhf");
    g.sample_size(20);
    run(&mut g, "fl_deployed", &inp, |x| math::asinhf(x));
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_asinhf(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
