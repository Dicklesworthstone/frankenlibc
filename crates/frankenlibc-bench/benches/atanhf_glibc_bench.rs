//! f32 `atanhf` candidate bench: deployed (full f64 log+widen) vs fast-f32 kernel
//! (fl fused `logf` on the band |x| ∈ [0.5,1) where Sterbenz makes `1-|x|` exact and
//! there is no small-x cancellation; f64 elsewhere) vs host glibc atanhf — all in ONE
//! process so per-worker load cancels in the ratios (defeats rch cross-worker variance).
//! atanhf is the last inverse-hyperbolic still widening the whole range to f64 (its
//! siblings asinhf/acoshf/tanhf/coshf already have f32 fast paths). No `abi-bench` →
//! bare `extern atanhf` = host glibc directly.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench atanhf_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "atanhf"]
    fn host_atanhf(x: f32) -> f32;
}

#[inline]
fn candidate(x: f32) -> f32 {
    // Mirrors frankenlibc_core::math::atanhf.
    let ax = x.abs();
    if (0.5..1.0).contains(&ax) {
        let r = 0.5 * math::logf((1.0 + ax) / (1.0 - ax));
        return r.copysign(x);
    }
    let fx = x as f64;
    let r = 0.5 * math::log((1.0 + fx) / (1.0 - fx));
    (r as f32).copysign(x)
}

/// OLD deployed form: full f64 log+widen for every input (pre-fast-path baseline).
#[inline]
fn old_f64(x: f32) -> f32 {
    let fx = x as f64;
    let r = 0.5 * math::log((1.0 + fx) / (1.0 - fx));
    (r as f32).copysign(x)
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
    println!("ATANHF_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // FULL-domain ULP sweep over (-1,1): dense near 0 (small-x f64 path), through the
    // [0.5,1) fast band, up to just below the ±1 poles. Both signs. Log-spaced |x| in
    // [1e-6, 1-2^-20].
    let mut worst = 0u64;
    let mut wx = 0.0f32;
    for k in 0..60000u32 {
        let t = k as f64 / 60000.0;
        // |x| in [1e-6, ~0.999999], denser toward 1.
        let mag = (1.0 - 10.0_f64.powf(-6.0 + t * 6.0)).max(1e-6) as f32;
        for x in [mag, -mag] {
            let cand = candidate(x);
            let g = unsafe { host_atanhf(x) };
            if cand.is_nan() && g.is_nan() { continue; }
            let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
            if u > worst { worst = u; wx = x; }
        }
    }
    eprintln!("atanhf candidate vs glibc worst ULP over |x| in [1e-6,1) = {worst} at x={wx}");
    // exact special cases: ±0, ±1 poles, |x|>1 domain (NaN), inf
    for &(x, name) in &[(0.0f32, "+0"), (-0.0f32, "-0"), (1.0f32, "+1"), (-1.0f32, "-1")] {
        let (cand, g) = (candidate(x), unsafe { host_atanhf(x) });
        assert_eq!(cand.to_bits(), g.to_bits(), "atanhf special case x={x} ({name}) cand={cand} glibc={g}");
    }
    assert!(worst <= 2, "atanhf candidate exceeds 2 ULP vs glibc (worst {worst} at x={wx})");

    // Timing input: the [0.5,1) fast-path band (where this lever applies), both signs.
    let inp: Vec<f32> = (0..64).map(|k| {
        let m = 0.5 + (k as f32) * (0.49 / 64.0);
        if k % 2 == 0 { m } else { -m }
    }).collect();
    let mut g = c.benchmark_group("atanhf");
    g.sample_size(40);
    run(&mut g, "old_f64", &inp, old_f64);
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_atanhf(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
