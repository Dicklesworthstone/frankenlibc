//! Reliable same-process survey: fl f32 exact binary ops (fmodf/remainderf) vs host
//! glibc (cc/BoldFalcon). Completes the exact-op map for f32 (the f64 fmod/remainder
//! found fmod clean, remainder glibc-hardware-faster/unclosable). No `abi-bench` →
//! bare `extern "C"` resolves to host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench fmodf_survey_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "fmodf"] fn h_fmodf(x: f32, y: f32) -> f32;
    #[link_name = "remainderf"] fn h_remainderf(x: f32, y: f32) -> f32;
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if s.is_empty() { return 0.0; }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

fn survey(g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>, name: &str, inp: &[(f32, f32)], fl: impl Fn(f32, f32) -> f32, gl: impl Fn(f32, f32) -> f32) {
    let run = |f: &dyn Fn(f32, f32) -> f32| -> f64 {
        let one = || { let mut a = 0.0f32; for &(x, y) in inp { a += f(black_box(x), black_box(y)); } a };
        for _ in 0..50 { black_box(one()); }
        let mut s = Vec::new();
        for _ in 0..200 { let t = Instant::now(); black_box(one()); s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / inp.len() as f64); }
        p50(&mut s)
    };
    let (a, b) = (run(&fl), run(&gl));
    let ratio = a / b;
    let flag = if ratio > 1.30 { "  <-- LIBM-SLOW" } else { "" };
    println!("FMODF_SURVEY {name:18} fl_p50={a:7.3} glibc_p50={b:7.3} ratio={ratio:.3}{flag}");
    g.bench_function(name, |bb| bb.iter(|| black_box(fl(black_box(inp[0].0), black_box(inp[0].1)))));
}

fn bench(c: &mut Criterion) {
    let typical: Vec<(f32, f32)> = (0..64).map(|k| (3.0 + k as f32 * 1.7, 0.7 + (k % 5) as f32 * 0.3)).collect();
    let stress: Vec<(f32, f32)> = (0..64).map(|k| (1.0e7 + k as f32 * 1.3e5, 1.0 + (k % 7) as f32 * 0.11)).collect();
    let mut g = c.benchmark_group("fmodf_survey");
    g.sample_size(10);
    survey(&mut g, "fmodf_typical", &typical, |x, y| math::fmodf(x, y), |x, y| unsafe { h_fmodf(x, y) });
    survey(&mut g, "fmodf_stress", &stress, |x, y| math::fmodf(x, y), |x, y| unsafe { h_fmodf(x, y) });
    survey(&mut g, "remainderf_typical", &typical, |x, y| math::remainderf(x, y), |x, y| unsafe { h_remainderf(x, y) });
    survey(&mut g, "remainderf_stress", &stress, |x, y| math::remainderf(x, y), |x, y| unsafe { h_remainderf(x, y) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
