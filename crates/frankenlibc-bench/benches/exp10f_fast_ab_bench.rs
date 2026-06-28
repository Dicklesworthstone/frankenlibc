//! f32 `exp10f` fallback band: OLD (libm::exp2 generic) vs NEW (fl fused `crate::math::exp2`)
//! vs host glibc exp10f — same process. exp10f's fallback (outside the [-10,10] integer and
//! [0.5,2.5] profile bands) computes 10^x = exp2(x·log2 10) in f64; it still calls the slow
//! generic libm::exp2, while the f64 `exp10` already switched to fl's fused exp2. No `abi-bench`
//! → bare `extern exp10f` = host glibc. Gate: diff_exp10f_within_4_ulps (4 ULP).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench exp10f_fast_ab_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "exp10f"]
    fn host_exp10f(x: f32) -> f32;
}

const LOG2_10: f64 = core::f64::consts::LOG2_10;

#[inline]
fn old_libm(x: f32) -> f32 {
    (libm::exp2(x as f64 * LOG2_10)) as f32
}
#[inline]
fn candidate(x: f32) -> f32 {
    (math::exp2(x as f64 * LOG2_10)) as f32
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
    println!("EXP10F_FAST impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // ULP sweep over the fallback band: non-integer x across the finite-normal f32 range.
    // (10^x is a finite f32 normal for x in ~[-37.9, 38.5]; beyond that both routes cast to
    // 0/inf identically — exclude.) Both candidate vs glibc and candidate vs old_libm.
    let mut worst_g = 0u64;
    let mut wx = 0.0f32;
    let mut worst_self = 0u64;
    for k in 0..200000u32 {
        let x = -37.0 + (k as f32) * (74.0 / 200000.0) + 0.123_4; // off-integer
        if (0.5..=2.5).contains(&x) { continue; }
        let cand = candidate(x);
        let g = unsafe { host_exp10f(x) };
        if cand.is_infinite() && g.is_infinite() { continue; }
        let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
        if u > worst_g { worst_g = u; wx = x; }
        let us = ((cand.to_bits() as i64) - (old_libm(x).to_bits() as i64)).unsigned_abs();
        if us > worst_self { worst_self = us; }
    }
    eprintln!("exp10f candidate vs glibc worst ULP = {worst_g} at x={wx}; vs old_libm worst = {worst_self}");
    assert!(worst_g <= 4, "exp10f candidate exceeds 4 ULP vs glibc (worst {worst_g} at x={wx})");

    let inp: Vec<f32> = (0..64).map(|k| -20.0 + k as f32 * 0.6234).filter(|x| !(0.5..=2.5).contains(x)).collect();
    let mut g = c.benchmark_group("exp10f_fast");
    g.sample_size(40);
    run(&mut g, "old_libm", &inp, old_libm);
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_exp10f(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
