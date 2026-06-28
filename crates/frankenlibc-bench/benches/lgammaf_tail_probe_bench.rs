//! f32 `lgammaf` large-x tail probe: deployed (libm::lgammaf) vs candidate
//! (fl's now-fast f64 `lgamma` rounded once: `lgamma(x as f64) as f32`) vs host glibc.
//! Probe-only: decides whether the f32 tail is a lever. No `abi-bench` → bare glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench lgammaf_tail_probe_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "lgammaf"]
    fn host_lgammaf(x: f32) -> f32;
}

#[inline]
fn candidate(x: f32) -> f32 {
    math::lgamma(x as f64) as f32
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
    println!("LGAMMAF_TAIL impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // ULP sweep over the deployed fast band [13, 1e15) vs glibc.
    let mut worst = 0u64;
    let mut wx = 13.0f32;
    for k in 0..120000u32 {
        let t = k as f64 / 120000.0;
        let x = (13.0 * 10.0_f64.powf(t * 13.886)) as f32; // 13 .. ~1e15
        let cand = candidate(x);
        let g = unsafe { host_lgammaf(x) };
        if cand.is_infinite() && g.is_infinite() { continue; }
        let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
        if u > worst { worst = u; wx = x; }
    }
    eprintln!("lgammaf candidate vs glibc worst ULP over [13,1e15) = {worst} at x={wx}");
    assert!(worst <= 1, "lgammaf f64-route candidate exceeds 1 ULP vs glibc (worst {worst} at x={wx})");

    let inp: Vec<f32> = (0..64).map(|k| 13.0 + k as f32 * (200.0 / 64.0)).collect();
    let mut g = c.benchmark_group("lgammaf_tail");
    g.sample_size(40);
    run(&mut g, "old_libm", &inp, |x| libm::lgammaf(x));
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_lgammaf(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
