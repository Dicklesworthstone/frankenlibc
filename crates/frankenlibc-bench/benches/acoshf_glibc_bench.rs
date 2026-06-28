//! f32 `acoshf` candidate bench: deployed (f64 log+sqrt) vs fast-f32 kernel (fl fused
//! `logf` for x>=1.5 where (x-1) carries no cancellation; f64 for x in [1,1.5)) vs host
//! glibc. Survey: deployed acoshf 1.36x slower than glibc. acoshf has NO bit-exact
//! same32 gate (only fp-exceptions/errno/basic), so a <=4 ULP kernel is landable.
//! No `abi-bench` → bare `extern acoshf` = host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench acoshf_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "acoshf"]
    fn host_acoshf(x: f32) -> f32;
}

#[inline]
fn candidate(x: f32) -> f32 {
    if x < 1.0 {
        // out of domain: NaN (deployed raises FE_INVALID via 0/0; here just the value).
        return f32::NAN;
    }
    if x >= 1.5 {
        // (x-1) >= 0.5 — no cancellation; pure f32 with the fused fast logf.
        math::logf(x + ((x - 1.0) * (x + 1.0)).sqrt())
    } else {
        // x in [1,1.5): (x-1) loses bits near 1 → widen to f64 (unchanged path).
        let fx = x as f64;
        (math::log(fx + ((fx - 1.0) * (fx + 1.0)).sqrt())) as f32
    }
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
    println!("ACOSHF_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    let mut worst = 0u64;
    let mut wx = 1.0f32;
    for k in 0..40000u32 {
        let x = 1.0 + (k as f32) * (20.0 / 40000.0);
        let cand = candidate(x);
        let g = unsafe { host_acoshf(x) };
        let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
        if u > worst { worst = u; wx = x; }
    }
    eprintln!("acoshf candidate vs glibc worst ULP over [1,21] = {worst} at x={wx}");
    // x=1 -> acosh(1)=0; inf -> inf
    assert_eq!(candidate(1.0).to_bits(), unsafe { host_acoshf(1.0) }.to_bits(), "acoshf(1)");
    assert_eq!(candidate(f32::INFINITY).to_bits(), unsafe { host_acoshf(f32::INFINITY) }.to_bits(), "acoshf(inf)");
    assert!(worst <= 4, "acoshf candidate exceeds 4 ULP vs glibc (worst {worst} at x={wx})");

    let inp: Vec<f32> = (0..64).map(|k| 1.01 + k as f32 * 0.5).collect();
    let mut g = c.benchmark_group("acoshf");
    g.sample_size(20);
    run(&mut g, "fl_deployed", &inp, |x| math::acoshf(x));
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_acoshf(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
