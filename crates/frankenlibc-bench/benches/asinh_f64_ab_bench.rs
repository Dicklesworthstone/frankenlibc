//! f64 `asinh` midrange [1,16) candidate: OLD (libm::asinh) vs NEW (fl fused f64 `log`
//! of the no-cancellation form log(|x|+√(x²+1))) vs host glibc asinh — all in ONE
//! process so per-worker load cancels in the ratios. The f64 survey flagged asinh at
//! ~1.20x LOSS vs glibc; the loss is in the [1,16) libm midrange (|x|≥16 already uses an
//! asymptotic series, |x|<1 keeps libm for the cancellation). This is the bare-log form,
//! NOT the previously-rejected log1p form. No `abi-bench` → bare `extern asinh` = glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench asinh_f64_ab_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "asinh"]
    fn host_asinh(x: f64) -> f64;
}

#[inline]
fn candidate(x: f64) -> f64 {
    // Mirrors the [1,16) band of frankenlibc_core::math::asinh.
    let ax = x.abs();
    let r = math::log(ax + (ax * ax + 1.0).sqrt());
    if x.is_sign_negative() { -r } else { r }
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
    println!("ASINH_F64_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // ULP sweep over the [1,16) band (both signs) vs glibc.
    let mut worst = 0u64;
    let mut wx = 1.0f64;
    for k in 0..200000u32 {
        let mag = 1.0 + (k as f64) * (15.0 / 200000.0);
        for x in [mag, -mag] {
            let cand = candidate(x);
            let g = unsafe { host_asinh(x) };
            let u = ((cand.to_bits() as i128) - (g.to_bits() as i128)).unsigned_abs() as u64;
            if u > worst {
                worst = u;
                wx = x;
            }
        }
    }
    eprintln!("asinh candidate vs glibc worst ULP over |x| in [1,16) = {worst} at x={wx}");
    assert!(
        worst <= 2,
        "asinh candidate exceeds 2 ULP vs glibc (worst {worst} at x={wx})"
    );

    // Timing input: the [1,16) midrange band, both signs.
    let inp: Vec<f64> = (0..64)
        .map(|k| {
            let m = 1.0 + (k as f64) * (15.0 / 64.0);
            if k % 2 == 0 { m } else { -m }
        })
        .collect();
    let mut g = c.benchmark_group("asinh_f64");
    g.sample_size(40);
    run(&mut g, "old_libm", &inp, libm::asinh);
    run(&mut g, "candidate", &inp, candidate);
    run(&mut g, "glibc", &inp, |x| unsafe { host_asinh(x) });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
