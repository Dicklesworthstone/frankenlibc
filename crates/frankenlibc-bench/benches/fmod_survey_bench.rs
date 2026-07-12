//! Reliable same-process survey: fl f64 exact binary ops (fmod/remainder) vs host
//! glibc (cc/BoldFalcon). These are exact (bit-exact-gated), so a lever here would be
//! a FASTER EXACT algorithm (not an accuracy trade). Flag if deployed >1.30x slower.
//! Two regimes: typical (small quotient) + stress (large x/y → many reduction steps).
//! No `abi-bench` → bare `extern "C"` resolves to host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench fmod_survey_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "fmod"]
    fn h_fmod(x: f64, y: f64) -> f64;
    #[link_name = "remainder"]
    fn h_remainder(x: f64, y: f64) -> f64;
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

fn survey(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    inp: &[(f64, f64)],
    fl: impl Fn(f64, f64) -> f64,
    gl: impl Fn(f64, f64) -> f64,
) {
    let run = |f: &dyn Fn(f64, f64) -> f64| -> f64 {
        let one = || {
            let mut a = 0.0;
            for &(x, y) in inp {
                a += f(black_box(x), black_box(y));
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
        p50(&mut s)
    };
    let (a, b) = (run(&fl), run(&gl));
    let ratio = a / b;
    let flag = if ratio > 1.30 {
        "  <-- LIBM-SLOW: exact-algo lever candidate"
    } else {
        ""
    };
    println!("FMOD_SURVEY {name:18} fl_p50={a:7.3} glibc_p50={b:7.3} ratio={ratio:.3}{flag}");
    g.bench_function(name, |bb| {
        bb.iter(|| black_box(fl(black_box(inp[0].0), black_box(inp[0].1))))
    });
}

fn bench(c: &mut Criterion) {
    // typical: small quotient (1-50 reduction steps)
    let typical: Vec<(f64, f64)> = (0..64)
        .map(|k| (3.0 + k as f64 * 1.7, 0.7 + (k % 5) as f64 * 0.3))
        .collect();
    // stress: huge x, small y → long bit-loop reduction
    let stress: Vec<(f64, f64)> = (0..64)
        .map(|k| (1.0e9 + k as f64 * 1.3e7, 1.0 + (k % 7) as f64 * 0.11))
        .collect();

    let mut g = c.benchmark_group("fmod_survey");
    g.sample_size(10);
    survey(
        &mut g,
        "fmod_typical",
        &typical,
        |x, y| math::fmod(x, y),
        |x, y| unsafe { h_fmod(x, y) },
    );
    survey(
        &mut g,
        "fmod_stress",
        &stress,
        |x, y| math::fmod(x, y),
        |x, y| unsafe { h_fmod(x, y) },
    );
    survey(
        &mut g,
        "remainder_typical",
        &typical,
        |x, y| math::remainder(x, y),
        |x, y| unsafe { h_remainder(x, y) },
    );
    survey(
        &mut g,
        "remainder_stress",
        &stress,
        |x, y| math::remainder(x, y),
        |x, y| unsafe { h_remainder(x, y) },
    );
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
