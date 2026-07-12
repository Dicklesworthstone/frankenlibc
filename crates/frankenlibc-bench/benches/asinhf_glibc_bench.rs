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
    // Corrected deployed form: fast f32 logf only on [1,1e19) (no cancellation AND no
    // f32 x² overflow); f64 cancellation-free log1p identity elsewhere (small-|x|, where
    // the bare log(|x|+sqrt(x²+1)) form lost ~1024 ULP; large-|x| overflow; ±0). inf/nan
    // short-circuited. Matches frankenlibc_core::math::asinhf.
    let ax = x.abs();
    if !ax.is_finite() {
        return x + x;
    }
    let r = if (1.0..1.0e19).contains(&ax) {
        math::logf(ax + (ax * ax + 1.0).sqrt())
    } else {
        let a = (x as f64).abs();
        math::log1p(a + a * a / (1.0 + (a * a + 1.0).sqrt())) as f32
    };
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

fn run<F: Fn(f32) -> f32>(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    inp: &[f32],
    f: F,
) {
    let one = || {
        let mut a = 0.0f32;
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
    println!("ASINHF_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(inp[0])))));
}

fn bench(c: &mut Criterion) {
    // Dense ULP sweep over [-20,20] incl the small-|x| region.
    let mut worst = 0u64;
    let mut wx = 0.0f32;
    // FULL-RANGE sweep incl tiny, mid-fast-path, the 1e19 overflow boundary, and large x
    // (the old [-20,20]-only sweep MISSED the f32 x² overflow that the corrected branch
    // now handles via the f64 fallback). Log-spaced |x| in [1e-12, 1e30], both signs.
    for k in 0..60000u32 {
        let t = k as f64 / 60000.0;
        let mag = (10.0_f64.powf(-12.0 + t * 42.0)) as f32; // 1e-12 .. 1e30
        for x in [mag, -mag] {
            let cand = candidate(x);
            let g = unsafe { host_asinhf(x) };
            if cand.is_nan() && g.is_nan() {
                continue;
            }
            let u = ((cand.to_bits() as i64) - (g.to_bits() as i64)).unsigned_abs();
            if u > worst {
                worst = u;
                wx = x;
            }
        }
    }
    eprintln!("asinhf candidate vs glibc worst ULP over |x| in [1e-12,1e30] = {worst} at x={wx}");
    // special cases (exact)
    for &(x, _name) in &[
        (f32::INFINITY, "inf"),
        (f32::NEG_INFINITY, "-inf"),
        (0.0f32, "+0"),
        (-0.0f32, "-0"),
    ] {
        let (cand, g) = (candidate(x), unsafe { host_asinhf(x) });
        assert_eq!(
            cand.to_bits(),
            g.to_bits(),
            "asinhf special case x={x} cand={cand} glibc={g}"
        );
    }
    assert!(
        worst <= 2,
        "asinhf candidate exceeds 2 ULP vs glibc (worst {worst} at x={wx})"
    );

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
