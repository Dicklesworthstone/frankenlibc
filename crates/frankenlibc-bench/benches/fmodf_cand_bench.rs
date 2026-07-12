//! f32 `fmodf` candidate: deployed (libm::fmodf, ~1.43x slower than glibc typical) vs
//! `fmod(x as f64, y as f64) as f32` (reuses fl's FAST f64 fmod; bit-exact because a
//! fmod of f32-exact operands is itself f32-representable) vs host glibc.
//! Verified bit-identical densely, then a pure speed win. No `abi-bench`.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench fmodf_cand_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "fmodf"]
    fn h_fmodf(x: f32, y: f32) -> f32;
}

#[inline]
fn candidate(x: f32, y: f32) -> f32 {
    (math::fmod(x as f64, y as f64)) as f32
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

fn run(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    inp: &[(f32, f32)],
    f: impl Fn(f32, f32) -> f32,
) {
    let one = || {
        let mut a = 0.0f32;
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
    println!("FMODF_CAND impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| {
        b.iter(|| black_box(f(black_box(inp[0].0), black_box(inp[0].1))))
    });
}

fn bench(c: &mut Criterion) {
    // Dense bit-exact verify vs glibc fmodf (random f32 bit patterns + edges).
    let mut s = 0xdead_beef_1234_5678u64;
    let mut rng = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let edges: Vec<(f32, f32)> = vec![
        (5.3, 2.0),
        (-5.3, 2.0),
        (5.3, -2.0),
        (1.0, 1.0),
        (0.0, 1.0),
        (-0.0, 1.0),
        (f32::from_bits(1), f32::from_bits(3)),
        (1e30, 3.0),
        (0.1, 0.3),
        (7.0, 7.0),
        (2.5, 1.0),
    ];
    let mut mism = 0u64;
    let mut first = String::new();
    let mut check = |x: f32, y: f32| {
        let (cb, gb) = (
            candidate(x, y).to_bits(),
            unsafe { h_fmodf(x, y) }.to_bits(),
        );
        if cb != gb && !(candidate(x, y).is_nan() && unsafe { h_fmodf(x, y) }.is_nan()) {
            mism += 1;
            if first.is_empty() {
                first = format!("fmodf({x:e},{y:e}) cand={:#010x} glibc={:#010x}", cb, gb);
            }
        }
    };
    for &(x, y) in &edges {
        check(x, y);
    }
    for _ in 0..3_000_000u32 {
        let x = f32::from_bits(rng() as u32);
        let y = f32::from_bits((rng() >> 32) as u32);
        if x.is_finite() && y.is_finite() && y != 0.0 {
            check(x, y);
        }
    }
    eprintln!("fmodf candidate bit-exact mismatches vs glibc = {mism} {first}");
    assert_eq!(mism, 0, "fmodf candidate not bit-identical to glibc");

    let typical: Vec<(f32, f32)> = (0..64)
        .map(|k| (3.0 + k as f32 * 1.7, 0.7 + (k % 5) as f32 * 0.3))
        .collect();
    let stress: Vec<(f32, f32)> = (0..64)
        .map(|k| (1.0e7 + k as f32 * 1.3e5, 1.0 + (k % 7) as f32 * 0.11))
        .collect();
    let mut g = c.benchmark_group("fmodf_cand");
    g.sample_size(10);
    run(&mut g, "fl_deployed_typical", &typical, |x, y| {
        math::fmodf(x, y)
    });
    run(&mut g, "candidate_typical", &typical, candidate);
    run(&mut g, "glibc_typical", &typical, |x, y| unsafe {
        h_fmodf(x, y)
    });
    run(&mut g, "fl_deployed_stress", &stress, |x, y| {
        math::fmodf(x, y)
    });
    run(&mut g, "candidate_stress", &stress, candidate);
    run(&mut g, "glibc_stress", &stress, |x, y| unsafe {
        h_fmodf(x, y)
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
