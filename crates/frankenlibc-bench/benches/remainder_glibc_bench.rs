//! f64 `remainder` candidate: deployed (libm = remquo-based, tracks quotient bits) vs
//! fdlibm fmod-based remainder using fl's FAST `fmod` vs host glibc (cc/BoldFalcon).
//! remainder is EXACT/uniquely-defined → the candidate must be BIT-IDENTICAL to glibc
//! (verified densely below) and is then a pure speed win, no accuracy trade.
//! No `abi-bench` → bare `extern remainder/fmod` = host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench remainder_glibc_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "remainder"]
    fn h_remainder(x: f64, y: f64) -> f64;
}

/// fdlibm `__ieee754_remainder`, fmod-based, using fl's fast `math::fmod`.
#[inline]
fn candidate(x: f64, p: f64) -> f64 {
    let xbits = x.to_bits();
    let pbits = p.to_bits();
    let sx = xbits & 0x8000_0000_0000_0000;
    let axb = xbits & 0x7fff_ffff_ffff_ffff; // |x| bits
    let apb = pbits & 0x7fff_ffff_ffff_ffff; // |p| bits
    // p == 0, or x non-finite, or p NaN  -> NaN (with the right flag)
    if apb == 0 || axb >= 0x7ff0_0000_0000_0000 || apb > 0x7ff0_0000_0000_0000 {
        return (x * p) / (x * p);
    }
    let ap = f64::from_bits(apb);
    let mut xv = x;
    // reduce x mod 2|p| when p+p cannot overflow (p exponent below max)
    if apb <= 0x7fdf_ffff_ffff_ffff {
        xv = math::fmod(xv, ap + ap);
    }
    // |x| == |p| exactly -> signed zero
    if axb == apb {
        return 0.0 * xv;
    }
    let mut xa = xv.abs();
    if apb < 0x0020_0000_0000_0000 {
        if xa + xa > ap {
            xa -= ap;
            if xa + xa >= ap {
                xa -= ap;
            }
        }
    } else {
        let p_half = 0.5 * ap;
        if xa > p_half {
            xa -= ap;
            if xa >= p_half {
                xa -= ap;
            }
        }
    }
    f64::from_bits(xa.to_bits() ^ sx)
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
    inp: &[(f64, f64)],
    f: impl Fn(f64, f64) -> f64,
) {
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
    println!("REMAINDER_BENCH impl={name} p50_ns_op={:.4}", p50(&mut s));
    g.bench_function(name, |b| {
        b.iter(|| black_box(f(black_box(inp[0].0), black_box(inp[0].1))))
    });
}

fn bench(c: &mut Criterion) {
    // DENSE bit-exact verification vs glibc, including ties / signs / subnormal y /
    // |x|==|y| / large&small / multiples.
    let mut s = 0x1234_5678_9abc_def1u64;
    let mut rng = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let edge: Vec<(f64, f64)> = vec![
        (1.5, 1.0),
        (2.5, 1.0),
        (-1.5, 1.0),
        (1.5, -1.0),
        (0.5, 1.0),
        (3.0, 1.0),
        (1.0, 1.0),
        (-1.0, 1.0),
        (5.0e-324, 1.0e-323),
        (1.0e300, 3.0),
        (7.0, 7.0),
        (0.0, 1.0),
        (-0.0, 1.0),
        (123456.789, 0.1),
        (1.0, 3.0),
        (2.0, 2.0),
    ];
    let mut mism = 0u64;
    let mut first = String::new();
    let mut check = |x: f64, y: f64| {
        let (cb, gb) = (
            candidate(x, y).to_bits(),
            unsafe { h_remainder(x, y) }.to_bits(),
        );
        if cb != gb {
            // both-NaN is fine
            let cn = candidate(x, y).is_nan() && unsafe { h_remainder(x, y) }.is_nan();
            if !cn {
                mism += 1;
                if first.is_empty() {
                    first = format!(
                        "remainder({x:e},{y:e}): cand={:#018x} glibc={:#018x}",
                        cb, gb
                    );
                }
            }
        }
    };
    for &(x, y) in &edge {
        check(x, y);
    }
    for _ in 0..2_000_000u32 {
        let x = f64::from_bits(rng());
        let y = f64::from_bits(rng());
        if x.is_finite() && y.is_finite() && y != 0.0 {
            check(x, y);
        }
    }
    eprintln!("remainder candidate bit-exact mismatches vs glibc = {mism} {first}");
    assert_eq!(mism, 0, "remainder candidate not bit-identical to glibc");

    let typical: Vec<(f64, f64)> = (0..64)
        .map(|k| (3.0 + k as f64 * 1.7, 0.7 + (k % 5) as f64 * 0.3))
        .collect();
    let stress: Vec<(f64, f64)> = (0..64)
        .map(|k| (1.0e9 + k as f64 * 1.3e7, 1.0 + (k % 7) as f64 * 0.11))
        .collect();
    let mut g = c.benchmark_group("remainder");
    g.sample_size(10);
    run(&mut g, "fl_deployed_typical", &typical, |x, y| {
        math::remainder(x, y)
    });
    run(&mut g, "candidate_typical", &typical, candidate);
    run(&mut g, "glibc_typical", &typical, |x, y| unsafe {
        h_remainder(x, y)
    });
    run(&mut g, "fl_deployed_stress", &stress, |x, y| {
        math::remainder(x, y)
    });
    run(&mut g, "candidate_stress", &stress, candidate);
    run(&mut g, "glibc_stress", &stress, |x, y| unsafe {
        h_remainder(x, y)
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
