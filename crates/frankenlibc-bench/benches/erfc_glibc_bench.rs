//! In-process A/B: fl `erfc`/`erf` vs REAL in-process glibc (no abi-bench → extern
//! resolves to host glibc). Documents the measured erfc gap (fl's libm/fdlibm path
//! vs glibc's faster erfc) as a baseline for a future ARM-optimized-routines port.
//!
//! NOTE (disproof, see NEGATIVE_EVIDENCE.md): widening the gated Cephes-rational
//! `exp(-x²)·P/Q` path from the benched 1/32 grid to the full [1,2.5) interval —
//! even with an fma `x*x`-rounding correction — lands right at 4 ULP and
//! INTERMITTENTLY exceeds it against the fleet's varying host glibc (2.42 vs
//! others). The dense sweep below is REPORT-ONLY (worst ULP) for that reason; the
//! deployed erfc keeps libm for non-grid args.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench erfc_glibc_bench`
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

unsafe extern "C" {
    fn erfc(x: f64) -> f64;
    fn erf(x: f64) -> f64;
}

const ARGS: &[f64] = &[0.3, 0.7, 1.3, 2.1, 2.7, 3.5, 5.0];

fn ulps(a: f64, b: f64) -> u64 {
    if a == b {
        return 0;
    }
    let (ia, ib) = (a.to_bits() as i64, b.to_bits() as i64);
    if (ia < 0) != (ib < 0) {
        return u64::MAX;
    }
    (ia - ib).unsigned_abs()
}

fn bench(c: &mut Criterion) {
    // Report-only ULP sweep over [1, 2.5) vs the live host glibc (varies by worker).
    let mut worst = 0u64;
    for k in 0..500u32 {
        let x = 1.0 + (k as f64) * (1.5 / 500.0);
        if x >= 2.5 {
            break;
        }
        worst = worst.max(ulps(frankenlibc_core::math::erfc(x), unsafe { erfc(x) }));
    }
    eprintln!("erfc [1,2.5) deployed-vs-glibc worst ULP = {worst}");

    let mut ge = c.benchmark_group("erfc");
    ge.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut s = 0.0;
            for &x in ARGS {
                s += black_box(frankenlibc_core::math::erfc(black_box(x)));
            }
            black_box(s)
        })
    });
    ge.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut s = 0.0;
            for &x in ARGS {
                s += black_box(unsafe { erfc(black_box(x)) });
            }
            black_box(s)
        })
    });
    ge.finish();
    let mut gf = c.benchmark_group("erf");
    gf.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut s = 0.0;
            for &x in ARGS {
                s += black_box(frankenlibc_core::math::erf(black_box(x)));
            }
            black_box(s)
        })
    });
    gf.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut s = 0.0;
            for &x in ARGS {
                s += black_box(unsafe { erf(black_box(x)) });
            }
            black_box(s)
        })
    });
    gf.finish();
}
criterion_group!(benches, bench);
criterion_main!(benches);
