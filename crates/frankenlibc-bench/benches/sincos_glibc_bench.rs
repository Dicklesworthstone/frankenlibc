//! Head-to-head `sincos` benchmark: frankenlibc_core vs host glibc (cc/BoldFalcon).
//!
//! fl's `sin`/`cos` beat glibc in the mid-range magnitude band [1.647e6, 1e15] via a
//! fast 3-FMA pi/2 reduction (see trig.rs), but `sincos` was still plain
//! `libm::sincos` (slow Payne-Hanek `rem_pio2`). This validates the fused
//! `sincos_band` lever: ONE fast reduction for both outputs, bit-identical to
//! `(sin(x), cos(x))`.
//!
//! No `abi-bench` feature -> the bench links NO fl ABI symbols, so the bare
//! `extern "C" sincos` resolves to the host glibc directly (no interposition).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench sincos_glibc_bench`

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};

unsafe extern "C" {
    fn sincos(x: f64, s: *mut f64, c: *mut f64);
}

#[inline]
fn host_sincos(x: f64) -> (f64, f64) {
    let mut s = 0.0f64;
    let mut c = 0.0f64;
    unsafe { sincos(x, &mut s, &mut c) };
    (s, c)
}

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

// Deterministic mid-range args inside the fast band [1.647e6, 1e15].
fn band_args() -> Vec<f64> {
    let mut v = Vec::with_capacity(64);
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..64 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        // map to [2e6, 9e14]
        let frac = (s >> 11) as f64 / (1u64 << 53) as f64;
        v.push(2.0e6 + frac * (9.0e14 - 2.0e6));
    }
    v
}

fn bench(c: &mut Criterion) {
    let args = band_args();

    // Conformance gate 1: fused sincos is bit-identical to (sin, cos).
    for &x in &args {
        let (s, co) = frankenlibc_core::math::sincos(x);
        assert_eq!(
            s.to_bits(),
            frankenlibc_core::math::sin(x).to_bits(),
            "sincos.0 != sin at x={x}"
        );
        assert_eq!(
            co.to_bits(),
            frankenlibc_core::math::cos(x).to_bits(),
            "sincos.1 != cos at x={x}"
        );
    }
    // Conformance gate 2: <=2 ULP vs host glibc across the band (matches the sin/cos
    // contract). ULP-vs-live-glibc varies by worker; assert on the gate worker.
    let mut worst = 0u64;
    let mut worst_x = 0.0f64;
    for i in 0..20000u32 {
        let x = 2.0e6 + (i as f64) * ((9.0e14 - 2.0e6) / 20000.0);
        let (fs, fc) = frankenlibc_core::math::sincos(x);
        let (gs, gc) = host_sincos(x);
        let u = ulps(fs, gs).max(ulps(fc, gc));
        if u > worst {
            worst = u;
            worst_x = x;
        }
    }
    eprintln!("sincos band fl-vs-glibc worst ULP = {worst} at x={worst_x}");
    assert!(worst <= 2, "sincos band exceeds 2 ULP vs glibc (worst {worst} at x={worst_x})");

    let mut g = c.benchmark_group("sincos_band");
    g.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut acc = 0.0f64;
            for &x in &args {
                let (s, co) = frankenlibc_core::math::sincos(black_box(x));
                acc += black_box(s) + black_box(co);
            }
            black_box(acc)
        })
    });
    g.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut acc = 0.0f64;
            for &x in &args {
                let (s, co) = host_sincos(black_box(x));
                acc += black_box(s) + black_box(co);
            }
            black_box(acc)
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
