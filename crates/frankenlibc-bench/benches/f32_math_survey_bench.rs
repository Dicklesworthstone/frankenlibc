//! Reliable same-process survey: deployed fl f32 transcendental passthroughs vs host
//! glibc (cc/BoldFalcon). Sibling of math_passthrough_survey_bench (f64). Applies the
//! refined reuse-lever filter — flag only functions where the deployed fl path is
//! >1.30x slower than glibc (candidate for an f64-widen / fast-primitive lever like
//! tgammaf). No `abi-bench` → bare `extern "C"` resolves to host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench f32_math_survey_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "tanf"]
    fn h_tanf(x: f32) -> f32;
    #[link_name = "asinf"]
    fn h_asinf(x: f32) -> f32;
    #[link_name = "acosf"]
    fn h_acosf(x: f32) -> f32;
    #[link_name = "atanf"]
    fn h_atanf(x: f32) -> f32;
    #[link_name = "asinhf"]
    fn h_asinhf(x: f32) -> f32;
    #[link_name = "acoshf"]
    fn h_acoshf(x: f32) -> f32;
    #[link_name = "atanhf"]
    fn h_atanhf(x: f32) -> f32;
    #[link_name = "expm1f"]
    fn h_expm1f(x: f32) -> f32;
    #[link_name = "log1pf"]
    fn h_log1pf(x: f32) -> f32;
    #[link_name = "cbrtf"]
    fn h_cbrtf(x: f32) -> f32;
    #[link_name = "coshf"]
    fn h_coshf(x: f32) -> f32;
    #[link_name = "sinhf"]
    fn h_sinhf(x: f32) -> f32;
    #[link_name = "tanhf"]
    fn h_tanhf(x: f32) -> f32;
    #[link_name = "j0f"]
    fn h_j0f(x: f32) -> f32;
    #[link_name = "atan2f"]
    fn h_atan2f(y: f32, x: f32) -> f32;
    #[link_name = "hypotf"]
    fn h_hypotf(x: f32, y: f32) -> f32;
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
    inputs: &[f32],
    fl: impl Fn(f32) -> f32,
    gl: impl Fn(f32) -> f32,
) {
    let run = |f: &dyn Fn(f32) -> f32| -> f64 {
        let one = || {
            let mut acc = 0.0f32;
            for &x in inputs {
                acc += f(black_box(x));
            }
            acc
        };
        for _ in 0..50 {
            black_box(one());
        }
        let mut s = Vec::new();
        for _ in 0..200 {
            let t = Instant::now();
            black_box(one());
            s.push(
                t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / inputs.len() as f64,
            );
        }
        p50(&mut s)
    };
    let (a, b) = (run(&fl), run(&gl));
    let ratio = a / b;
    let flag = if ratio > 1.30 {
        "  <-- LIBM-SLOW: lever candidate"
    } else {
        ""
    };
    println!("F32_SURVEY {name:8} fl_p50={a:7.3} glibc_p50={b:7.3} ratio={ratio:.3}{flag}");
    g.bench_function(name, |bb| bb.iter(|| black_box(fl(black_box(inputs[0])))));
}

fn bench(c: &mut Criterion) {
    let unit: Vec<f32> = (0..64).map(|k| -0.98 + k as f32 * (1.96 / 64.0)).collect();
    let pos1: Vec<f32> = (0..64).map(|k| 1.01 + k as f32 * 0.5).collect();
    let any: Vec<f32> = (0..64).map(|k| -20.0 + k as f32 * 0.625).collect();
    let small: Vec<f32> = (0..64).map(|k| -0.5 + k as f32 * (1.0 / 64.0)).collect();
    let gtm1: Vec<f32> = (0..64).map(|k| -0.5 + k as f32 * 0.5).collect();
    let posb: Vec<f32> = (0..64).map(|k| 0.5 + k as f32 * 0.5).collect();
    let mid: Vec<f32> = (0..64).map(|k| 0.5 + k as f32 * 0.1).collect();

    let mut g = c.benchmark_group("f32_survey");
    g.sample_size(10);
    survey(
        &mut g,
        "tanf",
        &any,
        |x| math::tanf(x),
        |x| unsafe { h_tanf(x) },
    );
    survey(
        &mut g,
        "asinf",
        &unit,
        |x| math::asinf(x),
        |x| unsafe { h_asinf(x) },
    );
    survey(
        &mut g,
        "acosf",
        &unit,
        |x| math::acosf(x),
        |x| unsafe { h_acosf(x) },
    );
    survey(
        &mut g,
        "atanf",
        &any,
        |x| math::atanf(x),
        |x| unsafe { h_atanf(x) },
    );
    survey(
        &mut g,
        "asinhf",
        &any,
        |x| math::asinhf(x),
        |x| unsafe { h_asinhf(x) },
    );
    survey(
        &mut g,
        "acoshf",
        &pos1,
        |x| math::acoshf(x),
        |x| unsafe { h_acoshf(x) },
    );
    survey(
        &mut g,
        "atanhf",
        &unit,
        |x| math::atanhf(x),
        |x| unsafe { h_atanhf(x) },
    );
    survey(
        &mut g,
        "expm1f",
        &small,
        |x| math::expm1f(x),
        |x| unsafe { h_expm1f(x) },
    );
    survey(
        &mut g,
        "log1pf",
        &gtm1,
        |x| math::log1pf(x),
        |x| unsafe { h_log1pf(x) },
    );
    survey(
        &mut g,
        "cbrtf",
        &any,
        |x| math::cbrtf(x),
        |x| unsafe { h_cbrtf(x) },
    );
    survey(
        &mut g,
        "coshf",
        &mid,
        |x| math::coshf(x),
        |x| unsafe { h_coshf(x) },
    );
    survey(
        &mut g,
        "sinhf",
        &mid,
        |x| math::sinhf(x),
        |x| unsafe { h_sinhf(x) },
    );
    survey(
        &mut g,
        "tanhf",
        &mid,
        |x| math::tanhf(x),
        |x| unsafe { h_tanhf(x) },
    );
    survey(
        &mut g,
        "j0f",
        &posb,
        |x| math::j0f(x),
        |x| unsafe { h_j0f(x) },
    );
    survey(
        &mut g,
        "atan2f",
        &any,
        |x| math::atan2f(x, 1.7),
        |x| unsafe { h_atan2f(x, 1.7) },
    );
    survey(
        &mut g,
        "hypotf",
        &any,
        |x| math::hypotf(x, 1.7),
        |x| unsafe { h_hypotf(x, 1.7) },
    );
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
