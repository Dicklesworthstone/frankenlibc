//! Reliable same-process survey: deployed fl f64 transcendental passthroughs vs host
//! glibc (cc/BoldFalcon). Applies the refined reuse-lever filter — only functions
//! where the deployed fl path is slower than glibc are worth a composition lever; the
//! rest are confirmed fine. No `abi-bench` → bare `extern "C"` resolves to host glibc.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench math_passthrough_survey_bench`

use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::math;
use std::hint::black_box;

unsafe extern "C" {
    #[link_name = "asin"]
    fn h_asin(x: f64) -> f64;
    #[link_name = "acos"]
    fn h_acos(x: f64) -> f64;
    #[link_name = "atan"]
    fn h_atan(x: f64) -> f64;
    #[link_name = "asinh"]
    fn h_asinh(x: f64) -> f64;
    #[link_name = "acosh"]
    fn h_acosh(x: f64) -> f64;
    #[link_name = "atanh"]
    fn h_atanh(x: f64) -> f64;
    #[link_name = "expm1"]
    fn h_expm1(x: f64) -> f64;
    #[link_name = "log1p"]
    fn h_log1p(x: f64) -> f64;
    #[link_name = "j0"]
    fn h_j0(x: f64) -> f64;
    #[link_name = "y0"]
    fn h_y0(x: f64) -> f64;
    #[link_name = "atan2"]
    fn h_atan2(y: f64, x: f64) -> f64;
    #[link_name = "hypot"]
    fn h_hypot(x: f64, y: f64) -> f64;
    #[link_name = "sin"]
    fn h_sin(x: f64) -> f64;
    #[link_name = "cos"]
    fn h_cos(x: f64) -> f64;
    #[link_name = "tan"]
    fn h_tan(x: f64) -> f64;
    #[link_name = "cbrt"]
    fn h_cbrt(x: f64) -> f64;
    #[link_name = "sinh"]
    fn h_sinh(x: f64) -> f64;
    #[link_name = "cosh"]
    fn h_cosh(x: f64) -> f64;
    #[link_name = "tanh"]
    fn h_tanh(x: f64) -> f64;
    #[link_name = "exp"]
    fn h_exp(x: f64) -> f64;
    #[link_name = "log"]
    fn h_log(x: f64) -> f64;
    #[link_name = "pow"]
    fn h_pow(x: f64, y: f64) -> f64;
    #[link_name = "erf"]
    fn h_erf(x: f64) -> f64;
    #[link_name = "erfc"]
    fn h_erfc(x: f64) -> f64;
    #[link_name = "tgamma"]
    fn h_tgamma(x: f64) -> f64;
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

fn timeit<F: Fn() -> f64>(f: F) -> f64 {
    // one batch's per-... wrapper-agnostic: returns ns for one f() call-set call.
    let start = Instant::now();
    black_box(f());
    start.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64
}

fn survey_unary(
    g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    inputs: &[f64],
    fl: impl Fn(f64) -> f64,
    gl: impl Fn(f64) -> f64,
) {
    let run = |label: &str, f: &dyn Fn(f64) -> f64| -> f64 {
        let mut samples = Vec::new();
        let bench_one = || {
            let mut acc = 0.0;
            for &x in inputs {
                acc += f(black_box(x));
            }
            acc
        };
        // warmup
        for _ in 0..50 {
            black_box(bench_one());
        }
        for _ in 0..200 {
            samples.push(timeit(&bench_one) / inputs.len() as f64);
        }
        let v = p50(&mut samples);
        let _ = label;
        v
    };
    let fl_ns = run("fl", &fl);
    let gl_ns = run("glibc", &gl);
    let ratio = fl_ns / gl_ns;
    let flag = if ratio > 1.30 {
        "  <-- LIBM-SLOW: lever candidate"
    } else {
        ""
    };
    println!(
        "MATH_SURVEY {name:10} fl_p50={fl_ns:7.3} glibc_p50={gl_ns:7.3} ratio={ratio:.3}{flag}"
    );
    // keep criterion happy with a token measurement
    g.bench_function(name, |b| b.iter(|| black_box(fl(black_box(inputs[0])))));
}

fn bench(c: &mut Criterion) {
    let unit: Vec<f64> = (0..64).map(|k| -0.98 + k as f64 * (1.96 / 64.0)).collect(); // (-1,1)
    let pos1: Vec<f64> = (0..64).map(|k| 1.01 + k as f64 * 0.5).collect(); // >1 (acosh)
    let any: Vec<f64> = (0..64).map(|k| -20.0 + k as f64 * 0.625).collect();
    let small: Vec<f64> = (0..64).map(|k| -0.5 + k as f64 * (1.0 / 64.0)).collect();
    let gtm1: Vec<f64> = (0..64).map(|k| -0.5 + k as f64 * 0.5).collect(); // >-1 (log1p)
    let posb: Vec<f64> = (0..64).map(|k| 0.5 + k as f64 * 0.5).collect(); // bessel

    let mut g = c.benchmark_group("math_survey");
    g.sample_size(10);
    survey_unary(
        &mut g,
        "asin",
        &unit,
        |x| math::asin(x),
        |x| unsafe { h_asin(x) },
    );
    survey_unary(
        &mut g,
        "acos",
        &unit,
        |x| math::acos(x),
        |x| unsafe { h_acos(x) },
    );
    survey_unary(
        &mut g,
        "atan",
        &any,
        |x| math::atan(x),
        |x| unsafe { h_atan(x) },
    );
    survey_unary(
        &mut g,
        "asinh",
        &any,
        |x| math::asinh(x),
        |x| unsafe { h_asinh(x) },
    );
    survey_unary(
        &mut g,
        "acosh",
        &pos1,
        |x| math::acosh(x),
        |x| unsafe { h_acosh(x) },
    );
    survey_unary(
        &mut g,
        "atanh",
        &unit,
        |x| math::atanh(x),
        |x| unsafe { h_atanh(x) },
    );
    survey_unary(
        &mut g,
        "expm1",
        &small,
        |x| math::expm1(x),
        |x| unsafe { h_expm1(x) },
    );
    survey_unary(
        &mut g,
        "log1p",
        &gtm1,
        |x| math::log1p(x),
        |x| unsafe { h_log1p(x) },
    );
    survey_unary(&mut g, "j0", &posb, |x| math::j0(x), |x| unsafe { h_j0(x) });
    survey_unary(&mut g, "y0", &posb, |x| math::y0(x), |x| unsafe { h_y0(x) });
    survey_unary(
        &mut g,
        "atan2",
        &any,
        |x| math::atan2(x, 1.7),
        |x| unsafe { h_atan2(x, 1.7) },
    );
    survey_unary(
        &mut g,
        "hypot",
        &any,
        |x| math::hypot(x, 1.7),
        |x| unsafe { h_hypot(x, 1.7) },
    );
    survey_unary(
        &mut g,
        "sin",
        &any,
        |x| math::sin(x),
        |x| unsafe { h_sin(x) },
    );
    survey_unary(
        &mut g,
        "cos",
        &any,
        |x| math::cos(x),
        |x| unsafe { h_cos(x) },
    );
    survey_unary(
        &mut g,
        "tan",
        &any,
        |x| math::tan(x),
        |x| unsafe { h_tan(x) },
    );
    // ORIG arm (same-run, same worker): the pre-lever `libm::tan` the deployed `math::tan`
    // replaced on the [π/4, TRIG_RED_MAX] band. Compare `tan` (CAND) vs `tan_orig` (ORIG)
    // within ONE run — both are Rust so the ratio is worker-frequency-stable, unlike the
    // fl-vs-glibc ratio which swings across workers.
    survey_unary(
        &mut g,
        "tan_orig",
        &any,
        |x| libm::tan(x),
        |x| unsafe { h_tan(x) },
    );
    // ORIG arms for the sin/cos FMA-reduction lever (pre-lever `libm::sin`/`libm::cos`).
    survey_unary(
        &mut g,
        "sin_orig",
        &any,
        |x| libm::sin(x),
        |x| unsafe { h_sin(x) },
    );
    survey_unary(
        &mut g,
        "cos_orig",
        &any,
        |x| libm::cos(x),
        |x| unsafe { h_cos(x) },
    );
    // f64 exp/log/pow — the most common transcendentals, not previously surveyed vs glibc 2.42.
    survey_unary(
        &mut g,
        "exp",
        &any,
        |x| math::exp(x),
        |x| unsafe { h_exp(x) },
    );
    survey_unary(
        &mut g,
        "log",
        &pos1,
        |x| math::log(x),
        |x| unsafe { h_log(x) },
    );
    survey_unary(
        &mut g,
        "pow",
        &posb,
        |x| math::pow(x, 1.7),
        |x| unsafe { h_pow(x, 1.7) },
    );
    survey_unary(
        &mut g,
        "cbrt",
        &any,
        |x| math::cbrt(x),
        |x| unsafe { h_cbrt(x) },
    );
    survey_unary(
        &mut g,
        "sinh",
        &small,
        |x| math::sinh(x),
        |x| unsafe { h_sinh(x) },
    );
    survey_unary(
        &mut g,
        "cosh",
        &small,
        |x| math::cosh(x),
        |x| unsafe { h_cosh(x) },
    );
    survey_unary(
        &mut g,
        "tanh",
        &any,
        |x| math::tanh(x),
        |x| unsafe { h_tanh(x) },
    );
    survey_unary(
        &mut g,
        "erf",
        &any,
        |x| math::erf(x),
        |x| unsafe { h_erf(x) },
    );
    let negwide: Vec<f64> = (0..64).map(|k| -20.0 + k as f64 * 0.3125).collect();
    survey_unary(
        &mut g,
        "erfc",
        &negwide,
        |x| math::erfc(x),
        |x| unsafe { h_erfc(x) },
    );
    survey_unary(
        &mut g,
        "tgamma",
        &pos1,
        |x| math::tgamma(x),
        |x| unsafe { h_tgamma(x) },
    );
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
