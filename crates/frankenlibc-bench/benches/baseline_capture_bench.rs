//! Baseline performance capture for implemented symbol families (bd-3h1u.1).
//!
//! Captures p50/p95/p99 latencies for ctype, math, stdlib, and errno families.
//! Complements existing benches (string_bench, malloc_bench, stdio_bench,
//! mutex_bench, condvar_bench) to achieve coverage across all major families.

use std::cell::RefCell;
use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main, measurement::WallTime};

#[derive(Default)]
struct BenchStats {
    samples_ns_per_op: Vec<f64>,
    total_iters: u64,
    total_ns: u128,
}

impl BenchStats {
    fn record(&mut self, iters: u64, dur: Duration) {
        let ns = dur.as_nanos();
        self.total_iters = self.total_iters.saturating_add(iters);
        self.total_ns = self.total_ns.saturating_add(ns);
        self.samples_ns_per_op.push(ns as f64 / iters as f64);
    }

    fn report(&self, mode_label: &str, bench_label: &str, symbol: &str) {
        let mut samples = self.samples_ns_per_op.clone();
        if samples.is_empty() {
            return;
        }
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let p50 = percentile_sorted(&samples, 0.50);
        let p95 = percentile_sorted(&samples, 0.95);
        let p99 = percentile_sorted(&samples, 0.99);
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let throughput_ops_s = if self.total_ns == 0 {
            0.0
        } else {
            (self.total_iters as f64) / (self.total_ns as f64 / 1e9)
        };

        println!(
            "BASELINE_CAPTURE_BENCH mode={} bench={} symbol={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
            mode_label,
            bench_label,
            symbol,
            samples.len(),
            p50,
            p95,
            p99,
            mean,
            throughput_ops_s
        );
    }
}

fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    debug_assert!((0.0..=1.0).contains(&p));
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn mode_label() -> &'static str {
    match std::env::var("FRANKENLIBC_MODE").ok().as_deref() {
        Some("hardened") => "hardened",
        Some("strict") => "strict",
        _ => "raw",
    }
}

fn bench_symbol<F>(
    group: &mut criterion::BenchmarkGroup<'_, WallTime>,
    mode: &'static str,
    bench_label: &str,
    symbol: &str,
    mut op: F,
) where
    F: FnMut(),
{
    let stats = RefCell::new(BenchStats::default());
    group.bench_function(BenchmarkId::new(bench_label, mode), |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                op();
            }
            let dur = start.elapsed().max(Duration::from_nanos(1));
            stats.borrow_mut().record(iters, dur);
            dur
        });
    });
    stats.borrow().report(mode, bench_label, symbol);
}

#[inline]
fn abi_isalpha(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::isalpha(i32::from(c)) }
}

#[inline]
fn abi_isdigit(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::isdigit(i32::from(c)) }
}

#[inline]
fn abi_isspace(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::isspace(i32::from(c)) }
}

#[inline]
fn abi_toupper(c: u8) -> i32 {
    // SAFETY: ASCII byte values are valid inputs for the C ctype entrypoint.
    unsafe { frankenlibc_abi::ctype_abi::toupper(i32::from(c)) }
}

#[inline]
fn abi_atoi(input: &[u8]) -> i32 {
    // SAFETY: benchmark inputs are static NUL-terminated byte strings.
    unsafe { frankenlibc_abi::stdlib_abi::atoi(input.as_ptr().cast()) }
}

#[inline]
fn abi_errno_location() -> *mut i32 {
    // SAFETY: __errno_location returns the current thread's valid errno slot.
    unsafe { frankenlibc_abi::errno_abi::__errno_location() }
}

// ═══════════════════════════════════════════════════════════════════
// CTYPE FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_ctype_isalpha(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_isalpha");

    for _ in 0..10_000 {
        black_box(abi_isalpha(b'A'));
        black_box(abi_isalpha(b'5'));
    }

    bench_symbol(&mut group, mode, "isalpha_ascii_letter", "isalpha", || {
        black_box(abi_isalpha(black_box(b'A')));
    });
    bench_symbol(&mut group, mode, "isalpha_digit", "isalpha", || {
        black_box(abi_isalpha(black_box(b'5')));
    });

    group.finish();
}

fn bench_ctype_isdigit(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_isdigit");

    for _ in 0..10_000 {
        black_box(abi_isdigit(b'7'));
        black_box(abi_isdigit(b'z'));
    }

    bench_symbol(&mut group, mode, "isdigit_digit", "isdigit", || {
        black_box(abi_isdigit(black_box(b'7')));
    });
    bench_symbol(&mut group, mode, "isdigit_letter", "isdigit", || {
        black_box(abi_isdigit(black_box(b'z')));
    });

    group.finish();
}

fn bench_ctype_toupper(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_toupper");

    for _ in 0..10_000 {
        black_box(abi_toupper(b'a'));
        black_box(abi_toupper(b'A'));
    }

    bench_symbol(&mut group, mode, "toupper_lowercase", "toupper", || {
        black_box(abi_toupper(black_box(b'a')));
    });
    bench_symbol(&mut group, mode, "toupper_already_upper", "toupper", || {
        black_box(abi_toupper(black_box(b'A')));
    });

    group.finish();
}

fn bench_ctype_isspace(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("ctype_isspace");

    for _ in 0..10_000 {
        black_box(abi_isspace(b' '));
        black_box(abi_isspace(b'x'));
    }

    bench_symbol(&mut group, mode, "isspace_space", "isspace", || {
        black_box(abi_isspace(black_box(b' ')));
    });
    bench_symbol(&mut group, mode, "isspace_non_space", "isspace", || {
        black_box(abi_isspace(black_box(b'x')));
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// MATH FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_math_trig(c: &mut Criterion) {
    use frankenlibc_core::math::{cos, sin, tan};

    c.bench_function("math/sin/small", |b| {
        b.iter(|| black_box(sin(black_box(0.5))))
    });

    c.bench_function("math/cos/small", |b| {
        b.iter(|| black_box(cos(black_box(0.5))))
    });

    c.bench_function("math/tan/small", |b| {
        b.iter(|| black_box(tan(black_box(0.5))))
    });
}

fn bench_math_exp_log(c: &mut Criterion) {
    use frankenlibc_core::math::{exp, log};

    c.bench_function("math/exp/small", |b| {
        b.iter(|| black_box(exp(black_box(1.5))))
    });

    c.bench_function("math/log/small", |b| {
        b.iter(|| black_box(log(black_box(2.5))))
    });
}

fn bench_math_sqrt(c: &mut Criterion) {
    use frankenlibc_core::math::sqrt;

    c.bench_function("math/sqrt/integer", |b| {
        b.iter(|| black_box(sqrt(black_box(144.0))))
    });

    c.bench_function("math/sqrt/large", |b| {
        b.iter(|| black_box(sqrt(black_box(1e12))))
    });
}

fn bench_math_pow(c: &mut Criterion) {
    use frankenlibc_core::math::pow;

    c.bench_function("math/pow/integer_exp", |b| {
        b.iter(|| black_box(pow(black_box(2.0), black_box(10.0))))
    });

    c.bench_function("math/pow/fractional_exp", |b| {
        b.iter(|| black_box(pow(black_box(2.0), black_box(0.5))))
    });
}

// ═══════════════════════════════════════════════════════════════════
// STDLIB FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_stdlib_atoi(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("stdlib_atoi");

    for _ in 0..10_000 {
        black_box(abi_atoi(b"42\0"));
        black_box(abi_atoi(b"2147483647\0"));
        black_box(abi_atoi(b"-999\0"));
    }

    bench_symbol(&mut group, mode, "atoi_small", "atoi", || {
        black_box(abi_atoi(black_box(b"42\0")));
    });
    bench_symbol(&mut group, mode, "atoi_large", "atoi", || {
        black_box(abi_atoi(black_box(b"2147483647\0")));
    });
    bench_symbol(&mut group, mode, "atoi_negative", "atoi", || {
        black_box(abi_atoi(black_box(b"-999\0")));
    });

    group.finish();
}

fn bench_stdlib_abs(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("stdlib_abs");

    for _ in 0..10_000 {
        black_box(frankenlibc_abi::stdlib_abi::abs(42));
        black_box(frankenlibc_abi::stdlib_abi::abs(-42));
    }

    bench_symbol(&mut group, mode, "abs_positive", "abs", || {
        black_box(frankenlibc_abi::stdlib_abi::abs(black_box(42)));
    });
    bench_symbol(&mut group, mode, "abs_negative", "abs", || {
        black_box(frankenlibc_abi::stdlib_abi::abs(black_box(-42)));
    });

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// ERRNO FAMILY BENCHMARKS
// ═══════════════════════════════════════════════════════════════════

fn bench_errno_location(c: &mut Criterion) {
    let mode = mode_label();
    let mut group = c.benchmark_group("errno_location");

    // SAFETY: returned pointer is valid for the current thread.
    unsafe { *abi_errno_location() = 0 };
    for _ in 0..10_000 {
        black_box(abi_errno_location());
    }

    bench_symbol(
        &mut group,
        mode,
        "errno_location",
        "__errno_location",
        || {
            black_box(abi_errno_location());
        },
    );

    group.finish();
}

// ═══════════════════════════════════════════════════════════════════
// STRING FAMILY — additional sizes not in string_bench.rs
// ═══════════════════════════════════════════════════════════════════

fn bench_strlen_varied(c: &mut Criterion) {
    use frankenlibc_core::string::strlen;

    for len in [1, 8, 32, 128, 512] {
        let mut s = vec![b'x'; len];
        s.push(0);
        let label = format!("string/strlen/{len}");
        c.bench_function(&label, |b| {
            b.iter(|| black_box(strlen(black_box(s.as_slice()))))
        });
    }
}

fn bench_strcmp_varied(c: &mut Criterion) {
    use frankenlibc_core::string::strcmp;

    for len in [4, 32, 256] {
        let mut a = vec![b'a'; len];
        a.push(0);
        let b_equal = a.clone();
        let label_eq = format!("string/strcmp/equal_{len}");
        c.bench_function(&label_eq, |bench| {
            bench.iter(|| {
                black_box(strcmp(
                    black_box(a.as_slice()),
                    black_box(b_equal.as_slice()),
                ))
            })
        });

        // Differ at last byte
        let mut b_diff = a.clone();
        b_diff[len - 1] = b'b';
        let label_diff = format!("string/strcmp/differ_last_{len}");
        c.bench_function(&label_diff, |bench| {
            bench.iter(|| {
                black_box(strcmp(
                    black_box(a.as_slice()),
                    black_box(b_diff.as_slice()),
                ))
            })
        });
    }
}

criterion_group!(
    name = ctype_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_ctype_isalpha, bench_ctype_isdigit, bench_ctype_toupper, bench_ctype_isspace
);

criterion_group!(
    name = math_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_math_trig, bench_math_exp_log, bench_math_sqrt, bench_math_pow
);

criterion_group!(
    name = stdlib_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_stdlib_atoi, bench_stdlib_abs
);

criterion_group!(
    name = errno_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_errno_location
);

criterion_group!(
    name = string_extended_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_millis(500))
        .sample_size(50);
    targets = bench_strlen_varied, bench_strcmp_varied
);

criterion_main!(
    ctype_benches,
    math_benches,
    stdlib_benches,
    errno_benches,
    string_extended_benches,
);
