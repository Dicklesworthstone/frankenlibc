//! String function benchmarks.

use std::cell::RefCell;
use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::string::{
    bcmp, memccpy, memchr, memcmp, memcpy, memmem, strcasecmp, strcasestr, strchr, strchrnul,
    strcmp, strcspn, strlen, strncasecmp, strncmp, strnstr, strpbrk, strrchr, strsep, strspn,
    strstr, wcscasecmp, wcschr, wcscmp, wcslen, wcsncasecmp, wcsncmp, wcsnlen, wcsrchr, wcsspn,
    wcsstr, wmemchr, wmemcmp, wmemrchr,
};

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

    fn report(&self, mode_label: &str, bench_label: &str) {
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
            "STRING_BENCH mode={} bench={} samples={} p50_ns_op={:.3} p95_ns_op={:.3} p99_ns_op={:.3} mean_ns_op={:.3} throughput_ops_s={:.3}",
            mode_label,
            bench_label,
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

fn bench_memcpy_sizes(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096, 65536];
    let mode = mode_label();
    let mut group = c.benchmark_group("memcpy");

    for &size in sizes {
        let src = vec![0xABu8; size];
        let mut dst = vec![0u8; size];
        let bench_label = format!("memcpy_{size}");
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(memcpy(&mut dst, &src, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(memcpy(&mut dst, &src, sz));
                    black_box(dst[0]);
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strlen(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strlen");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strlen_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strlen(&s));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strlen(&s));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_memcmp_sizes(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("memcmp");

    for &size in sizes {
        let left = vec![0x5Au8; size];
        let right = vec![0x5Au8; size];
        let bench_label = format!("memcmp_{size}");
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(memcmp(&left, &right, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(memcmp(&left, &right, sz));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strcmp(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strcmp");

    for &size in sizes {
        let mut left = vec![b'Q'; size];
        let mut right = vec![b'Q'; size];
        let bench_label = format!("strcmp_{size}");
        left.push(0);
        right.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strcmp(&left, &right));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strcmp(&left, &right));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strncmp(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strncmp");

    for &size in sizes {
        let mut left = vec![b'Q'; size];
        let mut right = vec![b'Q'; size];
        let bench_label = format!("strncmp_{size}");
        left.push(0);
        right.push(0);
        let n = size;
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strncmp(&left, &right, n));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strncmp(&left, &right, n));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

// Inline scalar reference (the pre-SIMD strncasecmp body) for an in-run
// before/after ratio against the SIMD implementation.
fn scalar_ref_strncasecmp(s1: &[u8], s2: &[u8], n: usize) -> i32 {
    for i in 0..n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();
        if la != lb {
            return (la as i32) - (lb as i32);
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

fn bench_strncasecmp_equal(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strncasecmp_equal");

    for &size in sizes {
        // Case-flipped equal strings (fold-equal, raw-differ): 'A' vs 'a'.
        let mut left = vec![b'A'; size];
        let mut right = vec![b'a'; size];
        left.push(0);
        right.push(0);
        let n = size;
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strncasecmp(&left, &right, n));
            black_box(strcasecmp(&left, &right));
        }

        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/simd"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(strncasecmp(&left, &right, n));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    simd_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        simd_stats
            .borrow()
            .report(mode, &format!("strncasecmp_simd_{size}"));

        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/scalar"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(scalar_ref_strncasecmp(&left, &right, n));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    scalar_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        scalar_stats
            .borrow()
            .report(mode, &format!("strncasecmp_scalar_{size}"));
    }
    group.finish();
}

// Inline scalar reference (the pre-SIMD memccpy body) for an in-run ratio.
fn scalar_ref_memccpy(dest: &mut [u8], src: &[u8], c: u8, n: usize) -> Option<usize> {
    let count = n.min(dest.len()).min(src.len());
    for i in 0..count {
        dest[i] = src[i];
        if src[i] == c {
            return Some(i + 1);
        }
    }
    None
}

// Inline scalar reference (the pre-SIMD bcmp body) for an in-run ratio.
fn scalar_ref_bcmp(a: &[u8], b: &[u8], n: usize) -> i32 {
    let count = n.min(a.len()).min(b.len());
    let mut i = 0usize;
    while i < count {
        if a[i] != b[i] {
            return 1;
        }
        i += 1;
    }
    0
}

fn bench_bcmp_equal(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("bcmp_equal");

    for &size in sizes {
        // Equal buffers: full scan, the worst case for the scalar byte loop.
        let a = vec![0x5Au8; size];
        let b = vec![0x5Au8; size];
        group.throughput(Throughput::Bytes(size as u64));

        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/simd"), size),
            &size,
            |bb, _| {
                bb.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(bcmp(&a, &b, size));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    simd_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        simd_stats
            .borrow()
            .report(mode, &format!("bcmp_simd_{size}"));

        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/scalar"), size),
            &size,
            |bb, _| {
                bb.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(scalar_ref_bcmp(&a, &b, size));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    scalar_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        scalar_stats
            .borrow()
            .report(mode, &format!("bcmp_scalar_{size}"));
    }
    group.finish();
}

fn bench_memccpy_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("memccpy_absent");

    for &size in sizes {
        // Stop byte absent: the whole buffer is copied (the bulk-copy win case).
        let src = vec![b'x'; size];
        group.throughput(Throughput::Bytes(size as u64));

        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/simd"), size),
            &size,
            |b, _| {
                let mut dst = vec![0u8; size];
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(memccpy(&mut dst, &src, 0, size));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    simd_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        simd_stats
            .borrow()
            .report(mode, &format!("memccpy_simd_{size}"));

        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/scalar"), size),
            &size,
            |b, _| {
                let mut dst = vec![0u8; size];
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(scalar_ref_memccpy(&mut dst, &src, 0, size));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    scalar_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        scalar_stats
            .borrow()
            .report(mode, &format!("memccpy_scalar_{size}"));
    }
    group.finish();
}

fn bench_strchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strchr_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strchr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strchr(&s, b'Z'));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strchr(&s, b'Z'));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strstr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let needle = b"ZQ\0";
    let mut group = c.benchmark_group("strstr_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strstr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strstr(&s, needle));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strstr(&s, needle));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strnstr_bounded_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let needle = b"ZQ\0";
    let mut group = c.benchmark_group("strnstr_bounded_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size * 4];
        let bench_label = format!("strnstr_bounded_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strnstr(&s, needle, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &bound| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strnstr(&s, needle, bound));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strcasestr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let needle = b"zq\0";
    let mut group = c.benchmark_group("strcasestr_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strcasestr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strcasestr(&s, needle));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strcasestr(&s, needle));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strrchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strrchr_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strrchr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strrchr(&s, b'Z'));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strrchr(&s, b'Z'));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strcspn_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let reject = b"Z\0";
    let mut group = c.benchmark_group("strcspn_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strcspn_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strcspn(&s, reject));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strcspn(&s, reject));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strcspn_general_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let reject = b"WXYZ\0";
    let mut group = c.benchmark_group("strcspn_general_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strcspn_general_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strcspn(&s, reject));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strcspn(&s, reject));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strpbrk_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let accept = b"Z\0";
    let mut group = c.benchmark_group("strpbrk_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strpbrk_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strpbrk(&s, accept));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strpbrk(&s, accept));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strpbrk_general_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let accept = b"WXYZ\0";
    let mut group = c.benchmark_group("strpbrk_general_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strpbrk_general_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strpbrk(&s, accept));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strpbrk(&s, accept));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strspn_full(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let accept = b"A\0";
    let mut group = c.benchmark_group("strspn_full");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strspn_full_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strspn(&s, accept));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strspn(&s, accept));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strspn_general_full(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let accept = b"ABCD\0";
    let mut group = c.benchmark_group("strspn_general_full");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strspn_general_full_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strspn(&s, accept));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strspn(&s, accept));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strsep_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let delim = b":\0";
    let mut group = c.benchmark_group("strsep_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strsep_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strsep(&mut s, delim));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strsep(&mut s, delim));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_strchrnul_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("strchrnul_absent");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        let bench_label = format!("strchrnul_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(strchrnul(&s, b'Z'));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(strchrnul(&s, b'Z'));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wcsrchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcsrchr_absent");

    for &size in sizes {
        let mut s = vec![b'A' as u32; size];
        let bench_label = format!("wcsrchr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcsrchr(&s, b'Z' as u32));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wcsrchr(&s, b'Z' as u32));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wcsstr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let needle = [b'Z' as u32, b'Q' as u32, 0];
    let mut group = c.benchmark_group("wcsstr_absent");

    for &size in sizes {
        let mut s = vec![b'A' as u32; size];
        let bench_label = format!("wcsstr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcsstr(&s, &needle));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wcsstr(&s, &needle));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wcschr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcschr_absent");

    for &size in sizes {
        let mut s = vec![b'A' as u32; size];
        let bench_label = format!("wcschr_absent_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcschr(&s, b'Z' as u32));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wcschr(&s, b'Z' as u32));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wcslen(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcslen");

    for &size in sizes {
        let mut s = vec![b'A' as u32; size];
        let bench_label = format!("wcslen_{size}");
        s.push(0);
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcslen(&s));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wcslen(&s));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wmemcmp_equal(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wmemcmp_equal");

    for &size in sizes {
        let left = vec![0x5A_u32; size];
        let right = vec![0x5A_u32; size];
        let bench_label = format!("wmemcmp_equal_{size}");
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wmemcmp(&left, &right, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wmemcmp(&left, &right, sz));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wcsncmp_equal(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcsncmp_equal");

    for &size in sizes {
        let mut left = vec![0x5A_u32; size];
        let mut right = vec![0x5A_u32; size];
        left.push(0);
        right.push(0);
        let n = size;
        let bench_label = format!("wcsncmp_equal_{size}");
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcsncmp(&left, &right, n));
            black_box(wcscmp(&left, &right));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wcsncmp(&left, &right, n));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

// Inline scalar reference (the pre-SIMD wcsncasecmp body) for an in-run
// before/after ratio against the SIMD implementation.
fn scalar_ref_wcsncasecmp(s1: &[u32], s2: &[u32], n: usize) -> i32 {
    #[inline]
    fn lower(c: u32) -> u32 {
        if (0x41..=0x5A).contains(&c) {
            c + 0x20
        } else {
            c
        }
    }
    let mut i = 0;
    while i < n {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };
        let la = lower(a);
        let lb = lower(b);
        if la != lb {
            return if (la as i32) < (lb as i32) { -1 } else { 1 };
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
    0
}

fn bench_wcsncasecmp_equal(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcsncasecmp_equal");

    for &size in sizes {
        // Case-flipped equal strings: fold-equal, raw-differ (the realistic
        // case-insensitive-compare workload). 'A' vs 'a'.
        let mut left = vec![0x41u32; size];
        let mut right = vec![0x61u32; size];
        left.push(0);
        right.push(0);
        let n = size;
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcsncasecmp(&left, &right, n));
            black_box(wcscasecmp(&left, &right));
        }

        // SIMD impl.
        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/simd"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(wcsncasecmp(&left, &right, n));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    simd_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        simd_stats
            .borrow()
            .report(mode, &format!("wcsncasecmp_simd_{size}"));

        // Scalar reference (pre-SIMD baseline).
        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/scalar"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(scalar_ref_wcsncasecmp(&left, &right, n));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    scalar_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        scalar_stats
            .borrow()
            .report(mode, &format!("wcsncasecmp_scalar_{size}"));
    }
    group.finish();
}

// Inline scalar reference (the pre-SIMD wcsspn body) for an in-run before/after
// ratio against the SIMD implementation.
fn scalar_ref_wcsspn(s: &[u32], accept: &[u32]) -> usize {
    let alen = accept.iter().position(|&c| c == 0).unwrap_or(accept.len());
    let set = &accept[..alen];
    for (i, &ch) in s.iter().enumerate() {
        if ch == 0 || !set.contains(&ch) {
            return i;
        }
    }
    s.len()
}

fn bench_wcsspn_full(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcsspn_full");

    // Accept set of 4 digits; string is all '1' (a full-accept matching prefix).
    let accept: Vec<u32> = vec![b'0' as u32, b'1' as u32, b'2' as u32, b'3' as u32, 0];

    for &size in sizes {
        let mut s = vec![b'1' as u32; size];
        s.push(0);
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wcsspn(&s, &accept));
        }

        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/simd"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(wcsspn(&s, &accept));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    simd_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        simd_stats
            .borrow()
            .report(mode, &format!("wcsspn_simd_{size}"));

        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/scalar"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(scalar_ref_wcsspn(&s, &accept));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    scalar_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        scalar_stats
            .borrow()
            .report(mode, &format!("wcsspn_scalar_{size}"));
    }
    group.finish();
}

// Inline scalar reference (pre-SIMD wcsnlen body) for an in-run ratio.
fn scalar_ref_wcsnlen(s: &[u32], maxlen: usize) -> usize {
    let limit = maxlen.min(s.len());
    s.iter().take(limit).position(|&c| c == 0).unwrap_or(limit)
}

fn bench_wcsnlen_full(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wcsnlen_full");

    for &size in sizes {
        // No NUL within maxlen: the whole prefix is scanned (the win case).
        let s = vec![b'x' as u32; size];
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/simd"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(wcsnlen(&s, size));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    simd_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        simd_stats
            .borrow()
            .report(mode, &format!("wcsnlen_simd_{size}"));

        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(
            BenchmarkId::new(format!("{mode}/scalar"), size),
            &size,
            |b, _| {
                b.iter_custom(|iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        black_box(scalar_ref_wcsnlen(&s, size));
                    }
                    let dur = start.elapsed().max(Duration::from_nanos(1));
                    scalar_stats.borrow_mut().record(iters, dur);
                    dur
                });
            },
        );
        scalar_stats
            .borrow()
            .report(mode, &format!("wcsnlen_scalar_{size}"));
    }
    group.finish();
}

fn bench_wmemrchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wmemrchr_absent");

    for &size in sizes {
        let s = vec![b'A' as u32; size];
        let bench_label = format!("wmemrchr_absent_{size}");
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wmemrchr(&s, b'Z' as u32, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wmemrchr(&s, b'Z' as u32, sz));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_wmemchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("wmemchr_absent");

    for &size in sizes {
        let s = vec![b'A' as u32; size];
        let bench_label = format!("wmemchr_absent_{size}");
        group.throughput(Throughput::Bytes(
            (size * std::mem::size_of::<u32>()) as u64,
        ));

        for _ in 0..10_000 {
            black_box(wmemchr(&s, b'Z' as u32, size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wmemchr(&s, b'Z' as u32, sz));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_memchr_absent(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mode = mode_label();
    let mut group = c.benchmark_group("memchr_absent");

    for &size in sizes {
        let haystack = vec![b'A'; size];
        let bench_label = format!("memchr_absent_{size}");
        group.throughput(Throughput::Bytes(size as u64));

        for _ in 0..10_000 {
            black_box(memchr(&haystack, b'Z', size));
        }

        let stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(mode, size), &size, |b, &sz| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(memchr(&haystack, b'Z', sz));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        stats.borrow().report(mode, &bench_label);
    }
    group.finish();
}

fn bench_regex_search(c: &mut Criterion) {
    use frankenlibc_core::string::regex::{REG_EXTENDED, regex_compile, regex_match_bounds_bytes};
    let mode = mode_label();
    // 4 KiB haystack of 'a' (no 'n'); pattern begins with a literal 'n' that
    // never occurs, so the first-byte prefilter skips every start position
    // instead of seeding a thread set (and its Vec allocs) at each one.
    let haystack = vec![b'a'; 4096];
    let compiled = regex_compile(b"needle[0-9]+", REG_EXTENDED).expect("compile");

    let mut group = c.benchmark_group("regex_search_absent");
    group.throughput(Throughput::Bytes(haystack.len() as u64));
    group.bench_function(BenchmarkId::new(mode, 4096), |b| {
        b.iter(|| black_box(regex_match_bounds_bytes(&compiled, black_box(&haystack), 0)));
    });
    group.finish();

    // Common first byte, rare multi-byte literal: the haystack is all 'e', so a
    // single-byte prefilter cannot skip anything (every position is a candidate)
    // and probes the VM ~n times; the literal-prefix memmem jump finds no
    // "error" and returns after one scan.
    let hay_e = vec![b'e'; 4096];
    let compiled_e = regex_compile(b"error[0-9]+", REG_EXTENDED).expect("compile");
    let mut g2 = c.benchmark_group("regex_search_common_first_byte");
    g2.throughput(Throughput::Bytes(hay_e.len() as u64));
    g2.bench_function(BenchmarkId::new(mode, 4096), |b| {
        b.iter(|| black_box(regex_match_bounds_bytes(&compiled_e, black_box(&hay_e), 0)));
    });
    g2.finish();

    // Case-insensitive, first byte absent in either case: the case-folded
    // first-byte prefilter skips the whole haystack instead of probing the VM
    // at every position (icase patterns previously got no prefilter at all).
    let compiled_i = regex_compile(b"needle", REG_EXTENDED | 2).expect("compile"); // 2 = REG_ICASE
    let mut g3 = c.benchmark_group("regex_search_icase_absent");
    g3.throughput(Throughput::Bytes(haystack.len() as u64));
    g3.bench_function(BenchmarkId::new(mode, 4096), |b| {
        b.iter(|| {
            black_box(regex_match_bounds_bytes(
                &compiled_i,
                black_box(&haystack),
                0,
            ))
        });
    });
    g3.finish();

    // icase, common first byte (all 'E'), rare full literal: the case-folded
    // single-byte set {e,E} cannot skip, but the icase literal jump (strcasestr)
    // finds no "errors" and returns after one scan.
    // Large epsilon-closure per step: an optional chain `a?a?...a?b` keeps ~N
    // states live at each position, stressing the thread-set dedup. On all-'a'
    // input the trailing 'b' never matches, so the VM runs the full closure at
    // each start — O(m^2) per step with the old linear-scan dedup, O(m) with the
    // gen-stamped one.
    let chain: Vec<u8> = b"a?".repeat(40).into_iter().chain(*b"b").collect();
    let hay_chain = vec![b'a'; 512];
    let compiled_chain = regex_compile(&chain, REG_EXTENDED).expect("compile");
    let mut g5 = c.benchmark_group("regex_thread_closure");
    g5.throughput(Throughput::Bytes(hay_chain.len() as u64));
    g5.bench_function(BenchmarkId::new(mode, 512), |b| {
        b.iter(|| {
            black_box(regex_match_bounds_bytes(
                &compiled_chain,
                black_box(&hay_chain),
                0,
            ))
        });
    });
    g5.finish();

    let hay_e_upper = vec![b'E'; 4096];
    let compiled_il = regex_compile(b"errors", REG_EXTENDED | 2).expect("compile");
    let mut g4 = c.benchmark_group("regex_search_icase_common_first_byte");
    g4.throughput(Throughput::Bytes(hay_e_upper.len() as u64));
    g4.bench_function(BenchmarkId::new(mode, 4096), |b| {
        b.iter(|| {
            black_box(regex_match_bounds_bytes(
                &compiled_il,
                black_box(&hay_e_upper),
                0,
            ))
        });
    });
    g4.finish();
}

fn bench_memmem(c: &mut Criterion) {
    let mode = mode_label();
    // ~4 KiB of English-like text; the needle's first byte ('q') is uncommon,
    // so the SIMD memchr prefilter skips long stretches the scalar Two-Way loop
    // would walk byte-by-byte.
    let unit = b"the brown fox jumps over the lazy dog and then rests a while. ";
    let mut hay: Vec<u8> = Vec::new();
    while hay.len() < 4096 {
        hay.extend_from_slice(unit);
    }
    let present: &[u8] = b"quznorf"; // absent (no 'q' run matches) -> full scan
    let absent: &[u8] = b"zzzzzzfox"; // 'z' present but needle never matches

    let cases: &[(&str, &[u8])] = &[("rare_first_byte", present), ("common_first_byte", absent)];
    let mut group = c.benchmark_group("memmem");
    for &(name, ndl) in cases {
        group.throughput(Throughput::Bytes(hay.len() as u64));
        group.bench_with_input(BenchmarkId::new(mode, name), &name, |b, _| {
            b.iter(|| {
                black_box(memmem(
                    black_box(&hay),
                    hay.len(),
                    black_box(ndl),
                    ndl.len(),
                ))
            });
        });
    }
    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = bench_memcpy_sizes, bench_strlen, bench_memcmp_sizes, bench_strcmp, bench_strncmp, bench_strncasecmp_equal, bench_memccpy_absent, bench_bcmp_equal, bench_strchr_absent, bench_strstr_absent, bench_strnstr_bounded_absent, bench_strcasestr_absent, bench_strrchr_absent, bench_strcspn_absent, bench_strcspn_general_absent, bench_strpbrk_absent, bench_strpbrk_general_absent, bench_strspn_full, bench_strspn_general_full, bench_strsep_absent, bench_strchrnul_absent, bench_wcsrchr_absent, bench_wcsstr_absent, bench_wcslen, bench_wcschr_absent, bench_wmemchr_absent, bench_wmemrchr_absent, bench_wmemcmp_equal, bench_wcsncmp_equal, bench_wcsncasecmp_equal, bench_wcsspn_full, bench_wcsnlen_full, bench_memchr_absent, bench_memmem, bench_regex_search
);
criterion_main!(benches);
