//! String function benchmarks.

use std::cell::RefCell;
use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::string::{
    memchr, memcmp, memcpy, strcasestr, strchr, strchrnul, strcmp, strcspn, strlen, strncmp,
    strnstr, strpbrk, strrchr, strsep, strspn, strstr, wcscasecmp, wcschr, wcscmp, wcslen,
    wcsncasecmp, wcsncmp, wcsrchr, wcsstr, wmemchr, wmemcmp, wmemrchr,
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
        let left = vec![0x5A as u32; size];
        let right = vec![0x5A as u32; size];
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
        let mut left = vec![0x5A as u32; size];
        let mut right = vec![0x5A as u32; size];
        left.push(0);
        right.push(0);
        let n = size;
        let bench_label = format!("wcsncmp_equal_{size}");
        group.throughput(Throughput::Bytes((size * std::mem::size_of::<u32>()) as u64));

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
        if (0x41..=0x5A).contains(&c) { c + 0x20 } else { c }
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
        group.throughput(Throughput::Bytes((size * std::mem::size_of::<u32>()) as u64));

        for _ in 0..10_000 {
            black_box(wcsncasecmp(&left, &right, n));
            black_box(wcscasecmp(&left, &right));
        }

        // SIMD impl.
        let simd_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(format!("{mode}/simd"), size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(wcsncasecmp(&left, &right, n));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                simd_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        simd_stats.borrow().report(mode, &format!("wcsncasecmp_simd_{size}"));

        // Scalar reference (pre-SIMD baseline).
        let scalar_stats = RefCell::new(BenchStats::default());
        group.bench_with_input(BenchmarkId::new(format!("{mode}/scalar"), size), &size, |b, _| {
            b.iter_custom(|iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    black_box(scalar_ref_wcsncasecmp(&left, &right, n));
                }
                let dur = start.elapsed().max(Duration::from_nanos(1));
                scalar_stats.borrow_mut().record(iters, dur);
                dur
            });
        });
        scalar_stats.borrow().report(mode, &format!("wcsncasecmp_scalar_{size}"));
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

criterion_group!(
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(1))
        .measurement_time(Duration::from_secs(2))
        .sample_size(100);
    targets = bench_memcpy_sizes, bench_strlen, bench_memcmp_sizes, bench_strcmp, bench_strncmp, bench_strchr_absent, bench_strstr_absent, bench_strnstr_bounded_absent, bench_strcasestr_absent, bench_strrchr_absent, bench_strcspn_absent, bench_strcspn_general_absent, bench_strpbrk_absent, bench_strpbrk_general_absent, bench_strspn_full, bench_strspn_general_full, bench_strsep_absent, bench_strchrnul_absent, bench_wcsrchr_absent, bench_wcsstr_absent, bench_wcslen, bench_wcschr_absent, bench_wmemchr_absent, bench_wmemrchr_absent, bench_wmemcmp_equal, bench_wcsncmp_equal, bench_wcsncasecmp_equal, bench_memchr_absent
);
criterion_main!(benches);
