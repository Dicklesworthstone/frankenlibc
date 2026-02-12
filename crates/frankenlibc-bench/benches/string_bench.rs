//! String function benchmarks.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn bench_memcpy_sizes(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096, 65536];
    let mut group = c.benchmark_group("memcpy");

    for &size in sizes {
        let src = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("frankenlibc", size), &size, |b, &sz| {
            b.iter(|| {
                let mut dst = vec![0u8; sz];
                // TODO: call glibc-rs-abi memcpy when wired
                dst.copy_from_slice(&src[..sz]);
                black_box(dst);
            });
        });
    }
    group.finish();
}

fn bench_strlen(c: &mut Criterion) {
    let sizes: &[usize] = &[16, 64, 256, 1024, 4096];
    let mut group = c.benchmark_group("strlen");

    for &size in sizes {
        let mut s = vec![b'A'; size];
        s.push(0); // null terminator
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("safe_rust", size), &size, |b, _| {
            b.iter(|| {
                // Find null byte position
                let len = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                black_box(len);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_memcpy_sizes, bench_strlen);
criterion_main!(benches);
