use std::ffi::c_void;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

fn benchmark_memcpy_paths(c: &mut Criterion) {
    let sizes: [usize; 4] = [64, 256, 1024, 4096];
    let mut group = c.benchmark_group("copy_paths");

    for size in sizes {
        let src = vec![0xAB_u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("tsm_preview", size), &size, |b, &_size| {
            b.iter(|| {
                let mut dst = vec![0_u8; size];
                // SAFETY: Benchmark uses valid non-overlapping buffers.
                unsafe {
                    frankenlibc::glibc_rust_memcpy_preview(
                        dst.as_mut_ptr().cast::<c_void>(),
                        src.as_ptr().cast::<c_void>(),
                        black_box(size),
                    );
                }
                black_box(dst);
            });
        });

        group.bench_with_input(BenchmarkId::new("host_libc", size), &size, |b, &_size| {
            b.iter(|| {
                let mut dst = vec![0_u8; size];
                // SAFETY: Benchmark uses valid non-overlapping buffers.
                unsafe {
                    libc::memcpy(
                        dst.as_mut_ptr().cast::<c_void>(),
                        src.as_ptr().cast::<c_void>(),
                        black_box(size),
                    );
                }
                black_box(dst);
            });
        });
    }

    group.finish();
}

criterion_group!(benches, benchmark_memcpy_paths);
criterion_main!(benches);
