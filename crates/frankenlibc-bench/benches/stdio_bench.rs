//! Stdio benchmarks (placeholder).
//!
//! Will benchmark printf formatting, file I/O, and buffering once implemented.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

fn bench_placeholder(c: &mut Criterion) {
    c.bench_function("stdio_placeholder", |b| {
        b.iter(|| {
            black_box(42);
        });
    });
}

criterion_group!(benches, bench_placeholder);
criterion_main!(benches);
