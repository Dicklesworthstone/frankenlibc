//! Multibyte -> wide conversion benchmarks (mbstowcs).
//!
//! mbstowcs is a scalar per-character mbtowc loop in the baseline; the
//! SIMD ASCII fast path bulk-widens whole ASCII runs. These benches exercise
//! the dominant real-world case (ASCII-heavy text) plus a mixed-UTF-8 case
//! that mostly falls back to the scalar path (regression guard).

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::string::mbstowcs;

fn bench_mbstowcs(c: &mut Criterion) {
    // ~1 KiB of ASCII (typical for paths, log lines, identifiers).
    let ascii: Vec<u8> = (0..1024).map(|i| b'a' + (i % 26) as u8).collect();
    // Mixed: ASCII runs interleaved with 2/3-byte UTF-8 (é, €) — exercises the
    // fast-path/scalar handoff repeatedly.
    let mut mixed: Vec<u8> = Vec::new();
    for i in 0..128 {
        mixed.extend_from_slice(b"word");
        if i % 2 == 0 {
            mixed.extend_from_slice(b"\xc3\xa9"); // é
        } else {
            mixed.extend_from_slice(b"\xe2\x82\xac"); // €
        }
        mixed.push(b' ');
    }

    let cases: &[(&str, &[u8])] = &[("ascii_1k", &ascii), ("mixed_utf8", &mixed)];

    let mut group = c.benchmark_group("wchar_mbstowcs");
    for &(name, src) in cases {
        group.throughput(Throughput::Bytes(src.len() as u64));
        let mut dest = vec![0u32; src.len() + 1];
        group.bench_with_input(BenchmarkId::from_parameter(name), src, |b, input| {
            b.iter(|| {
                let n = mbstowcs(black_box(&mut dest), black_box(input));
                black_box(n);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_mbstowcs);
criterion_main!(benches);
