//! Multibyte -> wide conversion benchmarks (mbstowcs).
//!
//! mbstowcs is a scalar per-character mbtowc loop in the baseline; the
//! SIMD ASCII fast path bulk-widens whole ASCII runs. These benches exercise
//! the dominant real-world case (ASCII-heavy text) plus a mixed-UTF-8 case
//! that mostly falls back to the scalar path (regression guard).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use frankenlibc_core::string::{mbstowcs, wcstombs};

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
    // Pure 4-byte astral codepoints. This isolates the remaining scalar
    // multibyte decode lane after 2-byte and 3-byte SIMD windows landed.
    let mut astral_4byte: Vec<u8> = Vec::with_capacity(1024 * 4);
    for i in 0..1024 {
        let cp = 0x1F600 + (i % 0x80) as u32;
        astral_4byte.push(0xF0 | (cp >> 18) as u8);
        astral_4byte.push(0x80 | ((cp >> 12) & 0x3F) as u8);
        astral_4byte.push(0x80 | ((cp >> 6) & 0x3F) as u8);
        astral_4byte.push(0x80 | (cp & 0x3F) as u8);
    }

    let cases: &[(&str, &[u8])] = &[
        ("ascii_1k", &ascii),
        ("astral_4byte", &astral_4byte),
        ("mixed_utf8", &mixed),
    ];

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

fn bench_wcstombs(c: &mut Criterion) {
    // ~1 KiB of ASCII codepoints.
    let ascii: Vec<u32> = (0..1024).map(|i| 0x61 + (i % 26) as u32).collect();
    // Pure 3-byte BMP codepoints. This is the remaining multibyte encode lane
    // after the 2-byte SIMD path landed.
    let cjk_3byte: Vec<u32> = (0..1024).map(|i| 0x4E00 + (i % 0x100) as u32).collect();
    // Pure 4-byte astral codepoints. This isolates the remaining scalar
    // multibyte encode lane after 2-byte and 3-byte SIMD windows landed.
    let astral_4byte: Vec<u32> = (0..1024).map(|i| 0x1F600 + (i % 0x80) as u32).collect();
    // Mixed: ASCII runs interleaved with 2/3-byte codepoints.
    let mut mixed: Vec<u32> = Vec::new();
    for i in 0..128 {
        mixed.extend_from_slice(&[0x77, 0x6f, 0x72, 0x64]); // "word"
        mixed.push(if i % 2 == 0 { 0xE9 } else { 0x20AC }); // é or €
        mixed.push(0x20); // space
    }

    let cases: &[(&str, &[u32])] = &[
        ("ascii_1k", &ascii),
        ("astral_4byte", &astral_4byte),
        ("cjk_3byte", &cjk_3byte),
        ("mixed_utf8", &mixed),
    ];

    let mut group = c.benchmark_group("wchar_wcstombs");
    for &(name, src) in cases {
        group.throughput(Throughput::Elements(src.len() as u64));
        let mut dest = vec![0u8; src.len() * 4 + 1];
        group.bench_with_input(BenchmarkId::from_parameter(name), src, |b, input| {
            b.iter(|| {
                let n = wcstombs(black_box(&mut dest), black_box(input));
                black_box(n);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_mbstowcs, bench_wcstombs);
criterion_main!(benches);
