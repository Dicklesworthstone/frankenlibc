//! iconv conversion benchmarks.
//!
//! The per-character iconv loop dispatches decode_char + encode_char (two large
//! `match`es over the codec enum) for every byte. The SIMD ASCII fast path
//! bulk-copies ASCII runs between ASCII-transparent encodings (UTF-8/ASCII/
//! Latin-1). These benches exercise the dominant ASCII-heavy case plus a mixed
//! case that mostly falls back to the scalar loop (regression guard).

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::iconv::{iconv, iconv_open};

fn bench_iconv(c: &mut Criterion) {
    // ~1 KiB ASCII text (UTF-8 -> ISO-8859-1: pure ASCII passthrough).
    let ascii: Vec<u8> = (0..1024).map(|i| 0x20 + (i % 0x5F) as u8).collect();
    // Mixed: ASCII runs interleaved with 2-byte UTF-8 codepoints that ARE
    // representable in Latin-1 (é=U+00E9, ü=U+00FC), so the conversion runs to
    // completion and exercises the fast-path/scalar handoff (rather than
    // aborting early on an unrepresentable codepoint).
    let mut mixed: Vec<u8> = Vec::new();
    for i in 0..128 {
        mixed.extend_from_slice(b"token");
        if i % 2 == 0 {
            mixed.extend_from_slice("é".as_bytes());
        } else {
            mixed.extend_from_slice("ü".as_bytes());
        }
    }

    let cases: &[(&str, &[u8])] = &[("ascii_1k", &ascii), ("mixed_utf8", &mixed)];

    let mut group = c.benchmark_group("iconv_utf8_to_latin1");
    for &(name, src) in cases {
        group.throughput(Throughput::Bytes(src.len() as u64));
        let mut dest = vec![0u8; src.len() * 2 + 8];
        group.bench_with_input(BenchmarkId::from_parameter(name), src, |b, input| {
            let mut cd = iconv_open(b"ISO-8859-1", b"UTF-8").expect("codec");
            b.iter(|| {
                let r = iconv(&mut cd, Some(black_box(input)), black_box(&mut dest));
                black_box(r.is_ok());
            });
        });
    }
    group.finish();
}

// UTF-8 -> KOI8-R: a single-byte legacy codepage whose low half is ASCII. The
// probe-cached fast path enables ASCII bulk-copy here too (previously this pair
// used the per-char scalar loop, since only UTF-8/ASCII/Latin-1 were fast).
fn bench_iconv_utf8_to_koi8r(c: &mut Criterion) {
    let ascii: Vec<u8> = (0..1024).map(|i| 0x20 + (i % 0x5F) as u8).collect();
    let mut group = c.benchmark_group("iconv_utf8_to_koi8r");
    group.throughput(Throughput::Bytes(ascii.len() as u64));
    let mut dest = vec![0u8; ascii.len() * 2 + 8];
    group.bench_with_input(BenchmarkId::from_parameter("ascii_1k"), &ascii[..], |b, input| {
        let mut cd = iconv_open(b"KOI8-R", b"UTF-8").expect("codec");
        b.iter(|| {
            let r = iconv(&mut cd, Some(black_box(input)), black_box(&mut dest));
            black_box(r.is_ok());
        });
    });
    group.finish();
}

// CP1251 -> KOI8-R: single-byte -> single-byte over Cyrillic-heavy text (bytes
// 0xC0..=0xFF). Every byte is non-ASCII, so the ASCII fast path does nothing and
// each byte hits the translation path — exercising the O(1) byte->byte LUT that
// replaces the per-char O(128) reverse-search in encode_koi8r.
fn bench_iconv_cp1251_to_koi8r(c: &mut Criterion) {
    let cyrillic: Vec<u8> = (0..1024).map(|i| 0xC0 + (i % 0x40) as u8).collect();
    let mut group = c.benchmark_group("iconv_cp1251_to_koi8r");
    group.throughput(Throughput::Bytes(cyrillic.len() as u64));
    let mut dest = vec![0u8; cyrillic.len() * 2 + 8];
    group.bench_with_input(BenchmarkId::from_parameter("cyrillic_1k"), &cyrillic[..], |b, input| {
        let mut cd = iconv_open(b"KOI8-R", b"CP1251").expect("codec");
        b.iter(|| {
            let r = iconv(&mut cd, Some(black_box(input)), black_box(&mut dest));
            black_box(r.is_ok());
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_iconv,
    bench_iconv_utf8_to_koi8r,
    bench_iconv_cp1251_to_koi8r
);
criterion_main!(benches);
