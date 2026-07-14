//! Multibyte -> wide conversion benchmarks (mbstowcs).
//!
//! mbstowcs is a scalar per-character mbtowc loop in the baseline; the
//! SIMD ASCII fast path bulk-widens whole ASCII runs. These benches exercise
//! the dominant real-world case (ASCII-heavy text) plus a mixed-UTF-8 case
//! that mostly falls back to the scalar path (regression guard).

#![feature(portable_simd)]

use std::hint::black_box;
use std::simd::{Simd, cmp::SimdPartialOrd};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use frankenlibc_core::string::{mbstowcs, wcstombs, wcswidth, wcwidth};

#[inline(never)]
fn wcswidth_scalar(s: &[u32], n: usize) -> i32 {
    let mut total = 0_i32;
    for &wc in s.iter().take(n) {
        if wc == 0 {
            break;
        }
        let width = wcwidth(wc);
        if width < 0 {
            return -1;
        }
        total = total.saturating_add(width);
    }
    total
}

#[inline(never)]
fn wcswidth_ascii_run(s: &[u32], n: usize) -> i32 {
    wcswidth(s, n)
}

#[inline(never)]
fn wcswidth_ascii_run16(s: &[u32], n: usize) -> i32 {
    const LANES: usize = 16;

    let scan = &s[..n.min(s.len())];
    let mut total = 0_i32;
    let mut i = 0usize;
    while i + LANES <= scan.len() {
        let lanes = Simd::<u32, LANES>::from_slice(&scan[i..i + LANES]);
        let printable_ascii = lanes.simd_ge(Simd::splat(0x20)) & lanes.simd_le(Simd::splat(0x7e));
        if !printable_ascii.all() {
            break;
        }
        total = total.saturating_add(LANES as i32);
        i += LANES;
    }

    for &wc in &scan[i..] {
        if wc == 0 {
            break;
        }
        let width = wcwidth(wc);
        if width < 0 {
            return -1;
        }
        total = total.saturating_add(width);
    }
    total
}

fn bench_wcswidth_ascii_fold64_ab(c: &mut Criterion) {
    // The candidate may fail its 64-wide certificate at any lane and must then
    // hand the untouched suffix to the pre-lever 16-wide path. Exercise those
    // boundaries and width classes before entering a timer.
    for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129] {
        let ascii = vec![b'x' as u32; len];
        assert_eq!(
            wcswidth_ascii_run16(&ascii, len),
            wcswidth_scalar(&ascii, len)
        );
        assert_eq!(
            wcswidth_ascii_run(&ascii, len),
            wcswidth_scalar(&ascii, len)
        );
        for &pos in &[0usize, 15, 16, 31, 32, 47, 48, 63, 64, 127, 128] {
            if pos >= len {
                continue;
            }
            for special in [0, 0x07, 0x0301, 0x4e16, 0x11_0000] {
                let mut input = ascii.clone();
                input[pos] = special;
                let expected = wcswidth_scalar(&input, len);
                assert_eq!(
                    wcswidth_ascii_run16(&input, len),
                    expected,
                    "fold16 mismatch len={len} pos={pos} special={special:#x}",
                );
                assert_eq!(
                    wcswidth_ascii_run(&input, len),
                    expected,
                    "fold64 mismatch len={len} pos={pos} special={special:#x}",
                );
            }
        }
    }

    black_box(wcwidth(b'x' as u32));

    let mut group = c.benchmark_group("wcswidth_ascii_fold64_ab");
    for size in [64usize, 256, 1024] {
        let input: Vec<u32> = (0..size).map(|i| (b' ' + (i % 95) as u8) as u32).collect();
        assert_eq!(wcswidth_ascii_run16(&input, size), size as i32);
        assert_eq!(wcswidth_ascii_run(&input, size), size as i32);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("fold16", size), &input, |b, input| {
            b.iter(|| black_box(wcswidth_ascii_run16(black_box(input), black_box(size))));
        });
        group.bench_with_input(BenchmarkId::new("fold64", size), &input, |b, input| {
            b.iter(|| black_box(wcswidth_ascii_run(black_box(input), black_box(size))));
        });
    }
    group.finish();
}

fn bench_wcswidth_ascii_run_ab(c: &mut Criterion) {
    // Exercise every boundary at which the SIMD prefix may hand back to the
    // scalar reference before timing the all-printable hot row.
    for len in [0usize, 1, 15, 16, 17, 31, 32, 33, 65] {
        let ascii = vec![b'x' as u32; len];
        assert_eq!(
            wcswidth_ascii_run(&ascii, len),
            wcswidth_scalar(&ascii, len)
        );
        for &pos in &[0usize, 15, 16, 31, 32, 64] {
            if pos >= len {
                continue;
            }
            for special in [0, 0x07, 0x0301, 0x4e16, 0x11_0000] {
                let mut input = ascii.clone();
                input[pos] = special;
                assert_eq!(
                    wcswidth_ascii_run(&input, len),
                    wcswidth_scalar(&input, len),
                    "wcswidth mismatch len={len} pos={pos} special={special:#x}",
                );
            }
        }
    }

    // Initialize the canonical BMP table outside all timed regions.
    black_box(wcwidth(b'x' as u32));

    let mut group = c.benchmark_group("wcswidth_ascii_run_ab");
    for size in [16usize, 64, 256, 1024] {
        let input: Vec<u32> = (0..size).map(|i| (b' ' + (i % 95) as u8) as u32).collect();
        assert_eq!(wcswidth_scalar(&input, size), size as i32);
        assert_eq!(wcswidth_ascii_run(&input, size), size as i32);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("scalar", size), &input, |b, input| {
            b.iter(|| black_box(wcswidth_scalar(black_box(input), black_box(size))));
        });
        group.bench_with_input(BenchmarkId::new("ascii_run", size), &input, |b, input| {
            b.iter(|| black_box(wcswidth_ascii_run(black_box(input), black_box(size))));
        });
    }
    group.finish();
}

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

criterion_group!(
    benches,
    bench_mbstowcs,
    bench_wcstombs,
    bench_wcswidth_ascii_run_ab,
    bench_wcswidth_ascii_fold64_ab
);
criterion_main!(benches);
