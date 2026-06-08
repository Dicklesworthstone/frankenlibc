#![feature(portable_simd)]
//! Same-process A/B timing for the folded wcsnlen vs the original per-16-element
//! reduction, run back-to-back so both experience identical machine load — the
//! shared rch worker is too noisy for reliable cross-run before/after numbers.
//! `#[ignore]` by default; run with `--ignored --nocapture`.

use std::simd::{Simd, cmp::SimdPartialEq};
use std::time::Instant;

use frankenlibc_core::string::wide::wcsnlen;

/// The original implementation: per-16-element SIMD chunk, one `.any()` reduction
/// per chunk.
fn wcsnlen_orig(s: &[u32], maxlen: usize) -> usize {
    const LANES: usize = 16;
    let limit = maxlen.min(s.len());
    let scan = &s[..limit];
    let mut chunks = scan.chunks_exact(LANES);
    let mut base = 0usize;
    for chunk in chunks.by_ref() {
        let lanes = Simd::<u32, LANES>::from_slice(chunk);
        if lanes.simd_eq(Simd::splat(0)).any() {
            for (j, &ch) in chunk.iter().enumerate() {
                if ch == 0 {
                    return base + j;
                }
            }
        }
        base += LANES;
    }
    for (j, &ch) in chunks.remainder().iter().enumerate() {
        if ch == 0 {
            return base + j;
        }
    }
    limit
}

fn time_it(label: &str, f: impl Fn() -> usize) -> f64 {
    const ITERS: u64 = 200_000;
    // Best-of-5 to shrug off scheduler hiccups.
    let mut best = f64::INFINITY;
    for _ in 0..5 {
        let start = Instant::now();
        let mut acc = 0usize;
        for _ in 0..ITERS {
            acc = acc.wrapping_add(std::hint::black_box(f()));
        }
        std::hint::black_box(acc);
        let ns = start.elapsed().as_nanos() as f64 / ITERS as f64;
        best = best.min(ns);
    }
    eprintln!("  {label:<16} {best:.2} ns/op (best of 5)");
    best
}

#[test]
#[ignore = "same-process A/B micro-bench; run with --ignored --nocapture"]
fn wcsnlen_fold_vs_orig() {
    for &size in &[256usize, 1024, 4096] {
        let s: Vec<u32> = vec![b'A' as u32; size + 1]; // no NUL until index `size`
        let buf = &s[..];
        eprintln!("size={size}");
        // Interleave folded/orig so transient load hits both equally.
        let folded = time_it("wcsnlen(folded)", || wcsnlen(buf, size));
        let orig = time_it("wcsnlen(orig16)", || wcsnlen_orig(buf, size));
        let folded2 = time_it("wcsnlen(folded)", || wcsnlen(buf, size));
        let orig2 = time_it("wcsnlen(orig16)", || wcsnlen_orig(buf, size));
        let f = folded.min(folded2);
        let o = orig.min(orig2);
        eprintln!("  => speedup folded vs orig16: {:.2}x\n", o / f);
        // Sanity: both must agree on the result.
        assert_eq!(wcsnlen(buf, size), wcsnlen_orig(buf, size));
    }
}
