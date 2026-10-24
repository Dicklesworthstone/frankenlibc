#![feature(portable_simd)]
//! Correctness + same-process A/B harness for wcsspn's SIMD fast paths.
//!
//! Asserts the production `wcsspn` matches naive per-panel reference scans over
//! the repeated-char and contiguous-range workloads, and (under `--ignored`)
//! times them back-to-back so both see identical machine load — the shared rch
//! worker is too noisy for reliable cross-run before/after (see bd-2g7oyh.264).
//!
//! NOTE (negative result): a 256-element folded-block variant of these paths was
//! evaluated and did NOT clear Score>=2.0 — wcsspn is already 32-lane optimised
//! (the repeated-char path regressed under folding; the range path is per-lane
//! subtract-bound at ~1.6x). The 256-block fold only wins big on the unoptimised
//! single-cheap-op scans (wcslen/wmemchr/wcsnlen). Kept as the measurement harness
//! for any future wcsspn lever.

use std::simd::{Simd, cmp::SimdPartialEq, cmp::SimdPartialOrd};
use std::time::Instant;

use frankenlibc_core::string::wide::wcsspn;

/// Naive single-repeated-char reference: per-32-element panel.
fn wcsspn_repeated_ref(s: &[u32], member: u32) -> usize {
    const LANES: usize = 32;
    let mut i = 0usize;
    while i + LANES <= s.len() {
        let lanes = Simd::<u32, LANES>::from_slice(&s[i..i + LANES]);
        if !lanes.simd_eq(Simd::splat(member)).all() {
            break;
        }
        i += LANES;
    }
    while i < s.len() {
        if s[i] != member {
            return i;
        }
        i += 1;
    }
    s.len()
}

/// Naive contiguous-range reference: per-16-element panel.
fn wcsspn_range_ref(s: &[u32], min: u32, max: u32) -> usize {
    const LANES: usize = 16;
    let mut i = 0usize;
    while i + LANES <= s.len() {
        let lanes = Simd::<u32, LANES>::from_slice(&s[i..i + LANES]);
        if !(lanes - Simd::splat(min))
            .simd_le(Simd::splat(max - min))
            .all()
        {
            break;
        }
        i += LANES;
    }
    while i < s.len() {
        let ch = s[i];
        if ch == 0 || ch < min || ch > max {
            return i;
        }
        i += 1;
    }
    s.len()
}

fn time_it(label: &str, f: impl Fn() -> usize) -> f64 {
    const ITERS: u64 = 200_000;
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
    eprintln!("  {label:<20} {best:.2} ns/op (best of 5)");
    best
}

/// Always-on correctness: production wcsspn must equal the naive references.
#[test]
fn wcsspn_matches_naive_references() {
    let accept: Vec<u32> = vec![b'0' as u32, b'1' as u32, b'2' as u32, b'3' as u32, 0];
    for size in [16usize, 31, 63, 256, 257, 1024, 4096] {
        // Repeated-char workload.
        let mut rep = vec![b'1' as u32; size];
        rep.push(0);
        assert_eq!(
            wcsspn(&rep, &accept),
            wcsspn_repeated_ref(&rep, b'1' as u32),
            "repeated size={size}"
        );
        // Varied in-range workload.
        let mut var: Vec<u32> = (0..size).map(|i| b'0' as u32 + (i as u32 % 4)).collect();
        var.push(0);
        assert_eq!(
            wcsspn(&var, &accept),
            wcsspn_range_ref(&var, b'0' as u32, b'3' as u32),
            "range size={size}"
        );
        // A non-member partway through must stop at the same index.
        if size > 8 {
            let mut stop = vec![b'1' as u32; size];
            stop[size / 2] = b'Z' as u32;
            stop.push(0);
            assert_eq!(
                wcsspn(&stop, &accept),
                wcsspn_repeated_ref(&stop, b'1' as u32),
                "stop size={size}"
            );
        }
    }
}

#[test]
#[ignore = "same-process A/B micro-bench; run with --ignored --nocapture"]
fn wcsspn_ab_timing() {
    let accept: Vec<u32> = vec![b'0' as u32, b'1' as u32, b'2' as u32, b'3' as u32, 0];
    for &size in &[256usize, 1024, 4096] {
        let mut rep = vec![b'1' as u32; size];
        rep.push(0);
        eprintln!("repeated size={size}");
        time_it("wcsspn(prod)", || wcsspn(&rep, &accept));
        time_it("naive32", || wcsspn_repeated_ref(&rep, b'1' as u32));

        let mut var: Vec<u32> = (0..size).map(|i| b'0' as u32 + (i as u32 % 4)).collect();
        var.push(0);
        eprintln!("range size={size}");
        time_it("wcsspn(prod)", || wcsspn(&var, &accept));
        time_it("naive16", || {
            wcsspn_range_ref(&var, b'0' as u32, b'3' as u32)
        });
    }
}
