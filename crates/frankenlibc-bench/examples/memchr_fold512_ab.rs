//! In-process A/B for the memchr/memrchr 512B skip tier (bd-sjvs5n).
//!
//! OLD arm: a faithful replica of the pre-tier deployed 8x32-lane/256B block loop
//! (mem.rs at 49ef98330). NEW arm: the deployed `frankenlibc_core::string::mem`
//! functions, which route long scans through the 512B tier above the 256B loop.
//! Byte-identity of every (haystack, needle, n) case is asserted before timing,
//! so a detection divergence can never be scored as a speedup.
//!
//! Run: `cargo run -p frankenlibc-bench --example memchr_fold512_ab --release`
//!
//! Restores the measurement discipline of the original `memchr_fold512_ab`
//! (5bf5b6217, 2026-07-04, deleted by 51c39dec3); the old ~8-10% number was
//! measured on the since-removed 4x64-lane design and does NOT transfer by
//! assumption — this bench re-proves or refutes the lever on the current code.

#![feature(portable_simd)]

use std::hint::black_box;
use std::simd::prelude::SimdPartialEq;
use std::time::Instant;

use frankenlibc_core::string::mem::{memchr, memrchr};

const SIMD_LANES: usize = 32;
const SIMD_FOLD_PANELS: usize = 4;
const SIMD_FOLD_BYTES: usize = SIMD_LANES * SIMD_FOLD_PANELS;
const BLOCK_256: usize = SIMD_FOLD_BYTES * 2;

type MemchrFn = fn(&[u8], u8, usize) -> Option<usize>;

/// OLD arm replica: the deployed memchr loop before the 512B tier — 256B blocks
/// of eight 32-lane panels with the combined OR tree and early extraction, 128B
/// stride. Mirrors mem.rs at 49ef98330 (only the tier insertion differs).
fn memchr_256_only(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    use std::simd::StdFloat;
    let count = n.min(haystack.len());
    let hs = &haystack[..count];
    if count < SIMD_LANES {
        return hs.iter().position(|&b| b == needle);
    }
    let needle_simd = core::simd::Simd::<u8, SIMD_LANES>::splat(needle);
    let mut cur = hs;
    while cur.len() >= BLOCK_256 {
        let block: &[u8; BLOCK_256] = match cur[..BLOCK_256].try_into() {
            Ok(arr) => arr,
            Err(_) => break,
        };
        let v = |i: usize| {
            core::simd::Simd::<u8, SIMD_LANES>::from_slice(
                &block[i * SIMD_LANES..(i + 1) * SIMD_LANES],
            )
        };
        let (v0, v1, v2, v3, v4, v5, v6, v7) = (v(0), v(1), v(2), v(3), v(4), v(5), v(6), v(7));
        let m_lo = (v0.simd_eq(needle_simd) | v1.simd_eq(needle_simd))
            | (v2.simd_eq(needle_simd) | v3.simd_eq(needle_simd));
        let m_hi = (v4.simd_eq(needle_simd) | v5.simd_eq(needle_simd))
            | (v6.simd_eq(needle_simd) | v7.simd_eq(needle_simd));
        if (m_lo | m_hi).any() {
            let base = count - cur.len();
            for (p, mask) in [
                (0, v0),
                (1, v1),
                (2, v2),
                (3, v3),
                (4, v4),
                (5, v5),
                (6, v6),
                (7, v7),
            ] {
                let m = mask.simd_eq(needle_simd).to_bitmask();
                if m != 0 {
                    return Some(base + p * SIMD_LANES + m.trailing_zeros() as usize);
                }
            }
        }
        cur = &cur[SIMD_FOLD_BYTES..];
    }
    cur.iter()
        .position(|&b| b == needle)
        .map(|j| count - cur.len() + j)
}

/// OLD arm replica of the memrchr block loop (last match, 256B windows from the end).
fn memrchr_256_only(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    let hs = &haystack[..count];
    if count < SIMD_LANES {
        return hs.iter().rposition(|&b| b == needle);
    }
    let needle_simd = core::simd::Simd::<u8, SIMD_LANES>::splat(needle);
    let mut cur = hs;
    while cur.len() >= BLOCK_256 {
        let block_start = cur.len() - BLOCK_256;
        let mut any = false;
        let mut best: Option<usize> = None;
        for p in (0..8).rev() {
            let v = core::simd::Simd::<u8, SIMD_LANES>::from_slice(
                &cur[block_start + p * SIMD_LANES..block_start + (p + 1) * SIMD_LANES],
            );
            let m = v.simd_eq(needle_simd).to_bitmask();
            if m != 0 && !any {
                best =
                    Some(block_start + p * SIMD_LANES + 31 - (m as u32).leading_zeros() as usize);
                any = true;
            }
        }
        if let Some(j) = best {
            return Some(j);
        }
        cur = &cur[..block_start];
    }
    cur.iter().rposition(|&b| b == needle)
}

struct Case {
    label: &'static str,
    sizes: &'static [usize],
    /// Fraction of positions equal to the needle (0.0 = absent).
    density: f64,
    /// Force the needle at / near the far end of the scan.
    tail_match: bool,
}

fn fill(buf: &mut [u8], needle: u8, density: f64, tail_match: bool, seed: &mut u64) {
    // xorshift64* — deterministic, no external rng dependency.
    let mut next = move || {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        *seed
    };
    for b in buf.iter_mut() {
        *b = (next() & 0xFF) as u8;
        if *b == needle {
            *b = b'^'; // avoid accidental matches at density 0
        }
    }
    let stride = (1.0 / density).max(1.0) as usize;
    if density > 0.0 {
        let mut i = 0usize;
        while i < buf.len() {
            buf[i] = needle;
            i += stride;
        }
    }
    if tail_match {
        let at = buf.len() - 1 - (next() as usize % 64).min(buf.len() - 1);
        buf[at] = needle;
    }
}

fn time_arm(f: MemchrFn, buf: &[u8], needle: u8, iters: usize) -> f64 {
    // Warm-up.
    for _ in 0..iters / 10 {
        black_box(f(black_box(buf), needle, buf.len()));
    }
    let mut samples = Vec::with_capacity(31);
    for _ in 0..31 {
        let t = Instant::now();
        for _ in 0..iters {
            black_box(f(black_box(buf), needle, buf.len()));
        }
        samples.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn main() {
    let mut seed: u64 = 0x9E3779B97F4A7C15;
    let cases = [
        Case {
            label: "absent",
            sizes: &[256, 512, 4096, 16384, 65536, 262144],
            density: 0.0,
            tail_match: false,
        },
        Case {
            label: "tail",
            sizes: &[256, 512, 4096, 16384, 65536, 262144],
            density: 0.0,
            tail_match: true,
        },
        Case {
            label: "d1/64",
            sizes: &[256, 512, 4096, 16384, 65536, 262144],
            density: 1.0 / 64.0,
            tail_match: false,
        },
    ];
    let needle = b'X';

    println!("memchr_fold512_ab (bd-sjvs5n): deployed(tier) vs 256B-only replica, same process");
    println!("byte-identity asserted on every case before timing");
    let mut worst_fwd = f64::INFINITY;
    let mut worst_rev = f64::INFINITY;
    for case in &cases {
        let max = case.sizes.iter().copied().max().unwrap();
        let mut buf = vec![0u8; max];
        for &n in case.sizes {
            fill(
                &mut buf[..n],
                needle,
                case.density,
                case.tail_match,
                &mut seed,
            );
            let iters = (2_000_000 / n.max(1)).max(64);

            // Byte-identity across a shifted sweep (hit positions, not just presence).
            for off in 0..64usize {
                let a = memchr(&buf[off..n], needle, n - off);
                let b = memchr_256_only(&buf[off..n], needle, n - off);
                assert_eq!(a, b, "memchr divergence at n={n} off={off}");
                let a = memrchr(&buf[off..n], needle, n - off);
                let b = memrchr_256_only(&buf[off..n], needle, n - off);
                assert_eq!(a, b, "memrchr divergence at n={n} off={off}");
            }

            let new_fwd = time_arm(memchr, &buf[..n], needle, iters);
            let old_fwd = time_arm(memchr_256_only, &buf[..n], needle, iters);
            let new_rev = time_arm(memrchr, &buf[..n], needle, iters);
            let old_rev = time_arm(memrchr_256_only, &buf[..n], needle, iters);
            let rf = new_fwd / old_fwd;
            let rr = new_rev / old_rev;
            println!(
                "{:>6} n={:>6}: memchr new {:>8.1}ns old {:>8.1}ns ratio {:0.3} | memrchr new {:>8.1}ns old {:>8.1}ns ratio {:0.3}",
                case.label, n, new_fwd, old_fwd, rf, new_rev, old_rev, rr
            );
            if n >= 4096 {
                worst_fwd = worst_fwd.min(rf);
                worst_rev = worst_rev.min(rr);
            }
        }
    }
    println!(
        "VERDICT n>=4096 worst ratio: memchr {worst_fwd:0.3} memrchr {worst_rev:0.3} (deployed/replica; <1.0 = tier wins)"
    );
}
