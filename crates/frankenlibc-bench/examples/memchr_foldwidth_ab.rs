//! In-process A/B for the memchr skip-loop: OLD Simd<u8,64> fold (512-bit, emulated on AVX2)
//! vs NEW Simd<u8,32> fold (native AVX2), both 256B/iter, over an absent-needle buffer.
//! Ratio cancels worker. Answers: is the 512-bit-lane fold the memchr per-byte bottleneck?
#![feature(portable_simd)]
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
// OLD: 256B fold via Simd<u8,64> panels (4 per block) — mirrors has_byte_memchr_folded.
fn scan64(hs: &[u8], needle: u8) -> Option<usize> {
    let n = hs.len();
    let nd = Simd::<u8, 64>::splat(needle);
    let mut base = 0;
    while n - base >= 256 {
        let p0 = Simd::<u8, 64>::from_slice(&hs[base..base + 64]).simd_eq(nd);
        let p1 = Simd::<u8, 64>::from_slice(&hs[base + 64..base + 128]).simd_eq(nd);
        let p2 = Simd::<u8, 64>::from_slice(&hs[base + 128..base + 192]).simd_eq(nd);
        let p3 = Simd::<u8, 64>::from_slice(&hs[base + 192..base + 256]).simd_eq(nd);
        if (p0 | p1 | p2 | p3).any() {
            for j in base..base + 256 {
                if hs[j] == needle {
                    return Some(j);
                }
            }
        }
        base += 256;
    }
    hs[base..]
        .iter()
        .position(|&b| b == needle)
        .map(|j| base + j)
}
// NEW: 256B fold via Simd<u8,32> panels (8 per block) — native AVX2 width.
fn scan32(hs: &[u8], needle: u8) -> Option<usize> {
    let n = hs.len();
    let nd = Simd::<u8, 32>::splat(needle);
    let mut base = 0;
    while n - base >= 256 {
        let mut acc = Simd::<u8, 32>::splat(0).simd_ne(Simd::splat(0)); // all-false mask
        let mut o = base;
        while o < base + 256 {
            acc |= Simd::<u8, 32>::from_slice(&hs[o..o + 32]).simd_eq(nd);
            o += 32;
        }
        if acc.any() {
            for j in base..base + 256 {
                if hs[j] == needle {
                    return Some(j);
                }
            }
        }
        base += 256;
    }
    hs[base..]
        .iter()
        .position(|&b| b == needle)
        .map(|j| base + j)
}
fn main() {
    for &n in &[1024usize, 4096, 16384] {
        let hs = vec![b'a'; n];
        let needle = b'z';
        assert_eq!(scan64(&hs, needle), scan32(&hs, needle), "mismatch n={n}");
        let iters = 300_000u64;
        let (mut ov, mut nv) = (Vec::new(), Vec::new());
        for r in 0..60 {
            let o = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(scan64(black_box(&hs), needle));
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            let nw = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(scan32(black_box(&hs), needle));
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            if r % 2 == 0 {
                ov.push(o());
                nv.push(nw());
            } else {
                nv.push(nw());
                ov.push(o());
            }
        }
        let (o, nn) = (pctl(&ov, 0.1), pctl(&nv, 0.1));
        println!(
            "memchr-fold n={n:<6} OLD(simd64)={o:7.1}ns NEW(simd32)={nn:7.1}ns  new/old={:.3} ({:.2}x)",
            nn / o,
            o / nn
        );
    }
}
