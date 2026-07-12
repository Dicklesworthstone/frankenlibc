//! In-process A/B for the wmemchr XOR-min fold: 128B (4x Simd<u32,8>) vs 256B (8x) vs 512B
//! (16x). min(x^c) has a 0 lane iff a panel contains c. Wider = fewer branches; does it beat
//! the current 128B here? (memchr's OR-of-eq liked wider; XOR-min may differ + more registers.)
#![feature(portable_simd)]
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::{SimdOrd, SimdPartialEq};
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
const P: usize = 8; // Simd<u32,8> panel
fn scan(s: &[u32], c: u32, panels: usize) -> Option<usize> {
    let block = P * panels;
    let t = Simd::<u32, P>::splat(c);
    let z = Simd::<u32, P>::splat(0);
    let mut base = 0;
    while base + block <= s.len() {
        let mut folded = Simd::<u32, P>::from_slice(&s[base..base + P]);
        folded ^= t;
        for k in 1..panels {
            let p = Simd::<u32, P>::from_slice(&s[base + k * P..base + (k + 1) * P]) ^ t;
            folded = folded.simd_min(p);
        }
        if folded.simd_eq(z).any() {
            for j in base..base + block {
                if s[j] == c {
                    return Some(j);
                }
            }
        }
        base += block;
    }
    s[base..].iter().position(|&x| x == c).map(|j| base + j)
}
fn main() {
    for &n in &[64usize, 256, 1024, 4096, 16384] {
        let s: Vec<u32> = vec![b'a' as u32; n];
        let c = b'z' as u32;
        assert_eq!(scan(&s, c, 4), scan(&s, c, 8), "mismatch n={n}");
        assert_eq!(scan(&s, c, 4), scan(&s, c, 16), "m512 n={n}");
        let iters = 300_000u64;
        let (mut v4, mut v8, mut v16) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..50 {
            let t = Instant::now();
            for _ in 0..iters {
                black_box(scan(black_box(&s), c, 4));
            }
            v4.push(t.elapsed().as_nanos() as f64 / iters as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(scan(black_box(&s), c, 8));
            }
            v8.push(t.elapsed().as_nanos() as f64 / iters as f64);
            let t = Instant::now();
            for _ in 0..iters {
                black_box(scan(black_box(&s), c, 16));
            }
            v16.push(t.elapsed().as_nanos() as f64 / iters as f64);
        }
        let (a, b, d) = (pctl(&v4, 0.1), pctl(&v8, 0.1), pctl(&v16, 0.1));
        println!(
            "wmemchr-fold n={n:<6} 128B={a:6.1} 256B={b:6.1} 512B={d:6.1}  256/128={:.3} 512/128={:.3}",
            b / a,
            d / a
        );
    }
}
