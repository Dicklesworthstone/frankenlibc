//! In-process A/B: swab 32B/iter swizzle (current) vs 128B-unrolled (4x). Byte-identity
//! asserted. swab swaps adjacent byte pairs. Does unrolling the swizzle loop help throughput?
#![feature(portable_simd)]
use std::hint::black_box;
use std::simd::Simd;
use std::simd::simd_swizzle;
use std::time::Instant;
fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}
const SW: [usize; 32] = [
    1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14, 17, 16, 19, 18, 21, 20, 23, 22, 25, 24,
    27, 26, 29, 28, 31, 30,
];
fn swab32(src: &[u8], dst: &mut [u8], n: usize) {
    let bytes = (n.min(src.len()).min(dst.len()) / 2) * 2;
    let mut i = 0;
    while i + 32 <= bytes {
        let v = Simd::<u8, 32>::from_slice(&src[i..i + 32]);
        simd_swizzle!(v, SW).copy_to_slice(&mut dst[i..i + 32]);
        i += 32;
    }
    while i < bytes {
        dst[i] = src[i + 1];
        dst[i + 1] = src[i];
        i += 2;
    }
}
fn swab128(src: &[u8], dst: &mut [u8], n: usize) {
    let bytes = (n.min(src.len()).min(dst.len()) / 2) * 2;
    let mut i = 0;
    while i + 128 <= bytes {
        for k in 0..4 {
            let o = i + k * 32;
            let v = Simd::<u8, 32>::from_slice(&src[o..o + 32]);
            simd_swizzle!(v, SW).copy_to_slice(&mut dst[o..o + 32]);
        }
        i += 128;
    }
    while i + 32 <= bytes {
        let v = Simd::<u8, 32>::from_slice(&src[i..i + 32]);
        simd_swizzle!(v, SW).copy_to_slice(&mut dst[i..i + 32]);
        i += 32;
    }
    while i < bytes {
        dst[i] = src[i + 1];
        dst[i + 1] = src[i];
        i += 2;
    }
}
fn main() {
    for &n in &[256usize, 1024, 4096, 16384] {
        let src: Vec<u8> = (0..n).map(|x| (x * 7 + 1) as u8).collect();
        let mut d1 = vec![0u8; n];
        let mut d2 = vec![0u8; n];
        swab32(&src, &mut d1, n);
        swab128(&src, &mut d2, n);
        assert_eq!(d1, d2, "mismatch n={n}");
        let iters = 400_000u64;
        let (mut ov, mut nv) = (Vec::new(), Vec::new());
        for r in 0..60 {
            let o = || {
                let mut d = vec![0u8; n];
                let t = Instant::now();
                for _ in 0..iters {
                    swab32(black_box(&src), black_box(&mut d), n);
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            let nw = || {
                let mut d = vec![0u8; n];
                let t = Instant::now();
                for _ in 0..iters {
                    swab128(black_box(&src), black_box(&mut d), n);
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
            "swab n={n:<6} 32B={o:7.1}ns 128B={nn:7.1}ns  128/32={:.3} ({:.2}x)",
            nn / o,
            o / nn
        );
    }
}
