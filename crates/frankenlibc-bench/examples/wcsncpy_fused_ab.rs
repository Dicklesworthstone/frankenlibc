//! In-process A/B for wcsncpy's strict body: two-pass (bounded NUL scan, then 128B-tier
//! copy, then NUL-pad) vs a fused single-pass (scan+copy+128B tier in one walk, then pad).
//! Baseline uses a 128B copy so the A/B isolates the FUSION benefit (one read vs two), not
//! just copy width. Byte-identity asserted. Covers exact-fill (len>=n) and padded (len<n).
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

// Bounded NUL scan: returns index of first NUL in [0,n) or n if none. 128B-tier, page-safe.
#[inline]
unsafe fn scan_n(src: *const u32, n: usize) -> usize {
    let z = Simd::<u32, 8>::splat(0);
    let mut i = 0;
    while i + 32 <= n && (unsafe { src.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
        let c0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let c1 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 8), 8) });
        let c2 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 16), 8) });
        let c3 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 24), 8) });
        if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any() {
            for (k, c) in [c0, c1, c2, c3].iter().enumerate() {
                let m = c.simd_eq(z).to_bitmask();
                if m != 0 {
                    return i + k * 8 + m.trailing_zeros() as usize;
                }
            }
        }
        i += 32;
    }
    while i < n {
        if unsafe { *src.add(i) } == 0 {
            return i;
        }
        i += 1;
    }
    n
}
// 128B-tier forward copy of `count` elements (disjoint).
#[inline]
unsafe fn copy_n(dst: *mut u32, src: *const u32, count: usize) {
    let mut i = 0;
    while i + 32 <= count {
        for k in 0..4 {
            let v = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + k * 8), 8)
            });
            v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + k * 8), 8) });
        }
        i += 32;
    }
    while i + 8 <= count {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
    while i < count {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
}

// TWO-PASS (mimics deployed strict wcsncpy with a fair 128B copy).
unsafe fn two_pass(dst: *mut u32, src: *const u32, n: usize) {
    let len = unsafe { scan_n(src, n) };
    let copy = (len + 1).min(n);
    unsafe { copy_n(dst, src, copy) };
    if copy < n {
        for j in copy..n {
            unsafe { *dst.add(j) = 0 };
        }
    }
}
// 8-lane copy (mimics deployed wide_copy_n for count<1024).
#[inline]
unsafe fn copy_n_8lane(dst: *mut u32, src: *const u32, count: usize) {
    let mut i = 0;
    while i + 8 <= count {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
    while i < count {
        unsafe { *dst.add(i) = *src.add(i) };
        i += 1;
    }
}
// OLD DEPLOYED two-pass: bounded scan + 8-lane copy + pad (what shipped before this change).
unsafe fn two_pass_8lane(dst: *mut u32, src: *const u32, n: usize) {
    let len = unsafe { scan_n(src, n) };
    let copy = (len + 1).min(n);
    unsafe { copy_n_8lane(dst, src, copy) };
    if copy < n {
        for j in copy..n {
            unsafe { *dst.add(j) = 0 };
        }
    }
}

// FUSED single-pass: scan+copy together, 128B tier, stop at NUL(copy through it) or n, then pad.
unsafe fn fused(dst: *mut u32, src: *const u32, n: usize) {
    let z = Simd::<u32, 8>::splat(0);
    let mut i = 0;
    // 128B tier
    while i + 32 <= n && (unsafe { src.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
        let c0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let c1 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 8), 8) });
        let c2 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 16), 8) });
        let c3 =
            Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i + 24), 8) });
        if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any() {
            for (k, c) in [c0, c1, c2, c3].iter().enumerate() {
                let m = c.simd_eq(z).to_bitmask();
                if m != 0 {
                    let nul = i + k * 8 + m.trailing_zeros() as usize;
                    for j in i + k * 8..=nul {
                        unsafe { *dst.add(j) = *src.add(j) };
                    }
                    for j in nul + 1..n {
                        unsafe { *dst.add(j) = 0 };
                    }
                    return;
                }
                c.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + k * 8), 8) });
            }
        }
        c0.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        c1.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 8), 8) });
        c2.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 16), 8) });
        c3.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 24), 8) });
        i += 32;
    }
    // 8-lane / scalar tail
    while i < n {
        let c = unsafe { *src.add(i) };
        if c == 0 {
            for j in i..n {
                unsafe { *dst.add(j) = 0 };
            }
            return;
        }
        unsafe { *dst.add(i) = c };
        i += 1;
    }
}

fn main() {
    for &(n, slen) in &[
        (16usize, 16usize),
        (64, 64),
        (256, 256),
        (1024, 1024),
        (4096, 4096),
        (64, 40),
        (256, 200),
        (1024, 900),
    ] {
        // src: slen non-zero chars then NUL (if slen<n) else n chars (NUL at n).
        let mut src: Vec<u32> = (0..(slen.max(n) + 8) as u32)
            .map(|x| b'a' as u32 + (x % 26))
            .collect();
        if slen < src.len() {
            src[slen] = 0;
        }
        let sp = src.as_ptr();
        let mut d1 = vec![7u32; n + 8];
        let mut d2 = vec![7u32; n + 8];
        let mut d3 = vec![7u32; n + 8];
        unsafe {
            two_pass_8lane(d1.as_mut_ptr(), sp, n);
            fused(d2.as_mut_ptr(), sp, n);
            two_pass(d3.as_mut_ptr(), sp, n);
        }
        assert_eq!(&d1[..n], &d2[..n], "data n={n} slen={slen}");
        assert_eq!(&d1[..n], &d3[..n], "data2 n={n}");
        let iters = 300_000u64;
        let (mut ov, mut nv) = (Vec::new(), Vec::new());
        let p1 = d1.as_mut_ptr();
        let p2 = d2.as_mut_ptr();
        for r in 0..60 {
            // OLD deployed = 8-lane two-pass (the arm that actually shipped before this change).
            let o = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { two_pass_8lane(black_box(p1), black_box(sp), n) });
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            let nw = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fused(black_box(p2), black_box(sp), n) });
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
        eprintln!(
            "wcsncpy n={n:<5} slen={slen:<5} OLD(8lane2pass)={o:7.2}ns fused={nn:7.2}ns  fused/old={:.3} ({:.2}x)",
            nn / o,
            o / nn
        );
    }
}
