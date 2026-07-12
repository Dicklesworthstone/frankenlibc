//! In-process A/B: wide_fused_copy (wcscpy/wcpcpy strict hot path) 8-lane loop (CURRENT)
//! vs a 128B (4x8-lane) tier that min-reduces the NUL check and bulk-stores 128B when
//! clean, dropping to the 8-lane scan only on the chunk with the NUL. Byte-identity asserted.
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

// CURRENT: exact copy of deployed wide_fused_copy (8-lane / 32B per iter).
unsafe fn fused8(dst: *mut u32, src: *const u32) -> usize {
    let z = Simd::<u32, 8>::splat(0);
    let pb = src as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { src.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        let nul = m0.trailing_zeros() as usize - align;
        for j in 0..=nul {
            unsafe { *dst.add(j) = *src.add(j) };
        }
        return nul;
    }
    let first = 8 - align;
    for j in 0..first {
        unsafe { *dst.add(j) = *src.add(j) };
    }
    let mut i = first;
    loop {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 {
            let nul = m.trailing_zeros() as usize;
            for j in 0..=nul {
                unsafe { *dst.add(i + j) = *src.add(i + j) };
            }
            return i + nul;
        }
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
}

// NEW: 128B (4x8-lane) tier above the 8-lane loop. Same align peel + first partial chunk.
unsafe fn fused32(dst: *mut u32, src: *const u32) -> usize {
    let z = Simd::<u32, 8>::splat(0);
    let pb = src as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { src.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        let nul = m0.trailing_zeros() as usize - align;
        for j in 0..=nul {
            unsafe { *dst.add(j) = *src.add(j) };
        }
        return nul;
    }
    let first = 8 - align;
    for j in 0..first {
        unsafe { *dst.add(j) = *src.add(j) };
    }
    let mut i = first; // src+i is 32B aligned
    // Prologue: 2 plain 8-lane chunks. Very short strings (<= ~24 wchars) hit their NUL
    // here and return before any 128B read, so the wide tier never over-reads a short
    // string's tail. Long strings pay 2 trivial iters then reap the 128B win. No counter
    // in the hot loop (that regressed mid-sizes). Each 32B read is 32-aligned => page-safe.
    for _ in 0..2 {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 {
            let nul = m.trailing_zeros() as usize;
            for j in 0..=nul {
                unsafe { *dst.add(i + j) = *src.add(i + j) };
            }
            return i + nul;
        }
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
    loop {
        // 128B tier, page-guarded: 4 chunks/iter, only when reading 128B ahead stays
        // in-page. min-reduce all four; a 0 in any lane -> a NUL somewhere in 128B.
        while (unsafe { src.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
            let c0 =
                Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
            let c1 = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + 8), 8)
            });
            let c2 = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + 16), 8)
            });
            let c3 = Simd::<u32, 8>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i + 24), 8)
            });
            if c0.simd_min(c1).simd_min(c2.simd_min(c3)).simd_eq(z).any() {
                for (k, c) in [c0, c1, c2, c3].iter().enumerate() {
                    let m = c.simd_eq(z).to_bitmask();
                    if m != 0 {
                        let nul = m.trailing_zeros() as usize;
                        let off = i + k * 8;
                        for j in 0..=nul {
                            unsafe { *dst.add(off + j) = *src.add(off + j) };
                        }
                        return off + nul;
                    }
                    c.copy_to_slice(unsafe {
                        std::slice::from_raw_parts_mut(dst.add(i + k * 8), 8)
                    });
                }
                unreachable!();
            }
            c0.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
            c1.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 8), 8) });
            c2.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 16), 8) });
            c3.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i + 24), 8) });
            i += 32;
        }
        // 8-lane step: 32-aligned 32B read never crosses a page. Advances i by 8 (keeps
        // 32-alignment); after enough steps we re-enter a page where the 128B tier is safe.
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 {
            let nul = m.trailing_zeros() as usize;
            for j in 0..=nul {
                unsafe { *dst.add(i + j) = *src.add(i + j) };
            }
            return i + nul;
        }
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
}

fn main() {
    for &n in &[16usize, 64, 256, 1024, 4096] {
        let src: Vec<u32> = (0..n as u32)
            .map(|x| b'a' as u32 + (x % 26))
            .chain(std::iter::once(0))
            .collect();
        let sp = src.as_ptr();
        let mut d1 = vec![0u32; n + 8];
        let mut d2 = vec![0u32; n + 8];
        let r1 = unsafe { fused8(d1.as_mut_ptr(), sp) };
        let r2 = unsafe { fused32(d2.as_mut_ptr(), sp) };
        assert_eq!(r1, n, "len8 n={n}");
        assert_eq!(r2, n, "len32 n={n}");
        assert_eq!(&d1[..=n], &d2[..=n], "data n={n}");
        let iters = 300_000u64;
        let (mut ov, mut nv) = (Vec::new(), Vec::new());
        let p1 = d1.as_mut_ptr();
        let p2 = d2.as_mut_ptr();
        for r in 0..60 {
            let o = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fused8(black_box(p1), black_box(sp)) });
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            let nw = || {
                let t = Instant::now();
                for _ in 0..iters {
                    black_box(unsafe { fused32(black_box(p2), black_box(sp)) });
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
            "wfused n={n:<5} 8lane={o:7.2}ns 128B={nn:7.2}ns  new/old={:.3} ({:.2}x)",
            nn / o,
            o / nn
        );
    }
}
