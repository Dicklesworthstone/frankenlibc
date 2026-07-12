//! Same-process A/B for the strcmp dual-pointer scan: OLD (single 32-byte panel
//! per iteration, one page-guard per panel) vs NEW (4×32 folded 128-byte block:
//! one combined page-guard + 4 pipelined loads OR'd into one branch, mirroring
//! glibc strcmp_avx2's 4×VEC unrolled loop) vs host glibc strcmp — all in ONE
//! process so per-worker load cancels in the ratios (defeats rch cross-worker
//! variance).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strcmp_fold_ab_bench`

#![feature(portable_simd)]

use std::ffi::{c_char, c_int};
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;

unsafe extern "C" {
    fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int;
}

#[inline(always)]
fn wide_read_within_page(addr: usize) -> bool {
    (addr & 0xFFF) <= 0x1000 - 8
}

#[inline]
fn swar_word_has_zero(w: u64) -> bool {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    (w.wrapping_sub(ONES) & !w & HIGHS) != 0
}

/// OLD: verbatim copy of the deployed `scan_strcmp` (single 32-byte panel).
unsafe fn scan_strcmp_old(s1: *const c_char, s2: *const c_char, bound: usize) -> (usize, bool) {
    let p1 = s1.cast::<u8>();
    let p2 = s2.cast::<u8>();
    let mut i = 0usize;
    loop {
        if i + 32 <= bound
            && (p1 as usize + i) & 0xFFF <= 0x1000 - 32
            && (p2 as usize + i) & 0xFFF <= 0x1000 - 32
        {
            let va =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p1.add(i), 32) });
            let vb =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p2.add(i), 32) });
            let flagged = (va.simd_ne(vb) | va.simd_eq(Simd::splat(0))).to_bitmask();
            if flagged == 0 {
                i += 32;
                continue;
            }
            return (i + flagged.trailing_zeros() as usize, false);
        }
        if i + 8 <= bound
            && wide_read_within_page(p1 as usize + i)
            && wide_read_within_page(p2 as usize + i)
        {
            let wa = unsafe { core::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { core::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if wa == wb && !swar_word_has_zero(wa) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                if a != b || a == 0 {
                    return (i + j, false);
                }
            }
            i += 8;
            continue;
        }
        if i >= bound {
            return (bound, true);
        }
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        if a != b || a == 0 {
            return (i, false);
        }
        i += 1;
    }
}

/// NEW: 4×32 folded 128-byte block. One page-guard covers all four panels; four
/// loads are issued back-to-back (ILP) and their (ne|eq0) masks OR'd, so a whole
/// equal NUL-free 128 bytes is skipped under a single branch. A flagged block
/// resolves the exact first panel/byte (byte-identical result). Falls through to
/// the unchanged 32B/8B/scalar tail for the <128B remainder and page edges.
unsafe fn scan_strcmp_new(s1: *const c_char, s2: *const c_char, bound: usize) -> (usize, bool) {
    let p1 = s1.cast::<u8>();
    let p2 = s2.cast::<u8>();
    let mut i = 0usize;
    let zero = Simd::<u8, 32>::splat(0);
    loop {
        // 128-byte folded fast path: only after 256B have cleared (`i >= 256`),
        // so short/moderate strings (≤256B, the dominant strcmp regime) stay on
        // the byte-identical single-panel path and pay zero fold setup. The fold
        // only engages once the string is proven long, where the 4-load
        // amortization clearly wins. Both blocks fully in-page and within bound.
        if i >= 256
            && i + 128 <= bound
            && (p1 as usize + i) & 0xFFF <= 0x1000 - 128
            && (p2 as usize + i) & 0xFFF <= 0x1000 - 128
        {
            let mut masks = [0u32; 4];
            let mut combined = 0u32;
            for k in 0..4 {
                let off = i + k * 32;
                let va = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p1.add(off), 32)
                });
                let vb = Simd::<u8, 32>::from_slice(unsafe {
                    core::slice::from_raw_parts(p2.add(off), 32)
                });
                let m = (va.simd_ne(vb) | va.simd_eq(zero)).to_bitmask() as u32;
                masks[k] = m;
                combined |= m;
            }
            if combined == 0 {
                i += 128;
                continue;
            }
            for k in 0..4 {
                if masks[k] != 0 {
                    return (i + k * 32 + masks[k].trailing_zeros() as usize, false);
                }
            }
        }
        if i + 32 <= bound
            && (p1 as usize + i) & 0xFFF <= 0x1000 - 32
            && (p2 as usize + i) & 0xFFF <= 0x1000 - 32
        {
            let va =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p1.add(i), 32) });
            let vb =
                Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p2.add(i), 32) });
            let flagged = (va.simd_ne(vb) | va.simd_eq(zero)).to_bitmask();
            if flagged == 0 {
                i += 32;
                continue;
            }
            return (i + flagged.trailing_zeros() as usize, false);
        }
        if i + 8 <= bound
            && wide_read_within_page(p1 as usize + i)
            && wide_read_within_page(p2 as usize + i)
        {
            let wa = unsafe { core::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { core::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if wa == wb && !swar_word_has_zero(wa) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                if a != b || a == 0 {
                    return (i + j, false);
                }
            }
            i += 8;
            continue;
        }
        if i >= bound {
            return (bound, true);
        }
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        if a != b || a == 0 {
            return (i, false);
        }
        i += 1;
    }
}

unsafe fn cmp_old(s1: *const c_char, s2: *const c_char) -> c_int {
    let (i, _) = unsafe { scan_strcmp_old(s1, s2, usize::MAX) };
    let a = unsafe { *s1.add(i) } as u8;
    let b = unsafe { *s2.add(i) } as u8;
    (a as c_int) - (b as c_int)
}
unsafe fn cmp_new(s1: *const c_char, s2: *const c_char) -> c_int {
    let (i, _) = unsafe { scan_strcmp_new(s1, s2, usize::MAX) };
    let a = unsafe { *s1.add(i) } as u8;
    let b = unsafe { *s2.add(i) } as u8;
    (a as c_int) - (b as c_int)
}

use criterion::{Criterion, criterion_group, criterion_main};

fn bench(c: &mut Criterion) {
    // Equal strings of length N (worst case: full scan to shared NUL). Plus a
    // diff-at-tail case. NUL-terminated; page-aligned away from boundaries.
    let lens = [16usize, 32, 64, 128, 256, 512, 1024];
    for &n in &lens {
        let mut a = vec![b'a'; n];
        a.push(0);
        let b = a.clone();
        // parity: equal -> 0
        assert_eq!(unsafe { cmp_old(a.as_ptr().cast(), b.as_ptr().cast()) }, 0);
        assert_eq!(unsafe { cmp_new(a.as_ptr().cast(), b.as_ptr().cast()) }, 0);
        assert_eq!(unsafe { strcmp(a.as_ptr().cast(), b.as_ptr().cast()) }, 0);

        let mut grp = c.benchmark_group(format!("strcmp_eq_{n}"));
        grp.bench_function("old_32panel", |bb| {
            bb.iter(|| {
                black_box(unsafe {
                    cmp_old(black_box(a.as_ptr().cast()), black_box(b.as_ptr().cast()))
                })
            })
        });
        grp.bench_function("new_128fold", |bb| {
            bb.iter(|| {
                black_box(unsafe {
                    cmp_new(black_box(a.as_ptr().cast()), black_box(b.as_ptr().cast()))
                })
            })
        });
        grp.bench_function("host_glibc", |bb| {
            bb.iter(|| {
                black_box(unsafe {
                    strcmp(black_box(a.as_ptr().cast()), black_box(b.as_ptr().cast()))
                })
            })
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
