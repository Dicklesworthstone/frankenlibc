//! Same-process A/B for the wcscpy copy kernel: OLD (2-pass: SIMD wcslen then
//! bulk copy) vs NEW (fused 1-pass: copy-while-scanning-for-NUL, 8×u32 panels) vs
//! host glibc `wcscpy`. All kernels reimplemented in-bench (no fl abi linkage) so
//! the rch worker rlib cache cannot serve a stale binary — only within-process
//! ratios are used. Reliable, unlike deployed-abi timing.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench wcscpy_fused_ab_bench`

#![feature(portable_simd)]

use std::ffi::c_void;
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;

use criterion::{Criterion, criterion_group, criterion_main};

unsafe extern "C" {
    fn wcscpy(dst: *mut c_void, src: *const c_void) -> *mut c_void;
}

const LANES: usize = 8; // 8 × u32 = 32 bytes

/// SIMD wide strlen (page-safe 8-lane scan), the scan half of the 2-pass kernel.
#[inline]
unsafe fn wcslen_simd(src: *const u32) -> usize {
    let mut i = 0usize;
    let zero = Simd::<u32, LANES>::splat(0);
    loop {
        if (src as usize + i * 4) & 0xFFF <= 0x1000 - 32 {
            let v = Simd::<u32, LANES>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i), LANES)
            });
            let m = v.simd_eq(zero).to_bitmask();
            if m == 0 {
                i += LANES;
                continue;
            }
            return i + m.trailing_zeros() as usize;
        }
        if unsafe { *src.add(i) } == 0 {
            return i;
        }
        i += 1;
    }
}

/// OLD: 2-pass — SIMD wcslen, then bulk copy of len+1 (through the NUL).
unsafe fn wcscpy_2pass(dst: *mut u32, src: *const u32) {
    let len = unsafe { wcslen_simd(src) };
    unsafe { std::ptr::copy_nonoverlapping(src, dst, len + 1) };
}

/// NEW: fused 1-pass — load an 8×u32 panel, copy it, and stop at the NUL lane.
/// One pass over the source (vs two), matching glibc's __wcscpy_avx2 shape.
unsafe fn wcscpy_fused(dst: *mut u32, src: *const u32) {
    let mut i = 0usize;
    let zero = Simd::<u32, LANES>::splat(0);
    loop {
        if (src as usize + i * 4) & 0xFFF <= 0x1000 - 32
            && (dst as usize + i * 4) & 0xFFF <= 0x1000 - 32
        {
            let v = Simd::<u32, LANES>::from_slice(unsafe {
                std::slice::from_raw_parts(src.add(i), LANES)
            });
            let m = v.simd_eq(zero).to_bitmask();
            if m == 0 {
                // No NUL in this panel: store all 8 and advance.
                v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), LANES) });
                i += LANES;
                continue;
            }
            // NUL at lane k: copy lanes 0..=k (through the terminator) and finish.
            let k = m.trailing_zeros() as usize;
            for j in 0..=k {
                unsafe { *dst.add(i + j) = *src.add(i + j) };
            }
            return;
        }
        // Page-boundary scalar tail.
        let ch = unsafe { *src.add(i) };
        unsafe { *dst.add(i) = ch };
        if ch == 0 {
            return;
        }
        i += 1;
    }
}

fn wstr(n: usize) -> Vec<u32> {
    let mut v = vec![b'a' as u32; n];
    v.push(0);
    v
}

fn bench(c: &mut Criterion) {
    for &n in &[3usize, 8, 16, 32, 64, 128] {
        let src = wstr(n);
        let ps = src.as_ptr();
        let mut d_old = vec![0u32; n + 8];
        let mut d_new = vec![0u32; n + 8];
        let mut d_g = vec![0u32; n + 8];
        unsafe { wcscpy_2pass(d_old.as_mut_ptr(), ps) };
        unsafe { wcscpy_fused(d_new.as_mut_ptr(), ps) };
        unsafe { wcscpy(d_g.as_mut_ptr().cast(), ps.cast()) };
        assert_eq!(d_old[..=n], d_new[..=n], "2pass vs fused n={n}");
        assert_eq!(d_old[..=n], d_g[..=n], "2pass vs glibc n={n}");

        let po = d_old.as_mut_ptr();
        let pn = d_new.as_mut_ptr();
        let pg = d_g.as_mut_ptr();
        let mut grp = c.benchmark_group(format!("wcscpy_{n}"));
        grp.bench_function("old_2pass", |b| {
            b.iter(|| black_box(unsafe { wcscpy_2pass(black_box(po), black_box(ps)) }))
        });
        grp.bench_function("new_fused", |b| {
            b.iter(|| black_box(unsafe { wcscpy_fused(black_box(pn), black_box(ps)) }))
        });
        grp.bench_function("host_glibc", |b| {
            b.iter(|| black_box(unsafe { wcscpy(black_box(pg.cast()), black_box(ps.cast())) }))
        });
        grp.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
