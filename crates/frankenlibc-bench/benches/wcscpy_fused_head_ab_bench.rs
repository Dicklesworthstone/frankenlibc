//! wcscpy A/B/C in one process (worker variance cancels in new/old). The deployed
//! strict path is TWO passes: scan_w_string (SIMD wcslen) + copy_nonoverlapping (which
//! lowers to the interposed fl `memcpy` symbol — ABI entry + membrane per call). glibc
//! fuses scan+copy into ONE pass. This measures a fused single-pass SIMD copy.
//!
//! ARM A (old) = scan (wcslen) + copy_nonoverlapping (the deployed shape, replicated).
//! ARM B (new) = fused: aligned-head-mask read + 8-lane SIMD store of full chunks +
//!               scalar tail up to and including the NUL. No memcpy call. One pass.
//! ARM C       = host glibc wcscpy via dlmopen.
#![feature(portable_simd)]
use std::simd::prelude::*;
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type CpyFn = unsafe extern "C" fn(*mut u32, *const u32) -> *mut u32;
fn host() -> CpyFn {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); libc::dlsym(h, b"wcscpy\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, CpyFn>(a) }
}

/// OLD: SIMD wcslen scan + copy_nonoverlapping (the interposed memcpy).
#[inline]
unsafe fn old_wcscpy(dst: *mut u32, src: *const u32) {
    let len = wide_len(src);
    unsafe { std::ptr::copy_nonoverlapping(src, dst, len + 1); }
}

#[inline]
unsafe fn wide_len(s: *const u32) -> usize {
    let z = Simd::<u32, 8>::splat(0);
    let pb = s as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { s.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 { return m0.trailing_zeros() as usize - align; }
    let mut i = 8 - align;
    loop {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 { return i + m.trailing_zeros() as usize; }
        i += 8;
    }
}

/// NEW: fused single-pass. Aligned-head-mask read (page-safe), 8-lane SIMD store for
/// full NUL-free chunks, scalar tail copies up to and including the NUL. No memcpy call.
#[inline]
unsafe fn new_wcscpy(dst: *mut u32, src: *const u32) {
    let z = Simd::<u32, 8>::splat(0);
    let pb = src as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { src.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        let nul = m0.trailing_zeros() as usize - align;
        for j in 0..=nul { unsafe { *dst.add(j) = *src.add(j); } }
        return;
    }
    // First (partial) chunk: elements [src, base+8) = (8-align) elements, all non-NUL.
    let first = 8 - align;
    for j in 0..first { unsafe { *dst.add(j) = *src.add(j); } }
    let mut i = first; // src+i is 32-byte aligned
    loop {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(src.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 {
            let nul = m.trailing_zeros() as usize;
            for j in 0..=nul { unsafe { *dst.add(i + j) = *src.add(i + j); } }
            return;
        }
        // No NUL: SIMD-store the full 8-lane chunk.
        v.copy_to_slice(unsafe { std::slice::from_raw_parts_mut(dst.add(i), 8) });
        i += 8;
    }
}

fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("wcscpy_fused"); grp.sample_size(10);
    let it = 4000u64;
    for &n in &[4usize, 16, 32, 64, 128, 256, 1024] {
        let mut src: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); src.push(0);
        let sp = src.as_ptr();
        let (mut a, mut b, mut cc) = (vec![0u32; n + 8], vec![0u32; n + 8], vec![0u32; n + 8]);
        unsafe { old_wcscpy(a.as_mut_ptr(), sp); new_wcscpy(b.as_mut_ptr(), sp); g(cc.as_mut_ptr(), sp); }
        assert_eq!(a[..=n], b[..=n], "new n={n}"); assert_eq!(a[..=n], cc[..=n], "glibc n={n}");
        let (mut os, mut ns, mut gs) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { unsafe { old_wcscpy(black_box(a.as_mut_ptr()), black_box(sp)); } } os.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { unsafe { new_wcscpy(black_box(b.as_mut_ptr()), black_box(sp)); } } ns.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g(black_box(cc.as_mut_ptr()), black_box(sp)) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (op,np,gp)=(pctl(&os,0.5),pctl(&ns,0.5),pctl(&gs,0.5));
        println!("WCSCPY_FUSED n={n} old={op:.2} new={np:.2} glibc={gp:.2} new/old={:.3} new/glibc={:.3} old/glibc={:.3}", np/op, np/gp, op/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
