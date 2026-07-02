//! wcschr find-or-nul head A/B/C, all in one process (worker variance cancels in
//! new/old). The DEPLOYED strict path is `wide_find_or_nul_simd` — a scalar
//! element-by-element head loop (up to 7 iters to reach 32-byte alignment) + an
//! i>=32 folded-128 tier. glibc reaches its aligned SIMD body immediately via an
//! aligned-load-down + head-mask. This ports that head trick (used for narrow
//! strchr in 847363e6e) to the wide finder and measures whether it closes the gap.
//!
//! ARM A (old) = deployed `bench_wide_find_or_nul_simd` (scalar head).
//! ARM B (new) = local copy with aligned-load-down + head-mask, same fold body.
//! ARM C       = host glibc wcschr via dlmopen.
//! Search char is absent (all 'a', NUL at n) so every arm scans the full string.
#![feature(portable_simd)]
use std::simd::prelude::*;
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type Fn_ = unsafe extern "C" fn(*const u32, u32) -> *const u32;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); libc::dlsym(h, b"wcschr\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, Fn_>(a) }
}

const LANES: usize = 8;

/// NEW: aligned-load-down + head-mask, then the same i>=32 folded-128 tier.
#[inline]
unsafe fn new_scan(s: *const u32, c: u32) -> (usize, bool) {
    let cv = Simd::<u32, LANES>::splat(c);
    let zv = Simd::<u32, LANES>::splat(0);
    let pb = s as usize;
    let align = (pb & 31) >> 2; // elements before the 32-byte boundary (0..=7)
    // SAFETY: base is aligned down <=28 bytes, same mapped page as s.
    let base = unsafe { s.sub(align) };
    let v0 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(base.cast::<[u32; LANES]>()) });
    let m0 = (v0.simd_eq(cv) | v0.simd_eq(zv)).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        let pos = m0.trailing_zeros() as usize; // lane within base window
        let is_c = unsafe { *base.add(pos) } == c;
        return (pos - align, is_c);
    }
    let mut i = LANES - align; // s+i is 32-byte aligned
    loop {
        if i >= 32 && ((s as usize) + i * 4) & 0xFFF <= 0x1000 - 128 {
            let b = unsafe { s.add(i) };
            let x0 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.cast::<[u32; LANES]>()) });
            let x1 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.add(LANES).cast::<[u32; LANES]>()) });
            let x2 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.add(2 * LANES).cast::<[u32; LANES]>()) });
            let x3 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.add(3 * LANES).cast::<[u32; LANES]>()) });
            let any = (x0.simd_eq(cv) | x0.simd_eq(zv)) | (x1.simd_eq(cv) | x1.simd_eq(zv))
                | (x2.simd_eq(cv) | x2.simd_eq(zv)) | (x3.simd_eq(cv) | x3.simd_eq(zv));
            if !any.any() { i += 4 * LANES; continue; }
        }
        let words = unsafe { core::ptr::read(s.add(i).cast::<[u32; LANES]>()) };
        let v = Simd::<u32, LANES>::from_array(words);
        if (v.simd_eq(cv) | v.simd_eq(zv)).any() {
            for j in 0..LANES {
                let ch = unsafe { *s.add(i + j) };
                if ch == c { return (i + j, true); }
                if ch == 0 { return (i + j, false); }
            }
        }
        i += LANES;
    }
}

/// NEW2: aligned-down head + min-combine c-or-NUL fold. `min(v^c, v)` has a zero lane
/// iff v==c (v^c==0) or v==0, so 4 vectors collapse to one `.simd_eq(0)` reduction —
/// the wcslen-style kernel that ties glibc, extended to the two-target wcschr search.
#[inline]
unsafe fn new2_scan(s: *const u32, c: u32) -> (usize, bool) {
    use std::simd::cmp::SimdOrd;
    let cv = Simd::<u32, LANES>::splat(c);
    let zv = Simd::<u32, LANES>::splat(0);
    let pb = s as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { s.sub(align) };
    let v0 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(base.cast::<[u32; LANES]>()) });
    let m0 = ((v0 ^ cv).simd_min(v0)).simd_eq(zv).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 {
        let pos = m0.trailing_zeros() as usize;
        let is_c = unsafe { *base.add(pos) } == c;
        return (pos - align, is_c);
    }
    let mut i = LANES - align;
    loop {
        if i >= 32 && (pb + i * 4) & 0xFFF <= 0x1000 - 128 {
            let b = unsafe { s.add(i) };
            let x0 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.cast::<[u32; LANES]>()) });
            let x1 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.add(LANES).cast::<[u32; LANES]>()) });
            let x2 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.add(2 * LANES).cast::<[u32; LANES]>()) });
            let x3 = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(b.add(3 * LANES).cast::<[u32; LANES]>()) });
            let e0 = (x0 ^ cv).simd_min(x0);
            let e1 = (x1 ^ cv).simd_min(x1);
            let e2 = (x2 ^ cv).simd_min(x2);
            let e3 = (x3 ^ cv).simd_min(x3);
            if !e0.simd_min(e1).simd_min(e2.simd_min(e3)).simd_eq(zv).any() { i += 4 * LANES; continue; }
        }
        let v = Simd::<u32, LANES>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; LANES]>()) });
        if (v ^ cv).simd_min(v).simd_eq(zv).any() {
            for j in 0..LANES {
                let ch = unsafe { *s.add(i + j) };
                if ch == c { return (i + j, true); }
                if ch == 0 { return (i + j, false); }
            }
        }
        i += LANES;
    }
}

fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("wcschr_head"); grp.sample_size(10);
    let miss = b'X' as u32; // absent → full scan to NUL
    for &n in &[4usize, 8, 16, 32, 48, 64, 96, 128, 256, 1024] {
        let mut buf: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); buf.push(0);
        let p = buf.as_ptr();
        // Byte-identity: old==new find idx==n (not found); glibc returns null.
        let (oi, of) = unsafe { frankenlibc_abi::wchar_abi::bench_wide_find_or_nul_simd(p, miss) };
        let (ni, nf) = unsafe { new_scan(p, miss) };
        let (n2i, n2f) = unsafe { new2_scan(p, miss) };
        assert_eq!((oi, of), (n, false), "old n={n}");
        assert_eq!((ni, nf), (n, false), "new n={n}");
        assert_eq!((n2i, n2f), (n, false), "new2 n={n}");
        assert!(unsafe { g(p, miss) }.is_null(), "glibc n={n}");
        let it = 4000u64;
        let (mut os, mut ns, mut n2s, mut gs) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { frankenlibc_abi::wchar_abi::bench_wide_find_or_nul_simd(black_box(p), miss) }); } os.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { new_scan(black_box(p), miss) }); } ns.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { new2_scan(black_box(p), miss) }); } n2s.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g(black_box(p), miss) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (op,np,n2p,gp)=(pctl(&os,0.5),pctl(&ns,0.5),pctl(&n2s,0.5),pctl(&gs,0.5));
        println!("WCSCHR_HEAD n={n} old={op:.2} new={np:.2} new2={n2p:.2} glibc={gp:.2} new/old={:.3} new2/old={:.3} new2/glibc={:.3}", np/op, n2p/op, n2p/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
