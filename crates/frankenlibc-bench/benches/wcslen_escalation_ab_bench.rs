//! wcslen escalation-threshold A/B/C, ALL in one process (worker variance cancels
//! in the old/new ratio — the durable technique from the printf/scanf campaign).
//!
//! ARM A = OLD unbounded scan: 8-lane tier escalates to the 128 B min-combine unroll
//!         only once `i>=64` (256 B) AND `s+i` is 128-aligned.
//! ARM B = NEW unbounded scan: escalate at the FIRST 128-byte boundary (drop the i>=64
//!         gate) so the 32..256-wchar medium band leaves the 32 B/iter tier sooner.
//! ARM C = host glibc wcslen via dlmopen (yardstick).
//!
//! new/old < 1.0 => the escalation change is a real per-worker speedup.
#![feature(portable_simd)]
use std::simd::prelude::*;
use std::sync::OnceLock;
use std::time::Instant;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

type Fn_ = unsafe extern "C" fn(*const u32) -> usize;
fn host() -> Fn_ {
    static H: OnceLock<usize> = OnceLock::new();
    let a = *H.get_or_init(|| unsafe {
        let h = libc::dlmopen(libc::LM_ID_NEWLM, b"libc.so.6\0".as_ptr().cast(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        assert!(!h.is_null()); libc::dlsym(h, b"wcslen\0".as_ptr().cast()) as usize
    });
    unsafe { std::mem::transmute::<usize, Fn_>(a) }
}

/// OLD: escalate only once i>=64 AND 128-aligned.
#[inline]
unsafe fn old_scan(s: *const u32) -> usize {
    let z = Simd::<u32, 8>::splat(0);
    let pb = s as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { s.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 { return m0.trailing_zeros() as usize - align; }
    let mut i = 8 - align;
    while i < 64 || (pb + i * 4) & 127 != 0 {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 { return i + m.trailing_zeros() as usize; }
        i += 8;
    }
    loop {
        let a = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let b = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 8), 8) });
        let c = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 16), 8) });
        let d = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 24), 8) });
        if a.simd_min(b).simd_min(c.simd_min(d)).simd_eq(z).any() {
            let ma = a.simd_eq(z).to_bitmask(); if ma != 0 { return i + ma.trailing_zeros() as usize; }
            let mb = b.simd_eq(z).to_bitmask(); if mb != 0 { return i + 8 + mb.trailing_zeros() as usize; }
            let mc = c.simd_eq(z).to_bitmask(); if mc != 0 { return i + 16 + mc.trailing_zeros() as usize; }
            return i + 24 + d.simd_eq(z).to_bitmask().trailing_zeros() as usize;
        }
        i += 32;
    }
}

/// NEW: escalate at the first 128-byte boundary.
#[inline]
unsafe fn new_scan(s: *const u32) -> usize {
    let z = Simd::<u32, 8>::splat(0);
    let pb = s as usize;
    let align = (pb & 31) >> 2;
    let base = unsafe { s.sub(align) };
    let v0 = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(base, 8) });
    let m0 = v0.simd_eq(z).to_bitmask() & !((1u64 << align) - 1);
    if m0 != 0 { return m0.trailing_zeros() as usize - align; }
    let mut i = 8 - align;
    while (pb + i * 4) & 127 != 0 {
        let v = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let m = v.simd_eq(z).to_bitmask();
        if m != 0 { return i + m.trailing_zeros() as usize; }
        i += 8;
    }
    loop {
        let a = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), 8) });
        let b = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 8), 8) });
        let c = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 16), 8) });
        let d = Simd::<u32, 8>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i + 24), 8) });
        if a.simd_min(b).simd_min(c.simd_min(d)).simd_eq(z).any() {
            let ma = a.simd_eq(z).to_bitmask(); if ma != 0 { return i + ma.trailing_zeros() as usize; }
            let mb = b.simd_eq(z).to_bitmask(); if mb != 0 { return i + 8 + mb.trailing_zeros() as usize; }
            let mc = c.simd_eq(z).to_bitmask(); if mc != 0 { return i + 16 + mc.trailing_zeros() as usize; }
            return i + 24 + d.simd_eq(z).to_bitmask().trailing_zeros() as usize;
        }
        i += 32;
    }
}

fn pctl(s: &[f64], q: f64) -> f64 { let mut v=s.to_vec(); v.sort_by(|a,b|a.partial_cmp(b).unwrap()); let r=q*(v.len()-1) as f64; let(lo,hi)=(r.floor() as usize,r.ceil() as usize); if lo==hi{v[lo]}else{v[lo]*(1.0-(r-lo as f64))+v[hi]*(r-lo as f64)} }

fn bench(c: &mut Criterion) {
    let g = host();
    let mut grp = c.benchmark_group("wcslen_esc"); grp.sample_size(10);
    for &n in &[4usize, 16, 32, 48, 64, 96, 128, 256, 1024] {
        let mut buf: Vec<u32> = std::iter::repeat(b'a' as u32).take(n).collect(); buf.push(0);
        let p = buf.as_ptr();
        // Byte-identity: old==new==glibc for this valid string.
        let (o, ne, gl) = unsafe { (old_scan(p), new_scan(p), g(p)) };
        assert_eq!(o, n, "old n={n}"); assert_eq!(ne, n, "new n={n}"); assert_eq!(gl, n, "glibc n={n}");
        let it = 4000u64;
        let (mut os, mut ns, mut gs) = (Vec::new(), Vec::new(), Vec::new());
        for _ in 0..80 {
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { old_scan(black_box(p)) }); } os.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { new_scan(black_box(p)) }); } ns.push(t.elapsed().as_nanos() as f64 / it as f64);
            let t = Instant::now(); for _ in 0..it { black_box(unsafe { g(black_box(p)) }); } gs.push(t.elapsed().as_nanos() as f64 / it as f64);
        }
        let (op,np,gp)=(pctl(&os,0.5),pctl(&ns,0.5),pctl(&gs,0.5));
        println!("WCSLEN_ESC n={n} old={op:.2} new={np:.2} glibc={gp:.2} new/old={:.3} new/glibc={:.3} old/glibc={:.3}", np/op, np/gp, op/gp);
    }
    grp.bench_function("noop", |b| b.iter(|| black_box(1u8))); grp.finish();
}
criterion_group!(benches, bench); criterion_main!(benches);
