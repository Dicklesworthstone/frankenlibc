//! In-process A/B for wcsrchr's scan: CURRENT deployed 8-lane mask-extraction vs a 128B
//! (4x8-lane) COMBINED-mask tier (page-guarded). The earlier fold failed because it used a
//! scalar rescan; this builds a 32-bit combined (c|nul) mask and extracts the last match
//! branchlessly (like narrow strrchr's 64-lane tier). Byte-identity of (last,span) asserted.
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

// CURRENT deployed: 8-lane mask extraction.
unsafe fn scan8(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let mut last = None;
    let mut i = 0;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    loop {
        let v = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        let eqc = v.simd_eq(cv);
        let eqz = v.simd_eq(zv);
        if (eqc | eqz).any() {
            let zm = eqz.to_bitmask();
            if zm != 0 {
                let p = zm.trailing_zeros() as usize;
                let cmb = eqc.to_bitmask() & ((1u64 << p) - 1);
                if cmb != 0 {
                    last = Some(i + (63 - cmb.leading_zeros() as usize));
                }
                return (last, i + p + 1);
            }
            last = Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize));
        }
        i += L;
    }
}
// NEW: 128B combined-mask tier + 8-lane fallback near page edge.
unsafe fn scan32(s: *const u32, c: u32) -> (Option<usize>, usize) {
    const L: usize = 8;
    let mut last = None;
    let mut i = 0;
    let head = ((32 - ((s as usize) & 31)) & 31) / 4;
    while i < head {
        let ch = unsafe { *s.add(i) };
        if ch == c {
            last = Some(i);
        }
        if ch == 0 {
            return (last, i + 1);
        }
        i += 1;
    }
    let cv = Simd::<u32, L>::splat(c);
    let zv = Simd::<u32, L>::splat(0);
    loop {
        while (unsafe { s.add(i) } as usize & 0xFFF) <= 0x1000 - 128 {
            let c0 =
                Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
            let c1 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 8).cast::<[u32; L]>())
            });
            let c2 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 16).cast::<[u32; L]>())
            });
            let c3 = Simd::<u32, L>::from_array(unsafe {
                core::ptr::read(s.add(i + 24).cast::<[u32; L]>())
            });
            let e0 = c0.simd_eq(cv) | c0.simd_eq(zv);
            let e1 = c1.simd_eq(cv) | c1.simd_eq(zv);
            let e2 = c2.simd_eq(cv) | c2.simd_eq(zv);
            let e3 = c3.simd_eq(cv) | c3.simd_eq(zv);
            if (e0 | e1 | e2 | e3).any() {
                let cm = c0.simd_eq(cv).to_bitmask()
                    | (c1.simd_eq(cv).to_bitmask() << 8)
                    | (c2.simd_eq(cv).to_bitmask() << 16)
                    | (c3.simd_eq(cv).to_bitmask() << 24);
                let zm = c0.simd_eq(zv).to_bitmask()
                    | (c1.simd_eq(zv).to_bitmask() << 8)
                    | (c2.simd_eq(zv).to_bitmask() << 16)
                    | (c3.simd_eq(zv).to_bitmask() << 24);
                if zm != 0 {
                    let p = zm.trailing_zeros() as usize;
                    let cmb = cm & ((1u64 << p) - 1);
                    if cmb != 0 {
                        last = Some(i + (63 - cmb.leading_zeros() as usize));
                    }
                    return (last, i + p + 1);
                }
                last = Some(i + (63 - cm.leading_zeros() as usize));
            }
            i += 32;
        }
        // 8-lane fallback near a page edge
        let v = Simd::<u32, L>::from_array(unsafe { core::ptr::read(s.add(i).cast::<[u32; L]>()) });
        let eqc = v.simd_eq(cv);
        let eqz = v.simd_eq(zv);
        if (eqc | eqz).any() {
            let zm = eqz.to_bitmask();
            if zm != 0 {
                let p = zm.trailing_zeros() as usize;
                let cmb = eqc.to_bitmask() & ((1u64 << p) - 1);
                if cmb != 0 {
                    last = Some(i + (63 - cmb.leading_zeros() as usize));
                }
                return (last, i + p + 1);
            }
            last = Some(i + (63 - eqc.to_bitmask().leading_zeros() as usize));
        }
        i += L;
    }
}

fn main() {
    for &n in &[16usize, 64, 256, 1024, 4096] {
        let base: Vec<u32> = (0..n as u32)
            .map(|x| b'a' as u32 + (x % 20))
            .chain(std::iter::once(0))
            .collect();
        let sp = base.as_ptr();
        for (tag, c) in [
            ("absent", b'Z' as u32),
            ("mid", (b'a' as u32) + ((n / 2 % 20) as u32)),
        ] {
            assert_eq!(
                unsafe { scan8(sp, c) },
                unsafe { scan32(sp, c) },
                "mismatch n={n} {tag}"
            );
            let iters = 300_000u64;
            let (mut ov, mut nv) = (Vec::new(), Vec::new());
            for r in 0..50 {
                let o = || {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { scan8(black_box(sp), c) });
                    }
                    t.elapsed().as_nanos() as f64 / iters as f64
                };
                let nw = || {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { scan32(black_box(sp), c) });
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
                "wcsrchr n={n:<5} {tag:<7} 8lane={o:7.2}ns 128B={nn:7.2}ns  new/old={:.3} ({:.2}x)",
                nn / o,
                o / nn
            );
        }
    }
}
