//! In-process A/B for wmemrchr (bounded wide reverse-search): current SCALAR reverse loop
//! vs a SIMD backward 8-lane scan with mask extraction (last match = highest set bit).
//! Byte-identity asserted. Workloads: c-absent (full scan), c-at-front (full reverse scan),
//! c-at-end (early exit), c-mid.
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

// CURRENT: scalar reverse find.
unsafe fn scalar_rev(s: *const u32, c: u32, n: usize) -> isize {
    let sl = unsafe { std::slice::from_raw_parts(s, n) };
    match (0..n).rev().find(|&i| sl[i] == c) {
        Some(i) => i as isize,
        None => -1,
    }
}
// NEW: SIMD backward 8-lane scan + mask extraction. All reads stay within [0,n).
unsafe fn simd_rev(s: *const u32, c: u32, n: usize) -> isize {
    const L: usize = 8;
    let cv = Simd::<u32, L>::splat(c);
    let mut i = n;
    // top remainder (highest indices first) scalar
    let rem = n % L;
    for _ in 0..rem {
        i -= 1;
        if unsafe { *s.add(i) } == c {
            return i as isize;
        }
    }
    // 8-lane chunks downward; first (=highest) match wins
    while i >= L {
        i -= L;
        let v = Simd::<u32, L>::from_slice(unsafe { std::slice::from_raw_parts(s.add(i), L) });
        let m = v.simd_eq(cv).to_bitmask();
        if m != 0 {
            return (i + (63 - m.leading_zeros() as usize)) as isize;
        }
    }
    -1
}

fn main() {
    for &n in &[16usize, 64, 256, 1024, 4096] {
        let mut base: Vec<u32> = (0..n as u32).map(|x| b'a' as u32 + (x % 25)).collect();
        let sp = base.as_ptr();
        // workloads: c absent, c at front(0), c at end(n-1), c mid(n/2)
        for (tag, setpos, c) in [
            ("absent", None, b'Z' as u32),
            ("front", Some(0usize), b'Z' as u32),
            ("end", Some(n - 1), b'Z' as u32),
            ("mid", Some(n / 2), b'Z' as u32),
        ] {
            let mut b2 = base.clone();
            if let Some(p) = setpos {
                b2[p] = c;
            }
            let p2 = b2.as_ptr();
            assert_eq!(
                unsafe { scalar_rev(p2, c, n) },
                unsafe { simd_rev(p2, c, n) },
                "mismatch n={n} {tag}"
            );
            let iters = 300_000u64;
            let (mut ov, mut nv) = (Vec::new(), Vec::new());
            for r in 0..50 {
                let o = || {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { scalar_rev(black_box(p2), c, n) });
                    }
                    t.elapsed().as_nanos() as f64 / iters as f64
                };
                let nw = || {
                    let t = Instant::now();
                    for _ in 0..iters {
                        black_box(unsafe { simd_rev(black_box(p2), c, n) });
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
                "wmemrchr n={n:<5} {tag:<7} scalar={o:8.2}ns simd={nn:8.2}ns  simd/scalar={:.3} ({:.2}x)",
                nn / o,
                o / nn
            );
        }
        let _ = sp;
    }
}
