//! wmemrchr resolve-on-hit A/B: the core kernel (frankenlibc_core::string::wide::wmemrchr) finds
//! the flagged reverse chunk with a SIMD `.any()`, then resolves the exact last match with a SCALAR
//! reverse rescan (`for j in (0..LANES).rev()`). Narrow memrchr dropped that scalar rposition for an
//! O(1) mask `63 - leading_zeros` (bd-2g7oyh: the rescan was ~3x); the WIDE kernel never got it.
//! This measures cur (scalar rescan) vs mask (leading_zeros) vs host glibc wmemrchr, byte-identity
//! asserted, across last-match positions — the resolve cost shows most when the target is near the
//! END (little reverse skip, so the per-hit resolve dominates), the realistic "find the LAST x" case.
#![feature(portable_simd)]
use std::ffi::c_void;
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;
use std::time::Instant;

const LONG: usize = 64; // WIDE_REVERSE_LONG_SIMD_LANES
const SHORT: usize = 16; // WIDE_REVERSE_SIMD_LANES
const LONG_MIN: usize = LONG * 4; // WIDE_REVERSE_LONG_MIN_LEN

fn pctl(s: &[f64], q: f64) -> f64 {
    let mut v = s.to_vec();
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((q * (v.len() - 1) as f64).round() as usize).min(v.len() - 1)]
}

// CURRENT: mirrors deployed core wmemrchr — scalar reverse rescan of the flagged chunk.
fn wmr_cur(s: &[u32], c: u32, n: usize) -> Option<usize> {
    let count = n.min(s.len());
    let scan = &s[..count];
    let mut end = count;
    if count >= LONG_MIN {
        let target = Simd::<u32, LONG>::splat(c);
        for chunk in scan.rchunks_exact(LONG) {
            let start = end - LONG;
            let lanes = Simd::<u32, LONG>::from_slice(chunk);
            if lanes.simd_eq(target).any() {
                for j in (0..LONG).rev() {
                    if chunk[j] == c {
                        return Some(start + j);
                    }
                }
            }
            end = start;
        }
    }
    let target = Simd::<u32, SHORT>::splat(c);
    for chunk in scan[..end].rchunks_exact(SHORT) {
        let start = end - SHORT;
        let lanes = Simd::<u32, SHORT>::from_slice(chunk);
        if lanes.simd_eq(target).any() {
            for j in (0..SHORT).rev() {
                if chunk[j] == c {
                    return Some(start + j);
                }
            }
        }
        end = start;
    }
    (0..end).rev().find(|&j| scan[j] == c)
}

// NEW: O(1) resolve — highest set lane via the SIMD bitmask (63 - leading_zeros).
fn wmr_mask(s: &[u32], c: u32, n: usize) -> Option<usize> {
    let count = n.min(s.len());
    let scan = &s[..count];
    let mut end = count;
    if count >= LONG_MIN {
        let target = Simd::<u32, LONG>::splat(c);
        for chunk in scan.rchunks_exact(LONG) {
            let start = end - LONG;
            let lanes = Simd::<u32, LONG>::from_slice(chunk);
            let bits = lanes.simd_eq(target).to_bitmask();
            if bits != 0 {
                return Some(start + (63 - bits.leading_zeros() as usize));
            }
            end = start;
        }
    }
    let target = Simd::<u32, SHORT>::splat(c);
    for chunk in scan[..end].rchunks_exact(SHORT) {
        let start = end - SHORT;
        let lanes = Simd::<u32, SHORT>::from_slice(chunk);
        let bits = lanes.simd_eq(target).to_bitmask() as u64;
        if bits != 0 {
            return Some(start + (63 - bits.leading_zeros() as usize));
        }
        end = start;
    }
    (0..end).rev().find(|&j| scan[j] == c)
}

type GFn = unsafe extern "C" fn(*const u32, u32, usize) -> *mut u32;
fn glibc_wmemrchr() -> GFn {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen libc failed");
        let s = libc::dlsym(h, b"wmemrchr\0".as_ptr().cast());
        assert!(!s.is_null(), "dlsym wmemrchr failed");
        std::mem::transmute::<*mut c_void, GFn>(s)
    }
}

fn main() {
    let g = glibc_wmemrchr();
    let c = 0x2f2f_u32; // arbitrary sentinel not otherwise in the fill
    for &n in &[256usize, 1024, 4096, 16384, 65536] {
        // Cases differ only in WHERE the last c sits (or dense/absent), isolating the resolve cost.
        for tag in ["near_end", "mid", "dense", "absent"] {
            let mut base: Vec<u32> = (0..n as u32).map(|x| 1 + (x % 100)).collect();
            match tag {
                // Last c at n-3 (lane ~ mid of the final long chunk) — minimal reverse skip.
                "near_end" => {
                    if n >= 3 {
                        base[n - 3] = c;
                    }
                }
                // Last c at n/2 — half the buffer is skipped before the resolve.
                "mid" => base[n / 2] = c,
                // c every 8th element — the last (n-8..) is found almost immediately.
                "dense" => {
                    for k in (0..n).step_by(8) {
                        base[k] = c;
                    }
                }
                _ => {} // absent: c never present → full reverse scan
            }
            let sp = base.as_ptr();

            let ref_ = wmr_cur(&base, c, n);
            assert_eq!(wmr_mask(&base, c, n), ref_, "mask mismatch n={n} {tag}");
            let gp = unsafe { g(sp, c, n) };
            let g_idx = if gp.is_null() {
                None
            } else {
                Some(unsafe { gp.offset_from(sp) } as usize)
            };
            assert_eq!(g_idx, ref_, "glibc mismatch n={n} {tag}");

            let iters: u64 = (8_000_000u64 / n as u64).max(1500);
            let (mut cur, mut mask, mut gl) = (Vec::new(), Vec::new(), Vec::new());
            let time = |f: &dyn Fn()| {
                let t = Instant::now();
                for _ in 0..iters {
                    f();
                }
                t.elapsed().as_nanos() as f64 / iters as f64
            };
            for r in 0..40 {
                let fc = || {
                    black_box(wmr_cur(black_box(&base), c, n));
                };
                let fm = || {
                    black_box(wmr_mask(black_box(&base), c, n));
                };
                let fg = || {
                    black_box(unsafe { g(black_box(sp), c, n) });
                };
                if r % 2 == 0 {
                    cur.push(time(&fc));
                    mask.push(time(&fm));
                    gl.push(time(&fg));
                } else {
                    gl.push(time(&fg));
                    mask.push(time(&fm));
                    cur.push(time(&fc));
                }
            }
            let (cur, mask, gl) = (pctl(&cur, 0.1), pctl(&mask, 0.1), pctl(&gl, 0.1));
            println!(
                "n={n:<6} {tag:<8} glibc={gl:8.1} cur={cur:8.1} mask={mask:8.1}ns | \
                 mask/cur={:.3}  cur/glibc={:.2}x  mask/glibc={:.2}x",
                mask / cur,
                cur / gl,
                mask / gl,
            );
        }
    }
}
