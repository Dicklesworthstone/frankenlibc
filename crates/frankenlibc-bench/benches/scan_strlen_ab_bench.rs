//! In-process A/B: old vs new scan_c_string None-path strlen kernel vs host glibc.
//! cc/BlackThrush. Worker variance cancels because old-kernel, new-kernel and glibc
//! are all timed in the SAME process; only the within-process ratios are meaningful.
//!
//! OLD = scalar head-align loop + per-iteration page-cross guard (pre-847363e6e).
//! NEW = glibc-style aligned-load-down + head-mask (no scalar head, no per-chunk guard).
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench scan_strlen_ab_bench`
#![feature(portable_simd)]

use std::ffi::{c_char, c_void};
use std::hint::black_box;
use std::simd::Simd;
use std::simd::cmp::SimdPartialEq;
use std::slice;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

type LenFn = unsafe extern "C" fn(*const c_char) -> usize;
type ChrFn = unsafe extern "C" fn(*const c_char, i32) -> *mut c_char;

fn host_sym(name: &[u8]) -> usize {
    unsafe {
        let h = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!h.is_null(), "dlmopen failed");
        let s = libc::dlsym(h, name.as_ptr().cast());
        assert!(!s.is_null());
        s as usize
    }
}

fn host_strlen() -> LenFn {
    static H: OnceLock<usize> = OnceLock::new();
    unsafe { std::mem::transmute::<usize, LenFn>(*H.get_or_init(|| host_sym(b"strlen\0"))) }
}

fn host_strchr() -> ChrFn {
    static H: OnceLock<usize> = OnceLock::new();
    unsafe { std::mem::transmute::<usize, ChrFn>(*H.get_or_init(|| host_sym(b"strchr\0"))) }
}

#[inline]
fn swar_has_zero(w: u64) -> bool {
    w.wrapping_sub(0x0101_0101_0101_0101) & !w & 0x8080_8080_8080_8080 != 0
}

/// OLD None-path kernel: scalar head-align to 8, then per-iteration page-cross guard.
#[inline(never)]
unsafe fn scan_old(p: *const u8) -> usize {
    let mut i = 0usize;
    let head = (p as usize).wrapping_neg() & 7;
    while i < head {
        if unsafe { *p.add(i) } == 0 {
            return i;
        }
        i += 1;
    }
    loop {
        if (p as usize + i) & 0xFFF <= 0x1000 - 32 {
            let v = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
            let mask = v.simd_eq(Simd::splat(0)).to_bitmask();
            if mask == 0 {
                i += 32;
                continue;
            }
            return i + mask.trailing_zeros() as usize;
        }
        let w = unsafe { *p.add(i).cast::<u64>() };
        if swar_has_zero(w) {
            for j in 0..8 {
                if unsafe { *p.add(i + j) } == 0 {
                    return i + j;
                }
            }
        }
        i += 8;
    }
}

/// NEW None-path kernel: align down to 32, one aligned load + head-mask, then aligned loads.
#[inline(never)]
unsafe fn scan_new(p: *const u8) -> usize {
    let align = (p as usize) & 31;
    let base = unsafe { p.sub(align) };
    let v0 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(base, 32) });
    let mask0 = v0.simd_eq(Simd::splat(0)).to_bitmask() & !((1u64 << align) - 1);
    if mask0 != 0 {
        return mask0.trailing_zeros() as usize - align;
    }
    let mut i = 32 - align;
    loop {
        let v = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
        let mask = v.simd_eq(Simd::splat(0)).to_bitmask();
        if mask != 0 {
            return i + mask.trailing_zeros() as usize;
        }
        i += 32;
    }
}

/// OLD strchr None-path kernel: scalar head-align to 8 + per-chunk page guard + folded-128.
#[inline(never)]
unsafe fn chr_old(p: *const u8, target: u8) -> usize {
    let bcast = (target as u64).wrapping_mul(0x0101_0101_0101_0101);
    let mut i = 0usize;
    let head = (p as usize).wrapping_neg() & 7;
    while i < head {
        let b = unsafe { *p.add(i) };
        if b == target || b == 0 {
            return i;
        }
        i += 1;
    }
    loop {
        if i >= 128 && (p as usize + i) & 0xFFF <= 0x1000 - 128 {
            let tv = Simd::<u8, 32>::splat(target);
            let zv = Simd::<u8, 32>::splat(0);
            let v0 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
            let v1 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i + 32), 32) });
            let v2 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i + 64), 32) });
            let v3 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i + 96), 32) });
            let any = (v0.simd_eq(tv) | v0.simd_eq(zv))
                | (v1.simd_eq(tv) | v1.simd_eq(zv))
                | (v2.simd_eq(tv) | v2.simd_eq(zv))
                | (v3.simd_eq(tv) | v3.simd_eq(zv));
            if !any.any() {
                i += 128;
                continue;
            }
        }
        if (p as usize + i) & 0xFFF <= 0x1000 - 32 {
            let v = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
            let hits = v.simd_eq(Simd::splat(0)) | v.simd_eq(Simd::splat(target));
            if !hits.any() {
                i += 32;
                continue;
            }
        }
        let w = unsafe { *p.add(i).cast::<u64>() };
        if swar_has_zero(w) || swar_has_zero(w ^ bcast) {
            for j in 0..8 {
                let b = unsafe { *p.add(i + j) };
                if b == target || b == 0 {
                    return i + j;
                }
            }
        }
        i += 8;
    }
}

/// NEW strchr None-path kernel: aligned-load-down + head-mask, then aligned 32B (no guard) + folded-128.
#[inline(never)]
unsafe fn chr_new(p: *const u8, target: u8) -> usize {
    let align = (p as usize) & 31;
    let base = unsafe { p.sub(align) };
    let v0 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(base, 32) });
    let headclear = !((1u64 << align) - 1);
    let nul0 = v0.simd_eq(Simd::splat(0)).to_bitmask() & headclear;
    let tgt0 = v0.simd_eq(Simd::splat(target)).to_bitmask() & headclear;
    let comb0 = nul0 | tgt0;
    if comb0 != 0 {
        return comb0.trailing_zeros() as usize - align;
    }
    let mut i = 32 - align;
    loop {
        if i >= 128 && (p as usize + i) & 0xFFF <= 0x1000 - 128 {
            let tv = Simd::<u8, 32>::splat(target);
            let zv = Simd::<u8, 32>::splat(0);
            let v1 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
            let v2 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i + 32), 32) });
            let v3 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i + 64), 32) });
            let v4 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i + 96), 32) });
            let any = (v1.simd_eq(tv) | v1.simd_eq(zv))
                | (v2.simd_eq(tv) | v2.simd_eq(zv))
                | (v3.simd_eq(tv) | v3.simd_eq(zv))
                | (v4.simd_eq(tv) | v4.simd_eq(zv));
            if !any.any() {
                i += 128;
                continue;
            }
        }
        let v = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
        let comb = (v.simd_eq(Simd::splat(0)) | v.simd_eq(Simd::splat(target))).to_bitmask();
        if comb != 0 {
            return i + comb.trailing_zeros() as usize;
        }
        i += 32;
    }
}

/// OLD strrchr None-path kernel: scalar head-align + per-chunk page guard + 8B SWAR.
#[inline(never)]
unsafe fn rchr_old(p: *const u8, target: u8) -> Option<usize> {
    let bcast = (target as u64).wrapping_mul(0x0101_0101_0101_0101);
    let mut last: Option<usize> = None;
    let mut i = 0usize;
    let head = (p as usize).wrapping_neg() & 7;
    while i < head {
        let b = unsafe { *p.add(i) };
        if b == target {
            last = Some(i);
        }
        if b == 0 {
            return last;
        }
        i += 1;
    }
    loop {
        if (p as usize + i) & 0xFFF <= 0x1000 - 32 {
            let v = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
            let hit = v.simd_eq(Simd::splat(target)) | v.simd_eq(Simd::splat(0));
            if !hit.any() {
                i += 32;
                continue;
            }
        }
        let w = unsafe { *p.add(i).cast::<u64>() };
        if swar_has_zero(w) {
            for j in 0..8 {
                let b = unsafe { *p.add(i + j) };
                if b == target {
                    last = Some(i + j);
                }
                if b == 0 {
                    return last;
                }
            }
        } else if swar_has_zero(w ^ bcast) {
            for j in (0..8).rev() {
                if unsafe { *p.add(i + j) } == target {
                    last = Some(i + j);
                    break;
                }
            }
        }
        i += 8;
    }
}

/// NEW strrchr None-path kernel: aligned-load-down + head-mask, last-match via bitmasks.
#[inline(never)]
unsafe fn rchr_new(p: *const u8, target: u8) -> Option<usize> {
    let align = (p as usize) & 31;
    let base = unsafe { p.sub(align) };
    let headclear = !((1u64 << align) - 1);
    let v0 = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(base, 32) });
    let nul0 = v0.simd_eq(Simd::splat(0)).to_bitmask() & headclear;
    let tgt0 = v0.simd_eq(Simd::splat(target)).to_bitmask() & headclear;
    if nul0 != 0 {
        let nul_pos = nul0.trailing_zeros();
        let upto = tgt0 & ((1u64 << (nul_pos + 1)) - 1);
        return if upto != 0 {
            Some((63 - upto.leading_zeros()) as usize - align)
        } else {
            None
        };
    }
    let mut last = if tgt0 != 0 {
        Some((63 - tgt0.leading_zeros()) as usize - align)
    } else {
        None
    };
    let mut i = 32 - align;
    loop {
        let v = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p.add(i), 32) });
        let hit = (v.simd_eq(Simd::splat(0)) | v.simd_eq(Simd::splat(target))).to_bitmask();
        if hit == 0 {
            i += 32;
            continue;
        }
        let nul = v.simd_eq(Simd::splat(0)).to_bitmask();
        let tgt = v.simd_eq(Simd::splat(target)).to_bitmask();
        if nul != 0 {
            let nul_pos = nul.trailing_zeros();
            let upto = tgt & ((1u64 << (nul_pos + 1)) - 1);
            if upto != 0 {
                last = Some(i + (63 - upto.leading_zeros()) as usize);
            }
            return last;
        }
        last = Some(i + (63 - tgt.leading_zeros()) as usize);
        i += 32;
    }
}

#[inline]
unsafe fn eq16(a: *const u8, b: *const u8) -> bool {
    unsafe { std::ptr::read_unaligned(a.cast::<u128>()) == std::ptr::read_unaligned(b.cast::<u128>()) }
}
#[inline]
unsafe fn eq32(a: *const u8, b: *const u8) -> bool {
    unsafe { eq16(a, b) && eq16(a.add(16), b.add(16)) }
}
#[inline]
unsafe fn first_diff_sign(a: *const u8, b: *const u8, lo: usize, hi: usize) -> i32 {
    let mut j = lo;
    while j < hi {
        let av = unsafe { *a.add(j) };
        let bv = unsafe { *b.add(j) };
        if av != bv {
            return if av < bv { -1 } else { 1 };
        }
        j += 1;
    }
    0
}

/// OLD memcmp kernel: lane=32 dispatch path — 32-chunks, 16-chunks, then SCALAR tail.
#[inline(never)]
unsafe fn memcmp_old(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i + 32 <= n {
        if !unsafe { eq32(a.add(i), b.add(i)) } {
            return unsafe { first_diff_sign(a, b, i, i + 32) };
        }
        i += 32;
    }
    while i + 16 <= n {
        if !unsafe { eq16(a.add(i), b.add(i)) } {
            return unsafe { first_diff_sign(a, b, i, i + 16) };
        }
        i += 16;
    }
    while i < n {
        let av = unsafe { *a.add(i) };
        let bv = unsafe { *b.add(i) };
        if av != bv {
            return if av < bv { -1 } else { 1 };
        }
        i += 1;
    }
    0
}

/// NEW memcmp kernel — EXACT deployable structure: 32-chunk loop, 16-chunk loop, then a
/// glibc-style overlapping power-of-2 tail (replaces the per-byte scalar tail). Mirrors
/// what raw_lane_memcmp_bytes will run (lane_bytes>=16 path).
#[inline(never)]
unsafe fn memcmp_new(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    while i + 32 <= n {
        if !unsafe { eq32(a.add(i), b.add(i)) } {
            return unsafe { first_diff_sign(a, b, i, i + 32) };
        }
        i += 32;
    }
    if i == n {
        return 0;
    }
    // remainder r = n - i in [1, 32): one overlapping wide load per size class. Each window
    // ends at n so it stays in bounds; the overlapped prefix was already proven equal.
    let r = n - i;
    if r >= 16 {
        if !unsafe { eq16(a.add(i), b.add(i)) } {
            return unsafe { first_diff_sign(a, b, i, i + 16) };
        }
        let off = n - 16;
        if !unsafe { eq16(a.add(off), b.add(off)) } {
            return unsafe { first_diff_sign(a, b, off, n) };
        }
    } else if r >= 8 {
        let x0 = unsafe { std::ptr::read_unaligned(a.add(i).cast::<u64>()) };
        let y0 = unsafe { std::ptr::read_unaligned(b.add(i).cast::<u64>()) };
        if x0 != y0 {
            return unsafe { first_diff_sign(a, b, i, i + 8) };
        }
        let off = n - 8;
        let x1 = unsafe { std::ptr::read_unaligned(a.add(off).cast::<u64>()) };
        let y1 = unsafe { std::ptr::read_unaligned(b.add(off).cast::<u64>()) };
        if x1 != y1 {
            return unsafe { first_diff_sign(a, b, off, n) };
        }
    } else if r >= 4 {
        let x0 = unsafe { std::ptr::read_unaligned(a.add(i).cast::<u32>()) };
        let y0 = unsafe { std::ptr::read_unaligned(b.add(i).cast::<u32>()) };
        if x0 != y0 {
            return unsafe { first_diff_sign(a, b, i, i + 4) };
        }
        let off = n - 4;
        let x1 = unsafe { std::ptr::read_unaligned(a.add(off).cast::<u32>()) };
        let y1 = unsafe { std::ptr::read_unaligned(b.add(off).cast::<u32>()) };
        if x1 != y1 {
            return unsafe { first_diff_sign(a, b, off, n) };
        }
    } else {
        return unsafe { first_diff_sign(a, b, i, n) };
    }
    0
}

fn p50(v: &mut [f64]) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    v[v.len() / 2]
}

fn measure(mut f: impl FnMut() -> u64) -> f64 {
    for _ in 0..200 {
        black_box(f());
    }
    let mut s = Vec::new();
    for _ in 0..500 {
        let t = Instant::now();
        let mut acc = 0u64;
        for _ in 0..64 {
            acc = acc.wrapping_add(f());
        }
        black_box(acc);
        s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / 64.0);
    }
    p50(&mut s)
}

fn bench(c: &mut Criterion) {
    let g = host_strlen();
    // Page-aligned backing buffer so we can place a string at any alignment offset.
    let backing = vec![b'x'; 16384];
    // For each length, sweep all 32 alignment offsets and sum kernel times, so the
    // reported ratio reflects the full alignment distribution (the old kernel's
    // scalar head cost is alignment-dependent; the new kernel's head-mask is flat).
    for &len in &[7usize, 15, 23, 31, 47, 63] {
        let mut buf = backing.clone();
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..32usize {
            // Lay out a `len`-byte non-NUL string at `off`, NUL-terminated.
            for k in 0..len {
                buf[off + k] = b'a' + (k % 26) as u8;
            }
            buf[off + len] = 0;
            let p = unsafe { buf.as_ptr().add(off) };
            // Byte-identity guard: all three agree with the true length.
            let lo = unsafe { scan_old(p) };
            let ln = unsafe { scan_new(p) };
            let lg = unsafe { g(p.cast()) };
            assert_eq!(lo, len, "old kernel wrong at off={off} len={len}");
            assert_eq!(ln, len, "new kernel wrong at off={off} len={len}");
            assert_eq!(lg, len, "glibc disagrees at off={off} len={len}");
            old_t += measure(|| unsafe { scan_old(black_box(p)) } as u64);
            new_t += measure(|| unsafe { scan_new(black_box(p)) } as u64);
            g_t += measure(|| unsafe { g(black_box(p.cast())) } as u64);
            buf[off + len] = b'x';
        }
        println!(
            "SCAN_AB len={len:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 32.0,
            new_t / 32.0,
            g_t / 32.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }
    // strchr A/B: search an ABSENT byte so the scan runs to the NUL (worst case,
    // same scan-floor workload as strlen). glibc strchr returns NULL on absence.
    let g_chr = host_strchr();
    let absent = 0x01u8; // never appears in the 'a'..'z' payloads
    for &len in &[7usize, 15, 23, 31, 47, 63] {
        let mut buf = backing.clone();
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..32usize {
            for k in 0..len {
                buf[off + k] = b'a' + (k % 26) as u8;
            }
            buf[off + len] = 0;
            let p = unsafe { buf.as_ptr().add(off) };
            // Byte-identity guard: both kernels return the NUL index on absence; glibc returns NULL.
            assert_eq!(unsafe { chr_old(p, absent) }, len, "chr_old wrong off={off} len={len}");
            assert_eq!(unsafe { chr_new(p, absent) }, len, "chr_new wrong off={off} len={len}");
            assert!(
                unsafe { g_chr(p.cast(), absent as i32) }.is_null(),
                "glibc strchr should miss off={off} len={len}"
            );
            old_t += measure(|| unsafe { chr_old(black_box(p), absent) } as u64);
            new_t += measure(|| unsafe { chr_new(black_box(p), absent) } as u64);
            g_t += measure(|| unsafe { g_chr(black_box(p.cast()), absent as i32) } as usize as u64);
            buf[off + len] = b'x';
        }
        println!(
            "CHR_AB len={len:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 32.0,
            new_t / 32.0,
            g_t / 32.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // strrchr A/B: target PRESENT near the END (exercises last-match resolution &
    // full scan to NUL). glibc strrchr returns a pointer to the last match.
    let g_rchr =
        unsafe { std::mem::transmute::<usize, ChrFn>(host_sym(b"strrchr\0")) };
    for &len in &[7usize, 15, 23, 31, 47, 63, 256, 1024, 4096] {
        let mut buf = backing.clone();
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        // Target 'Q' placed at two spots (len/2 and len-2) so a real last-match exists.
        let tgt = b'Q';
        for off in 0..32usize {
            for k in 0..len {
                buf[off + k] = b'a' + (k % 26) as u8;
            }
            if len >= 4 {
                buf[off + len / 2] = tgt;
                buf[off + len - 2] = tgt;
            }
            buf[off + len] = 0;
            let p = unsafe { buf.as_ptr().add(off) };
            let want = if len >= 4 { Some(len - 2) } else { None };
            assert_eq!(unsafe { rchr_old(p, tgt) }, want, "rchr_old wrong off={off} len={len}");
            assert_eq!(unsafe { rchr_new(p, tgt) }, want, "rchr_new wrong off={off} len={len}");
            let gp = unsafe { g_rchr(p.cast(), tgt as i32) };
            let g_idx = if gp.is_null() {
                None
            } else {
                Some(unsafe { gp.cast::<u8>().offset_from(p) } as usize)
            };
            assert_eq!(g_idx, want, "glibc strrchr disagrees off={off} len={len}");
            old_t += measure(|| unsafe { rchr_old(black_box(p), tgt) }.unwrap_or(0) as u64);
            new_t += measure(|| unsafe { rchr_new(black_box(p), tgt) }.unwrap_or(0) as u64);
            g_t += measure(|| unsafe { g_rchr(black_box(p.cast()), tgt as i32) } as usize as u64);
            buf[off + len] = b'x';
        }
        println!(
            "RCHR_AB len={len:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 32.0,
            new_t / 32.0,
            g_t / 32.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // memcmp A/B: EQUAL buffers (full-scan worst case, the family-bench regime). Also
    // a correctness sweep with a single differing byte at every position vs glibc sign.
    type McmpFn = unsafe extern "C" fn(*const c_void, *const c_void, usize) -> i32;
    let g_mcmp =
        unsafe { std::mem::transmute::<usize, McmpFn>(host_sym(b"memcmp\0")) };
    // Correctness: for several n, flip one byte at each position and check sign agreement.
    for &n in &[1usize, 3, 4, 7, 8, 15, 16, 23, 31, 32, 47, 63] {
        let mut a = vec![b'a' + 0u8; n + 1];
        for k in 0..n {
            a[k] = b'a' + (k % 26) as u8;
        }
        for pos in 0..n {
            let mut b = a.clone();
            b[pos] = a[pos] ^ 0x20; // differ at exactly `pos`
            let ap = a.as_ptr();
            let bp = b.as_ptr();
            let want = unsafe { g_mcmp(ap.cast(), bp.cast(), n) }.signum();
            assert_eq!(
                unsafe { memcmp_old(ap, bp, n) }.signum(),
                want,
                "memcmp_old sign wrong n={n} pos={pos}"
            );
            assert_eq!(
                unsafe { memcmp_new(ap, bp, n) }.signum(),
                want,
                "memcmp_new sign wrong n={n} pos={pos}"
            );
        }
        // equal buffers => 0
        assert_eq!(unsafe { memcmp_new(a.as_ptr(), a.as_ptr(), n) }, 0, "memcmp_new eq n={n}");
    }
    for &len in &[7usize, 15, 23, 31, 47, 63] {
        let mut a = backing.clone();
        let mut bb = backing.clone();
        for k in 0..len {
            a[k] = b'a' + (k % 26) as u8;
            bb[k] = b'a' + (k % 26) as u8;
        }
        let ap = a.as_ptr();
        let bp = bb.as_ptr();
        let old_t = measure(|| unsafe { memcmp_old(black_box(ap), black_box(bp), len) } as i64 as u64);
        let new_t = measure(|| unsafe { memcmp_new(black_box(ap), black_box(bp), len) } as i64 as u64);
        let g_t = measure(|| unsafe { g_mcmp(black_box(ap.cast()), black_box(bp.cast()), len) } as i64 as u64);
        println!(
            "MCMP_AB len={len:<3} old_p50_ns={old_t:.3} new_p50_ns={new_t:.3} glibc_p50_ns={g_t:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    let mut grp = c.benchmark_group("scan_ab");
    grp.bench_function("noop", |bb| bb.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
