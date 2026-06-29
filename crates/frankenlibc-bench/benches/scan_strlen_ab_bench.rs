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
type CmpFn = unsafe extern "C" fn(*const c_char, *const c_char) -> i32;

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

#[inline]
fn swar_ascii_lower(w: u64) -> u64 {
    const ONES: u64 = 0x0101_0101_0101_0101;
    const HIGHS: u64 = 0x8080_8080_8080_8080;
    let guarded = w | HIGHS;
    let ge_a = guarded.wrapping_sub(ONES.wrapping_mul(0x41)) & HIGHS;
    let ge_5b = guarded.wrapping_sub(ONES.wrapping_mul(0x5B)) & HIGHS;
    let ascii = !w & HIGHS;
    let is_upper = ge_a & !ge_5b & ascii;
    w | (is_upper >> 2)
}
#[inline]
fn fold32(v: Simd<u8, 32>) -> Simd<u8, 32> {
    use std::simd::Select;
    use std::simd::cmp::SimdPartialOrd;
    let up = v.simd_ge(Simd::splat(b'A')) & v.simd_le(Simd::splat(b'Z'));
    up.select(v + Simd::splat(0x20), v)
}

/// OLD strcasecmp scan: 32B fold-flag then FALL THROUGH to 8B SWAR re-scan to resolve.
#[inline(never)]
unsafe fn scasecmp_old(p1: *const u8, p2: *const u8, bound: usize) -> (i32, usize) {
    let mut i = 0usize;
    loop {
        if i + 32 <= bound && page_ok32(p1 as usize + i) && page_ok32(p2 as usize + i) {
            let va = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p1.add(i), 32) });
            let vb = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p2.add(i), 32) });
            let flagged = fold32(va).simd_ne(fold32(vb)) | va.simd_eq(Simd::splat(0));
            if !flagged.any() {
                i += 32;
                continue;
            }
        }
        if i + 8 <= bound && page_ok8(p1 as usize + i) && page_ok8(p2 as usize + i) {
            let wa = unsafe { std::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { std::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if swar_ascii_lower(wa) == swar_ascii_lower(wb) && !has_byte_u64(wa, 0) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                let la = a.to_ascii_lowercase();
                let lb = b.to_ascii_lowercase();
                if la != lb {
                    return ((la as i32) - (lb as i32), i + j + 1);
                }
                if a == 0 {
                    return (0, i + j + 1);
                }
            }
            i += 8;
            continue;
        }
        if i >= bound {
            return (0, bound);
        }
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();
        if la != lb {
            return ((la as i32) - (lb as i32), i + 1);
        }
        if a == 0 {
            return (0, i + 1);
        }
        i += 1;
    }
}

/// NEW strcasecmp scan: 32B fold-flag with O(1) trailing_zeros resolve (no SWAR re-scan).
#[inline(never)]
unsafe fn scasecmp_new(p1: *const u8, p2: *const u8, bound: usize) -> (i32, usize) {
    let mut i = 0usize;
    loop {
        if i + 32 <= bound && page_ok32(p1 as usize + i) && page_ok32(p2 as usize + i) {
            let va = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p1.add(i), 32) });
            let vb = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p2.add(i), 32) });
            let flagged = (fold32(va).simd_ne(fold32(vb)) | va.simd_eq(Simd::splat(0))).to_bitmask();
            if flagged == 0 {
                i += 32;
                continue;
            }
            let k = i + flagged.trailing_zeros() as usize;
            let a = unsafe { *p1.add(k) };
            let b = unsafe { *p2.add(k) };
            let la = a.to_ascii_lowercase();
            let lb = b.to_ascii_lowercase();
            if la != lb {
                return ((la as i32) - (lb as i32), k + 1);
            }
            return (0, k + 1);
        }
        // (fallthrough tiers omitted: bench inputs always hit the 32B panel)
        if i >= bound {
            return (0, bound);
        }
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        let la = a.to_ascii_lowercase();
        let lb = b.to_ascii_lowercase();
        if la != lb {
            return ((la as i32) - (lb as i32), i + 1);
        }
        if a == 0 {
            return (0, i + 1);
        }
        i += 1;
    }
}

#[inline]
fn page_ok32(a: usize) -> bool {
    a & 0xFFF <= 0x1000 - 32
}
#[inline]
fn page_ok8(a: usize) -> bool {
    a & 0xFFF <= 0x1000 - 8
}

/// OLD strcmp scan: 32B SIMD flag then FALL THROUGH to 8B SWAR re-scan to resolve.
#[inline(never)]
unsafe fn scmp_old(p1: *const u8, p2: *const u8, bound: usize) -> usize {
    let mut i = 0usize;
    loop {
        if i + 32 <= bound && page_ok32(p1 as usize + i) && page_ok32(p2 as usize + i) {
            let va = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p1.add(i), 32) });
            let vb = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p2.add(i), 32) });
            let flagged = va.simd_ne(vb) | va.simd_eq(Simd::splat(0));
            if !flagged.any() {
                i += 32;
                continue;
            }
        }
        if i + 8 <= bound && page_ok8(p1 as usize + i) && page_ok8(p2 as usize + i) {
            let wa = unsafe { std::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { std::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if wa == wb && !swar_has_zero(wa) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                if a != b || a == 0 {
                    return i + j;
                }
            }
            i += 8;
            continue;
        }
        if i >= bound {
            return bound;
        }
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        if a != b || a == 0 {
            return i;
        }
        i += 1;
    }
}

/// NEW strcmp scan: 32B SIMD with O(1) trailing_zeros resolve (no SWAR re-scan).
#[inline(never)]
unsafe fn scmp_new(p1: *const u8, p2: *const u8, bound: usize) -> usize {
    let mut i = 0usize;
    loop {
        if i + 32 <= bound && page_ok32(p1 as usize + i) && page_ok32(p2 as usize + i) {
            let va = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p1.add(i), 32) });
            let vb = Simd::<u8, 32>::from_slice(unsafe { slice::from_raw_parts(p2.add(i), 32) });
            let flagged = (va.simd_ne(vb) | va.simd_eq(Simd::splat(0))).to_bitmask();
            if flagged == 0 {
                i += 32;
                continue;
            }
            return i + flagged.trailing_zeros() as usize;
        }
        if i + 8 <= bound && page_ok8(p1 as usize + i) && page_ok8(p2 as usize + i) {
            let wa = unsafe { std::ptr::read_unaligned(p1.add(i).cast::<u64>()) };
            let wb = unsafe { std::ptr::read_unaligned(p2.add(i).cast::<u64>()) };
            if wa == wb && !swar_has_zero(wa) {
                i += 8;
                continue;
            }
            for j in 0..8 {
                let a = unsafe { *p1.add(i + j) };
                let b = unsafe { *p2.add(i + j) };
                if a != b || a == 0 {
                    return i + j;
                }
            }
            i += 8;
            continue;
        }
        if i >= bound {
            return bound;
        }
        let a = unsafe { *p1.add(i) };
        let b = unsafe { *p2.add(i) };
        if a != b || a == 0 {
            return i;
        }
        i += 1;
    }
}

#[inline]
fn has_byte_u64(w: u64, needle: u8) -> bool {
    let x = w ^ (needle as u64).wrapping_mul(0x0101_0101_0101_0101);
    x.wrapping_sub(0x0101_0101_0101_0101) & !x & 0x8080_8080_8080_8080 != 0
}

/// OLD memchr small-n path: 8-byte SWAR loop + scalar tail (no SIMD for n<32).
#[inline(never)]
unsafe fn mchr_old(p: *const u8, needle: u8, n: usize) -> Option<usize> {
    let mut base = 0usize;
    while n - base >= 8 {
        let w = unsafe { std::ptr::read_unaligned(p.add(base).cast::<u64>()) };
        if has_byte_u64(w, needle) {
            for j in 0..8 {
                if unsafe { *p.add(base + j) } == needle {
                    return Some(base + j);
                }
            }
        }
        base += 8;
    }
    while base < n {
        if unsafe { *p.add(base) } == needle {
            return Some(base);
        }
        base += 1;
    }
    None
}

/// NEW memchr small-n path: two overlapping 16-byte SIMD probes for n in [16,32).
#[inline(never)]
unsafe fn mchr_new(p: *const u8, needle: u8, n: usize) -> Option<usize> {
    if (16..32).contains(&n) {
        let v0 = Simd::<u8, 16>::from_slice(unsafe { slice::from_raw_parts(p, 16) });
        let m0 = v0.simd_eq(Simd::splat(needle)).to_bitmask();
        if m0 != 0 {
            return Some(m0.trailing_zeros() as usize);
        }
        let off = n - 16;
        let v1 = Simd::<u8, 16>::from_slice(unsafe { slice::from_raw_parts(p.add(off), 16) });
        let m1 = v1.simd_eq(Simd::splat(needle)).to_bitmask();
        if m1 != 0 {
            return Some(off + m1.trailing_zeros() as usize);
        }
        return None;
    }
    unsafe { mchr_old(p, needle, n) }
}

/// OLD memrchr small-n path: 8-byte SWAR reverse loop + scalar front remainder.
#[inline(never)]
unsafe fn mrchr_old(p: *const u8, needle: u8, n: usize) -> Option<usize> {
    let mut end = n;
    while end >= 8 {
        let w = unsafe { std::ptr::read_unaligned(p.add(end - 8).cast::<u64>()) };
        if has_byte_u64(w, needle) {
            for j in (0..8).rev() {
                if unsafe { *p.add(end - 8 + j) } == needle {
                    return Some(end - 8 + j);
                }
            }
        }
        end -= 8;
    }
    for j in (0..end).rev() {
        if unsafe { *p.add(j) } == needle {
            return Some(j);
        }
    }
    None
}

/// NEW memrchr small-n path: two overlapping 16-byte SIMD probes, high→low.
#[inline(never)]
unsafe fn mrchr_new(p: *const u8, needle: u8, n: usize) -> Option<usize> {
    if (16..32).contains(&n) {
        let off = n - 16;
        let vh = Simd::<u8, 16>::from_slice(unsafe { slice::from_raw_parts(p.add(off), 16) });
        let mh = vh.simd_eq(Simd::splat(needle)).to_bitmask() as u64;
        if mh != 0 {
            return Some(off + (63 - mh.leading_zeros() as usize));
        }
        let vl = Simd::<u8, 16>::from_slice(unsafe { slice::from_raw_parts(p, 16) });
        let ml = vl.simd_eq(Simd::splat(needle)).to_bitmask() as u64;
        if ml != 0 {
            return Some(63 - ml.leading_zeros() as usize);
        }
        return None;
    }
    unsafe { mrchr_old(p, needle, n) }
}

/// OLD bounded NUL scan (strnlen) small-n path: 8-byte SWAR + scalar tail.
#[inline(never)]
unsafe fn snlen_old(p: *const u8, limit: usize) -> usize {
    let mut i = 0usize;
    while i + 8 <= limit {
        let w = unsafe { std::ptr::read_unaligned(p.add(i).cast::<u64>()) };
        if has_byte_u64(w, 0) {
            for j in 0..8 {
                if unsafe { *p.add(i + j) } == 0 {
                    return i + j;
                }
            }
        }
        i += 8;
    }
    while i < limit {
        if unsafe { *p.add(i) } == 0 {
            return i;
        }
        i += 1;
    }
    limit
}

/// NEW bounded NUL scan small-n path: two overlapping 16-byte SIMD probes.
#[inline(never)]
unsafe fn snlen_new(p: *const u8, limit: usize) -> usize {
    if (16..32).contains(&limit) {
        let v0 = Simd::<u8, 16>::from_slice(unsafe { slice::from_raw_parts(p, 16) });
        let m0 = v0.simd_eq(Simd::splat(0)).to_bitmask();
        if m0 != 0 {
            return m0.trailing_zeros() as usize;
        }
        let off = limit - 16;
        let v1 = Simd::<u8, 16>::from_slice(unsafe { slice::from_raw_parts(p.add(off), 16) });
        let m1 = v1.simd_eq(Simd::splat(0)).to_bitmask();
        if m1 != 0 {
            return off + m1.trailing_zeros() as usize;
        }
        return limit;
    }
    unsafe { snlen_old(p, limit) }
}

/// OLD wcsnlen small-n path: 16-lane u32 chunks + scalar tail (scalar-only for n<16).
#[inline(never)]
unsafe fn wnlen_old(s: *const u32, limit: usize) -> usize {
    let mut base = 0usize;
    while base + 16 <= limit {
        let v = Simd::<u32, 16>::from_slice(unsafe { slice::from_raw_parts(s.add(base), 16) });
        let m = v.simd_eq(Simd::splat(0)).to_bitmask();
        if m != 0 {
            return base + m.trailing_zeros() as usize;
        }
        base += 16;
    }
    while base < limit {
        if unsafe { *s.add(base) } == 0 {
            return base;
        }
        base += 1;
    }
    limit
}

macro_rules! wnlen_probe {
    ($s:expr, $limit:expr, $L:literal) => {{
        let v0 = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($s, $L) });
        let m0 = v0.simd_eq(Simd::splat(0)).to_bitmask();
        if m0 != 0 {
            return m0.trailing_zeros() as usize;
        }
        let off = $limit - $L;
        let v1 = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($s.add(off), $L) });
        let m1 = v1.simd_eq(Simd::splat(0)).to_bitmask();
        if m1 != 0 {
            return off + m1.trailing_zeros() as usize;
        }
        return $limit;
    }};
}

/// OLD wmemcmp small-n path: 16-lane u32 chunks + scalar tail (scalar-only for n<16).
#[inline(never)]
unsafe fn wmcmp_old(a: *const u32, b: *const u32, count: usize) -> i32 {
    let mut base = 0usize;
    while base + 16 <= count {
        let av = Simd::<u32, 16>::from_slice(unsafe { slice::from_raw_parts(a.add(base), 16) });
        let bv = Simd::<u32, 16>::from_slice(unsafe { slice::from_raw_parts(b.add(base), 16) });
        let d = av.simd_ne(bv).to_bitmask();
        if d != 0 {
            let j = base + d.trailing_zeros() as usize;
            let (x, y) = (unsafe { *a.add(j) } as i32, unsafe { *b.add(j) } as i32);
            return if x < y { -1 } else { 1 };
        }
        base += 16;
    }
    while base < count {
        let (x, y) = (unsafe { *a.add(base) } as i32, unsafe { *b.add(base) } as i32);
        if x != y {
            return if x < y { -1 } else { 1 };
        }
        base += 1;
    }
    0
}

macro_rules! wmcmp_probe {
    ($a:expr, $b:expr, $count:expr, $L:literal) => {{
        let v0a = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($a, $L) });
        let v0b = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($b, $L) });
        let d0 = v0a.simd_ne(v0b).to_bitmask();
        if d0 != 0 {
            let j = d0.trailing_zeros() as usize;
            let (x, y) = (unsafe { *$a.add(j) } as i32, unsafe { *$b.add(j) } as i32);
            return if x < y { -1 } else { 1 };
        }
        let off = $count - $L;
        let v1a = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($a.add(off), $L) });
        let v1b = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($b.add(off), $L) });
        let d1 = v1a.simd_ne(v1b).to_bitmask();
        if d1 != 0 {
            let j = off + d1.trailing_zeros() as usize;
            let (x, y) = (unsafe { *$a.add(j) } as i32, unsafe { *$b.add(j) } as i32);
            return if x < y { -1 } else { 1 };
        }
        return 0;
    }};
}

/// NEW wmemcmp small-n path: two overlapping u32 SIMD probes per size class.
#[inline(never)]
unsafe fn wmcmp_new(a: *const u32, b: *const u32, count: usize) -> i32 {
    if (16..32).contains(&count) {
        wmcmp_probe!(a, b, count, 16);
    } else if (8..16).contains(&count) {
        wmcmp_probe!(a, b, count, 8);
    }
    unsafe { wmcmp_old(a, b, count) }
}

/// OLD wmemchr small-n path: 16-lane u32 chunks + scalar tail (scalar-only for n<16).
#[inline(never)]
unsafe fn wmchr_old(s: *const u32, c: u32, count: usize) -> Option<usize> {
    let mut base = 0usize;
    while base + 16 <= count {
        let v = Simd::<u32, 16>::from_slice(unsafe { slice::from_raw_parts(s.add(base), 16) });
        let m = v.simd_eq(Simd::splat(c)).to_bitmask();
        if m != 0 {
            return Some(base + m.trailing_zeros() as usize);
        }
        base += 16;
    }
    while base < count {
        if unsafe { *s.add(base) } == c {
            return Some(base);
        }
        base += 1;
    }
    None
}

macro_rules! wmchr_probe {
    ($s:expr, $c:expr, $count:expr, $L:literal) => {{
        let t = Simd::<u32, $L>::splat($c);
        let v0 = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($s, $L) });
        let m0 = v0.simd_eq(t).to_bitmask();
        if m0 != 0 {
            return Some(m0.trailing_zeros() as usize);
        }
        let off = $count - $L;
        let v1 = Simd::<u32, $L>::from_slice(unsafe { slice::from_raw_parts($s.add(off), $L) });
        let m1 = v1.simd_eq(t).to_bitmask();
        if m1 != 0 {
            return Some(off + m1.trailing_zeros() as usize);
        }
        return None;
    }};
}

/// NEW wmemchr small-n path: two overlapping u32 SIMD probes per size class.
#[inline(never)]
unsafe fn wmchr_new(s: *const u32, c: u32, count: usize) -> Option<usize> {
    if (16..32).contains(&count) {
        wmchr_probe!(s, c, count, 16);
    } else if (8..16).contains(&count) {
        wmchr_probe!(s, c, count, 8);
    }
    unsafe { wmchr_old(s, c, count) }
}

/// NEW wcsnlen small-n path: two overlapping u32 SIMD probes per size class.
#[inline(never)]
unsafe fn wnlen_new(s: *const u32, limit: usize) -> usize {
    if (16..32).contains(&limit) {
        wnlen_probe!(s, limit, 16);
    } else if (8..16).contains(&limit) {
        wnlen_probe!(s, limit, 8);
    } else if (4..8).contains(&limit) {
        wnlen_probe!(s, limit, 4);
    }
    unsafe { wnlen_old(s, limit) }
}

/// OLD memset small-n path: 8-aligned u64 volatile stores + byte head/tail.
#[inline(never)]
unsafe fn memset_old(dst: *mut u8, value: u8, n: usize) {
    let word = (value as u64).wrapping_mul(0x0101_0101_0101_0101);
    let mut i = 0usize;
    let head = ((dst as usize).wrapping_neg() & 7).min(n);
    while i < head {
        unsafe { std::ptr::write_volatile(dst.add(i), value) };
        i += 1;
    }
    while i + 32 <= n {
        let p = unsafe { dst.add(i).cast::<u64>() };
        unsafe {
            std::ptr::write_volatile(p, word);
            std::ptr::write_volatile(p.add(1), word);
            std::ptr::write_volatile(p.add(2), word);
            std::ptr::write_volatile(p.add(3), word);
        }
        i += 32;
    }
    while i + 8 <= n {
        unsafe { std::ptr::write_volatile(dst.add(i).cast::<u64>(), word) };
        i += 8;
    }
    while i < n {
        unsafe { std::ptr::write_volatile(dst.add(i), value) };
        i += 1;
    }
}

/// NEW memset small-n path: straight-line OVERLAPPING _mm_storeu_si128 (SSE2) vector
/// stores — explicit instructions, never lowered to @llvm.memset (recursion-safe).
#[inline(never)]
unsafe fn memset_new(dst: *mut u8, value: u8, n: usize) {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::{__m128i, _mm_set1_epi8, _mm_storeu_si128};
    unsafe {
        if n >= 16 {
            let v = _mm_set1_epi8(value as i8);
            let mut i = 0usize;
            // straight-line stride-16 stores (NOT a constant-fill loop idiom: compiler
            // still keeps explicit storeu instructions) + one overlapping tail store.
            while i + 16 <= n {
                _mm_storeu_si128(dst.add(i).cast::<__m128i>(), v);
                i += 16;
            }
            _mm_storeu_si128(dst.add(n - 16).cast::<__m128i>(), v);
        } else {
            // n < 16: overlapping power-of-2 scalar stores.
            let word = (value as u64).wrapping_mul(0x0101_0101_0101_0101);
            if n >= 8 {
                std::ptr::write_unaligned(dst.cast::<u64>(), word);
                std::ptr::write_unaligned(dst.add(n - 8).cast::<u64>(), word);
            } else if n >= 4 {
                let w = value as u32 as u64 * 0x0101_0101;
                std::ptr::write_unaligned(dst.cast::<u32>(), w as u32);
                std::ptr::write_unaligned(dst.add(n - 4).cast::<u32>(), w as u32);
            } else {
                for j in 0..n {
                    *dst.add(j) = value;
                }
            }
        }
    }
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

    // strcmp A/B: EQUAL strings (NUL in first 32B panel = the case where the old scan
    // flags then re-scans with SWAR). bound large (NUL-terminated). glibc returns 0.
    let g_scmp =
        unsafe { std::mem::transmute::<usize, CmpFn>(host_sym(b"strcmp\0")) };
    for &len in &[7usize, 15, 23, 31, 47, 63] {
        let mut a = backing.clone();
        let mut bb = backing.clone();
        for k in 0..len {
            a[k] = b'a' + (k % 26) as u8;
            bb[k] = b'a' + (k % 26) as u8;
        }
        a[len] = 0;
        bb[len] = 0;
        let p1 = a.as_ptr();
        let p2 = bb.as_ptr();
        let bound = backing.len();
        assert_eq!(unsafe { scmp_old(p1, p2, bound) }, len, "scmp_old off len={len}");
        assert_eq!(unsafe { scmp_new(p1, p2, bound) }, len, "scmp_new off len={len}");
        assert_eq!(unsafe { g_scmp(p1.cast(), p2.cast()) }, 0, "glibc strcmp eq len={len}");
        let old_t = measure(|| unsafe { scmp_old(black_box(p1), black_box(p2), bound) } as u64);
        let new_t = measure(|| unsafe { scmp_new(black_box(p1), black_box(p2), bound) } as u64);
        let g_t = measure(|| unsafe { g_scmp(black_box(p1.cast()), black_box(p2.cast())) } as i64 as u64);
        println!(
            "SCMP_AB len={len:<3} old_p50_ns={old_t:.3} new_p50_ns={new_t:.3} glibc_p50_ns={g_t:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // memchr A/B: ABSENT byte in [16,32)-byte buffers (full scan = the small-n floor).
    type MchrFn = unsafe extern "C" fn(*const c_void, i32, usize) -> *mut c_void;
    let g_mchr =
        unsafe { std::mem::transmute::<usize, MchrFn>(host_sym(b"memchr\0")) };
    let absent = 0x01u8;
    for &len in &[16usize, 19, 23, 27, 31] {
        let mut buf = backing.clone();
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..32usize {
            for k in 0..len {
                buf[off + k] = b'a' + (k % 26) as u8;
            }
            let p = unsafe { buf.as_ptr().add(off) };
            assert_eq!(unsafe { mchr_old(p, absent, len) }, None, "mchr_old off={off} len={len}");
            assert_eq!(unsafe { mchr_new(p, absent, len) }, None, "mchr_new off={off} len={len}");
            assert!(unsafe { g_mchr(p.cast(), absent as i32, len) }.is_null());
            // also a present-byte correctness check at a couple positions
            for &pos in &[0usize, len / 2, len - 1] {
                buf[off + pos] = absent;
                assert_eq!(unsafe { mchr_new(p, absent, len) }, Some(pos), "mchr_new present off={off} len={len} pos={pos}");
                let gp = unsafe { g_mchr(p.cast(), absent as i32, len) };
                assert_eq!(gp as usize - p as usize, pos, "glibc present");
                buf[off + pos] = b'a' + (pos % 26) as u8;
            }
            old_t += measure(|| unsafe { mchr_old(black_box(p), absent, len) }.unwrap_or(99) as u64);
            new_t += measure(|| unsafe { mchr_new(black_box(p), absent, len) }.unwrap_or(99) as u64);
            g_t += measure(|| unsafe { g_mchr(black_box(p.cast()), absent as i32, len) } as usize as u64);
        }
        println!(
            "MCHR_AB len={len:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 32.0,
            new_t / 32.0,
            g_t / 32.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // memrchr A/B: ABSENT byte in [16,32)-byte buffers (full reverse scan). glibc memrchr.
    let g_mrchr =
        unsafe { std::mem::transmute::<usize, MchrFn>(host_sym(b"memrchr\0")) };
    let absent2 = 0x01u8;
    for &len in &[16usize, 19, 23, 27, 31] {
        let mut buf = backing.clone();
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..32usize {
            for k in 0..len {
                buf[off + k] = b'a' + (k % 26) as u8;
            }
            let p = unsafe { buf.as_ptr().add(off) };
            assert_eq!(unsafe { mrchr_old(p, absent2, len) }, None, "mrchr_old off={off} len={len}");
            assert_eq!(unsafe { mrchr_new(p, absent2, len) }, None, "mrchr_new off={off} len={len}");
            assert!(unsafe { g_mrchr(p.cast(), absent2 as i32, len) }.is_null());
            // present-byte LAST-match correctness (two matches; want the higher)
            for &(lo, hi) in &[(0usize, len - 1), (1, len / 2), (len / 3, len - 2)] {
                if lo >= hi || hi >= len {
                    continue;
                }
                buf[off + lo] = absent2;
                buf[off + hi] = absent2;
                assert_eq!(unsafe { mrchr_new(p, absent2, len) }, Some(hi), "mrchr_new last off={off} len={len}");
                let gp = unsafe { g_mrchr(p.cast(), absent2 as i32, len) };
                assert_eq!(gp as usize - p as usize, hi, "glibc memrchr last");
                buf[off + lo] = b'a' + (lo % 26) as u8;
                buf[off + hi] = b'a' + (hi % 26) as u8;
            }
            old_t += measure(|| unsafe { mrchr_old(black_box(p), absent2, len) }.unwrap_or(99) as u64);
            new_t += measure(|| unsafe { mrchr_new(black_box(p), absent2, len) }.unwrap_or(99) as u64);
            g_t += measure(|| unsafe { g_mrchr(black_box(p.cast()), absent2 as i32, len) } as usize as u64);
        }
        println!(
            "MRCHR_AB len={len:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 32.0,
            new_t / 32.0,
            g_t / 32.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // strnlen A/B: NO NUL in [0,limit) (full scan to limit = worst case). glibc strnlen.
    type SnlenFn = unsafe extern "C" fn(*const c_char, usize) -> usize;
    let g_snlen =
        unsafe { std::mem::transmute::<usize, SnlenFn>(host_sym(b"strnlen\0")) };
    for &limit in &[16usize, 19, 23, 27, 31] {
        let mut buf = backing.clone();
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..32usize {
            // Fill [off, off+limit) with non-NUL so the scan runs the full limit.
            for k in 0..limit {
                buf[off + k] = b'a' + (k % 26) as u8;
            }
            let p = unsafe { buf.as_ptr().add(off) };
            assert_eq!(unsafe { snlen_old(p, limit) }, limit, "snlen_old off={off} limit={limit}");
            assert_eq!(unsafe { snlen_new(p, limit) }, limit, "snlen_new off={off} limit={limit}");
            assert_eq!(unsafe { g_snlen(p.cast(), limit) }, limit, "glibc strnlen full");
            // present-NUL FIRST-occurrence correctness at a couple positions
            for &pos in &[0usize, limit / 2, limit - 1] {
                buf[off + pos] = 0;
                assert_eq!(unsafe { snlen_new(p, limit) }, pos, "snlen_new first off={off} limit={limit} pos={pos}");
                assert_eq!(unsafe { g_snlen(p.cast(), limit) }, pos, "glibc strnlen first");
                buf[off + pos] = b'a' + (pos % 26) as u8;
            }
            old_t += measure(|| unsafe { snlen_old(black_box(p), limit) } as u64);
            new_t += measure(|| unsafe { snlen_new(black_box(p), limit) } as u64);
            g_t += measure(|| unsafe { g_snlen(black_box(p.cast()), limit) } as u64);
        }
        println!(
            "SNLEN_AB lim={limit:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 32.0,
            new_t / 32.0,
            g_t / 32.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // wcsnlen A/B: NO NUL in [0,limit) wchars (full scan). glibc wcsnlen (wchar_t=u32).
    type WNlenFn = unsafe extern "C" fn(*const u32, usize) -> usize;
    let g_wnlen =
        unsafe { std::mem::transmute::<usize, WNlenFn>(host_sym(b"wcsnlen\0")) };
    let mut wbuf = vec![0x41u32; 4096];
    for &limit in &[4usize, 6, 8, 12, 15, 16, 23, 31] {
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..16usize {
            for k in 0..limit {
                wbuf[off + k] = 0x41 + (k as u32 % 26);
            }
            let p = unsafe { wbuf.as_ptr().add(off) };
            assert_eq!(unsafe { wnlen_old(p, limit) }, limit, "wnlen_old off={off} limit={limit}");
            assert_eq!(unsafe { wnlen_new(p, limit) }, limit, "wnlen_new off={off} limit={limit}");
            assert_eq!(unsafe { g_wnlen(p, limit) }, limit, "glibc wcsnlen full");
            for &pos in &[0usize, limit / 2, limit - 1] {
                wbuf[off + pos] = 0;
                assert_eq!(unsafe { wnlen_new(p, limit) }, pos, "wnlen_new first off={off} limit={limit} pos={pos}");
                assert_eq!(unsafe { g_wnlen(p, limit) }, pos, "glibc wcsnlen first");
                wbuf[off + pos] = 0x41 + (pos as u32 % 26);
            }
            old_t += measure(|| unsafe { wnlen_old(black_box(p), limit) } as u64);
            new_t += measure(|| unsafe { wnlen_new(black_box(p), limit) } as u64);
            g_t += measure(|| unsafe { g_wnlen(black_box(p), limit) } as u64);
        }
        println!(
            "WNLEN_AB lim={limit:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 16.0,
            new_t / 16.0,
            g_t / 16.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // wmemchr A/B: ABSENT target in [8,32) wchars (full scan). glibc wmemchr.
    type WMchrFn = unsafe extern "C" fn(*const u32, u32, usize) -> *mut u32;
    let g_wmchr =
        unsafe { std::mem::transmute::<usize, WMchrFn>(host_sym(b"wmemchr\0")) };
    let needle = 0x0000_0001u32;
    for &count in &[8usize, 12, 15, 16, 23, 31] {
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..16usize {
            for k in 0..count {
                wbuf[off + k] = 0x41 + (k as u32 % 26);
            }
            let p = unsafe { wbuf.as_ptr().add(off) };
            assert_eq!(unsafe { wmchr_old(p, needle, count) }, None, "wmchr_old off={off} count={count}");
            assert_eq!(unsafe { wmchr_new(p, needle, count) }, None, "wmchr_new off={off} count={count}");
            assert!(unsafe { g_wmchr(p, needle, count) }.is_null());
            for &pos in &[0usize, count / 2, count - 1] {
                wbuf[off + pos] = needle;
                assert_eq!(unsafe { wmchr_new(p, needle, count) }, Some(pos), "wmchr_new first off={off} count={count} pos={pos}");
                let gp = unsafe { g_wmchr(p, needle, count) };
                assert_eq!((gp as usize - p as usize) / 4, pos, "glibc wmemchr first");
                wbuf[off + pos] = 0x41 + (pos as u32 % 26);
            }
            old_t += measure(|| unsafe { wmchr_old(black_box(p), needle, count) }.unwrap_or(99) as u64);
            new_t += measure(|| unsafe { wmchr_new(black_box(p), needle, count) }.unwrap_or(99) as u64);
            g_t += measure(|| unsafe { g_wmchr(black_box(p), needle, count) } as usize as u64);
        }
        println!(
            "WMCHR_AB cnt={count:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 16.0,
            new_t / 16.0,
            g_t / 16.0,
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // strcasecmp A/B: case-insensitively EQUAL strings (NUL in first 32B panel = the
    // re-scan case). bound large (NUL-terminated). glibc strcasecmp returns 0.
    let g_scasecmp =
        unsafe { std::mem::transmute::<usize, CmpFn>(host_sym(b"strcasecmp\0")) };
    for &len in &[7usize, 15, 23, 31, 47, 63] {
        let mut a = backing.clone();
        let mut bb = backing.clone();
        for k in 0..len {
            // upper in a, lower in b => case-insensitively equal
            a[k] = b'A' + (k % 26) as u8;
            bb[k] = b'a' + (k % 26) as u8;
        }
        a[len] = 0;
        bb[len] = 0;
        let p1 = a.as_ptr();
        let p2 = bb.as_ptr();
        let bound = backing.len();
        assert_eq!(unsafe { scasecmp_old(p1, p2, bound) }.0, 0, "scasecmp_old eq len={len}");
        assert_eq!(unsafe { scasecmp_new(p1, p2, bound) }.0, 0, "scasecmp_new eq len={len}");
        assert_eq!(unsafe { g_scasecmp(p1.cast(), p2.cast()) }, 0, "glibc strcasecmp eq len={len}");
        // a differing byte at a couple positions: signs must agree with glibc
        for &pos in &[0usize, len / 2, len - 1] {
            let save = bb[pos];
            bb[pos] = b'a' + ((pos + 5) % 26) as u8;
            let want = unsafe { g_scasecmp(p1.cast(), p2.cast()) }.signum();
            assert_eq!(unsafe { scasecmp_old(p1, p2, bound) }.0.signum(), want, "old sign len={len} pos={pos}");
            assert_eq!(unsafe { scasecmp_new(p1, p2, bound) }.0.signum(), want, "new sign len={len} pos={pos}");
            bb[pos] = save;
        }
        let old_t = measure(|| unsafe { scasecmp_old(black_box(p1), black_box(p2), bound) }.0 as i64 as u64);
        let new_t = measure(|| unsafe { scasecmp_new(black_box(p1), black_box(p2), bound) }.0 as i64 as u64);
        let g_t = measure(|| unsafe { g_scasecmp(black_box(p1.cast()), black_box(p2.cast())) } as i64 as u64);
        println!(
            "SCASE_AB len={len:<3} old_p50_ns={old_t:.3} new_p50_ns={new_t:.3} glibc_p50_ns={g_t:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // wmemcmp A/B: EQUAL buffers (full scan worst case) + a differing-position sweep.
    type WMcmpFn = unsafe extern "C" fn(*const u32, *const u32, usize) -> i32;
    let g_wmcmp =
        unsafe { std::mem::transmute::<usize, WMcmpFn>(host_sym(b"wmemcmp\0")) };
    let mut wa = vec![0x41u32; 4096];
    let mut wbb = vec![0x41u32; 4096];
    for &count in &[4usize, 6, 8, 12, 15, 16, 23, 31] {
        for k in 0..count {
            wa[k] = 0x41 + (k as u32 % 26);
            wbb[k] = 0x41 + (k as u32 % 26);
        }
        let p1 = wa.as_ptr();
        let p2 = wbb.as_ptr();
        // correctness: flip one element at each position, signs must agree with glibc
        for pos in 0..count {
            let save = wbb[pos];
            wbb[pos] = wa[pos] + 1;
            let want = unsafe { g_wmcmp(p1, p2, count) }.signum();
            assert_eq!(unsafe { wmcmp_old(p1, p2, count) }.signum(), want, "wmcmp_old n={count} pos={pos}");
            assert_eq!(unsafe { wmcmp_new(p1, p2, count) }.signum(), want, "wmcmp_new n={count} pos={pos}");
            wbb[pos] = save;
        }
        assert_eq!(unsafe { wmcmp_new(p1, p2, count) }, 0, "wmcmp_new eq n={count}");
        let old_t = measure(|| unsafe { wmcmp_old(black_box(p1), black_box(p2), count) } as i64 as u64);
        let new_t = measure(|| unsafe { wmcmp_new(black_box(p1), black_box(p2), count) } as i64 as u64);
        let g_t = measure(|| unsafe { g_wmcmp(black_box(p1), black_box(p2), count) } as i64 as u64);
        println!(
            "WMCMP_AB cnt={count:<3} old_p50_ns={old_t:.3} new_p50_ns={new_t:.3} glibc_p50_ns={g_t:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            new_t / old_t,
            new_t / g_t,
            old_t / g_t
        );
    }

    // memset A/B: small-n fill. OLD volatile u64 vs NEW overlapping _mm_storeu vs glibc.
    type MemsetFn = unsafe extern "C" fn(*mut c_void, i32, usize) -> *mut c_void;
    let g_memset =
        unsafe { std::mem::transmute::<usize, MemsetFn>(host_sym(b"memset\0")) };
    let mut dbuf = vec![0u8; 4096];
    for &n in &[7usize, 15, 16, 23, 31, 32, 47, 63] {
        let mut old_t = 0.0;
        let mut new_t = 0.0;
        let mut g_t = 0.0;
        for off in 0..16usize {
            let p = unsafe { dbuf.as_mut_ptr().add(off) };
            // byte-identity check vs a reference fill
            let mut refb = vec![0xAAu8; n + 16];
            unsafe { memset_old(p, 0x5A, n) };
            refb[..n].copy_from_slice(unsafe { slice::from_raw_parts(p, n) });
            unsafe { memset_new(p, 0x3C, n) };
            assert!(unsafe { slice::from_raw_parts(p, n) }.iter().all(|&b| b == 0x3C), "new fill n={n}");
            unsafe { g_memset(p.cast(), 0x5A, n) };
            assert_eq!(unsafe { slice::from_raw_parts(p, n) }, &refb[..n], "new vs glibc bytes n={n}");
            old_t += measure(|| { unsafe { memset_old(black_box(p), 0x11, n) }; black_box(p) as u64 });
            new_t += measure(|| { unsafe { memset_new(black_box(p), 0x22, n) }; black_box(p) as u64 });
            g_t += measure(|| unsafe { g_memset(black_box(p.cast()), 0x33, n) } as u64);
        }
        println!(
            "MEMSET_AB n={n:<3} old_p50_ns={:.3} new_p50_ns={:.3} glibc_p50_ns={:.3} \
             new/old={:.3} new/glibc={:.3} old/glibc={:.3}",
            old_t / 16.0,
            new_t / 16.0,
            g_t / 16.0,
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
