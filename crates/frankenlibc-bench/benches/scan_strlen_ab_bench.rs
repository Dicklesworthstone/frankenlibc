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
    let backing = vec![b'x'; 4096];
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

    let mut grp = c.benchmark_group("scan_ab");
    grp.bench_function("noop", |bb| bb.iter(|| black_box(1u8)));
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
