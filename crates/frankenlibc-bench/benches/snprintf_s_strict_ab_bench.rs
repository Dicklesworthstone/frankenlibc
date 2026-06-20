//! In-process A/B for the deployed strict `snprintf("%s", str)` copy kernel
//! (cc/BlackThrush, BOLD-VERIFY).
//!
//! WHY THIS EXISTS: the rch fleet lands each `rch exec` on a different worker
//! with an isolated target dir, so criterion baselines never persist and
//! cross-run absolute ns are not comparable (the same fl snprintf measured
//! 22/40/103/120 ns across workers). The ONLY worker-variance-immune metric is
//! a within-process ratio. This bench measures THREE kernels in ONE process so
//! their ratios are directly comparable regardless of which (loaded) worker runs
//! it:
//!   1. `old_strict_s`  — the previous `strict_direct_snprintf_s` fused scalar
//!                        scan+copy byte loop (a per-byte bound branch).
//!   2. `new_strict_s`  — page-safe SWAR/SIMD strlen (verbatim copy of the
//!                        deployed `strlen`'s `scan_c_string` None branch, NO
//!                        membrane `known_remaining`) + `memcpy`. THE SHIPPED kernel.
//!   3. `host glibc`    — real `libc::snprintf` (this bench links NO fl symbols,
//!                        so `libc::snprintf` resolves to host glibc directly —
//!                        no dlmopen needed, no symbol collision).
//!
//! Both kernels are EXACT mirrors of production `strict_direct_snprintf_s` (size==0,
//! NULL→"(null)", "%s\n", truncation, return = full source length). `verify()`
//! runs first and asserts new==old for every edge case (byte-identity of the
//! shipped change) and new==glibc for the plain "%s" cases — executable proof,
//! since the deployed strict path lives in `#[cfg(not(test))] mod stdio_abi` and
//! is unreachable from `cargo test`.
#![feature(portable_simd)]

use std::hint::black_box;
use std::os::raw::c_char;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Previous deployed kernel: fused scalar NUL-scan + copy with a per-byte bound
/// branch. Exact mirror of the pre-change `strict_direct_snprintf_s`.
unsafe fn old_strict_s(str_buf: *mut c_char, size: usize, arg: *const c_char, newline: bool) -> i32 {
    let mut len = 0usize;
    if size == 0 || str_buf.is_null() {
        if arg.is_null() {
            len = b"(null)".len();
        } else {
            let src = arg.cast::<u8>();
            while unsafe { *src.add(len) } != 0 {
                len += 1;
            }
        }
        return (len + usize::from(newline)) as i32;
    }
    let dst = str_buf.cast::<u8>();
    let copy_limit = size - 1;
    if arg.is_null() {
        for &byte in b"(null)" {
            if len < copy_limit {
                unsafe { *dst.add(len) = byte };
            }
            len += 1;
        }
    } else {
        let src = arg.cast::<u8>();
        loop {
            let byte = unsafe { *src.add(len) };
            if byte == 0 {
                break;
            }
            if len < copy_limit {
                unsafe { *dst.add(len) = byte };
            }
            len += 1;
        }
    }
    let total_len = len + usize::from(newline);
    if newline && len < copy_limit {
        unsafe { *dst.add(len) = b'\n' };
    }
    unsafe { *dst.add(total_len.min(copy_limit)) = 0 };
    total_len as i32
}

/// SWAR zero-byte test — identical to `string_abi::swar_word_has_zero`.
#[inline(always)]
fn swar_word_has_zero(w: u64) -> bool {
    w.wrapping_sub(0x0101_0101_0101_0101) & !w & 0x8080_8080_8080_8080 != 0
}

/// Page-safe NUL scan — a verbatim copy of `string_abi::scan_c_string`'s
/// unbounded (None) branch. An 8-aligned 8-byte load never straddles a 4096-byte
/// page, so it cannot fault past the NUL's own mapped page.
unsafe fn swar_strlen(ptr: *const c_char) -> usize {
    use core::simd::cmp::SimdPartialEq;
    use core::simd::Simd;
    let p = ptr.cast::<u8>();
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
            let v = Simd::<u8, 32>::from_slice(unsafe { core::slice::from_raw_parts(p.add(i), 32) });
            if !v.simd_eq(Simd::splat(0)).any() {
                i += 32;
                continue;
            }
        }
        let w = unsafe { *p.add(i).cast::<u64>() };
        if swar_word_has_zero(w) {
            for j in 0..8 {
                if unsafe { *p.add(i + j) } == 0 {
                    return i + j;
                }
            }
        }
        i += 8;
    }
}

/// Shipped kernel: page-safe SWAR/SIMD strlen + `memcpy`, no membrane lookup.
/// Exact mirror of the post-change `strict_direct_snprintf_s`.
unsafe fn new_strict_s(str_buf: *mut c_char, size: usize, arg: *const c_char, newline: bool) -> i32 {
    let src: &[u8] = if arg.is_null() {
        b"(null)"
    } else {
        let len = unsafe { swar_strlen(arg) };
        unsafe { core::slice::from_raw_parts(arg.cast::<u8>(), len) }
    };
    let len = src.len();
    if size == 0 || str_buf.is_null() {
        return (len + usize::from(newline)) as i32;
    }
    let dst = str_buf.cast::<u8>();
    let copy_limit = size - 1;
    let string_copy = len.min(copy_limit);
    if string_copy > 0 {
        unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, string_copy) };
    }
    let total_len = len + usize::from(newline);
    if newline && len < copy_limit {
        unsafe { *dst.add(len) = b'\n' };
    }
    unsafe { *dst.add(total_len.min(copy_limit)) = 0 };
    total_len as i32
}

/// Executable byte-identity proof. Panics (failing the bench) on any mismatch.
fn verify() {
    // (arg_bytes_with_nul or None, size, newline)
    let cases: &[(Option<&[u8]>, usize, bool)] = &[
        (Some(b"hello\0"), 128, false),
        (Some(b"hi\0"), 128, true),
        (Some(b"abcdefgh\0"), 4, false), // truncation
        (Some(b"abcdef\0"), 4, true),    // newline doesn't fit
        (Some(b"abc\0"), 4, false),      // exact fit
        (Some(b"ab\0"), 4, true),        // newline fits
        (Some(b"\0"), 8, false),         // empty string
        (Some(b"x\0"), 1, false),        // size 1 -> only NUL room
        (None, 128, false),              // NULL -> "(null)"
        (None, 4, false),                // NULL truncated
        (Some(b"abcdefgh\0"), 0, false), // size 0 -> count only
    ];
    for &(arg, size, newline) in cases {
        let argp = match arg {
            Some(b) => b.as_ptr() as *const c_char,
            None => std::ptr::null(),
        };
        let mut a = [0x7fi8; 32];
        let mut b = [0x7fi8; 32];
        let ra = unsafe { old_strict_s(a.as_mut_ptr(), size, argp, newline) };
        let rb = unsafe { new_strict_s(b.as_mut_ptr(), size, argp, newline) };
        assert_eq!(ra, rb, "rc mismatch old vs new for {arg:?} size={size} nl={newline}");
        assert_eq!(a, b, "bytes mismatch old vs new for {arg:?} size={size} nl={newline}");
    }
    // new == glibc for the plain "%s" cases glibc supports (non-null, no newline).
    let fmt = c"%s";
    for &(arg, size) in &[(b"hello\0".as_slice(), 128usize), (b"abcdefgh\0", 4), (b"abc\0", 4)] {
        let argp = arg.as_ptr() as *const c_char;
        let mut g = [0x7fi8; 32];
        let mut n = [0x7fi8; 32];
        let rg = unsafe { libc::snprintf(g.as_mut_ptr(), size, fmt.as_ptr(), argp) };
        let rn = unsafe { new_strict_s(n.as_mut_ptr(), size, argp, false) };
        assert_eq!(rg, rn, "rc mismatch glibc vs new for {arg:?} size={size}");
        assert_eq!(g, n, "bytes mismatch glibc vs new for {arg:?} size={size}");
    }
}

fn bench(c: &mut Criterion) {
    verify(); // byte-identity proof runs before any measurement

    let payloads: &[(&str, usize)] = &[("8B", 8), ("38B", 38), ("200B", 200)];
    let fmt = c"%s";

    for &(name, n) in payloads {
        let s: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
        let cstr = std::ffi::CString::new(s).expect("payload");
        let arg = cstr.as_ptr();

        let mut group = c.benchmark_group(format!("snprintf_s_strict_{name}"));
        group.throughput(Throughput::Bytes(n as u64));

        group.bench_with_input(BenchmarkId::new("old_byteloop", name), &arg, |b, &arg| {
            b.iter(|| {
                let mut buf = [0i8; 256];
                let rc = unsafe { old_strict_s(buf.as_mut_ptr(), buf.len(), black_box(arg), false) };
                black_box((rc, buf[0]));
            });
        });

        group.bench_with_input(BenchmarkId::new("new_swar_memcpy", name), &arg, |b, &arg| {
            b.iter(|| {
                let mut buf = [0i8; 256];
                let rc = unsafe { new_strict_s(buf.as_mut_ptr(), buf.len(), black_box(arg), false) };
                black_box((rc, buf[0]));
            });
        });

        group.bench_with_input(BenchmarkId::new("host_glibc", name), &arg, |b, &arg| {
            b.iter(|| {
                let mut buf = [0i8; 256];
                let rc = unsafe {
                    libc::snprintf(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), black_box(arg))
                };
                black_box((rc, buf[0]));
            });
        });

        group.finish();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = bench
}
criterion_main!(benches);
