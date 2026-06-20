//! Measures the shipped `memset` fill primitive (`raw_memset_bytes`) against the
//! old byte-at-a-time volatile loop it replaced and against host glibc `memset`.
//!
//! Deterministic fixed-iteration timing (robust under a contended remote worker
//! where Criterion's adaptive windows produce garbage). Reports best-of-K median
//! ns/op so transient scheduler noise is rejected.
//!
//! Run: `cargo bench -p frankenlibc-bench --features abi-bench --bench memset_abi_bench`
use std::ffi::c_void;
use std::hint::black_box;
use std::time::Instant;

use frankenlibc_abi::string_abi::{
    bench_raw_memcpy_bytes, bench_raw_memmove_bytes, bench_raw_memset_bytes, bench_scan_c_string,
    bench_scan_c_string_for_byte, bench_scan_c_string_last_byte, bench_scan_strcasecmp,
    bench_scan_strcmp,
};
use frankenlibc_abi::wchar_abi::{
    bench_scan_wcscasecmp_simd, bench_scan_wcscmp_simd, bench_wide_find_or_nul_simd,
    bench_wide_last_before_nul_simd,
};

/// Pre-lever wcscasecmp: scalar wchar_t (u32) ASCII-folded compare to diff/NUL.
#[inline(never)]
unsafe fn old_scalar_wcscasecmp(s1: *const u32, s2: *const u32) -> i32 {
    #[inline(always)]
    fn lower(c: u32) -> u32 {
        if (0x41..=0x5A).contains(&c) {
            c + 0x20
        } else {
            c
        }
    }
    unsafe {
        let mut i = 0usize;
        loop {
            let raw = *s1.add(i);
            let a = lower(raw);
            let b = lower(*s2.add(i));
            if a != b || raw == 0 {
                return a.wrapping_sub(b) as i32;
            }
            i += 1;
        }
    }
}

/// Pre-lever wcscmp: scalar wchar_t (u32) element-at-a-time compare to diff/NUL.
#[inline(never)]
unsafe fn old_scalar_wcscmp(s1: *const u32, s2: *const u32) -> i32 {
    unsafe {
        let mut i = 0usize;
        loop {
            let a = *s1.add(i);
            let b = *s2.add(i);
            if a != b {
                return if (a as i32) < (b as i32) { -1 } else { 1 };
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

unsafe extern "C" {
    fn wcschr(s: *const u32, c: u32) -> *mut u32;
    fn wcsrchr(s: *const u32, c: u32) -> *mut u32;
    fn wcscmp(s1: *const u32, s2: *const u32) -> i32;
    fn wcscasecmp(s1: *const u32, s2: *const u32) -> i32;
    fn wcsstr(haystack: *const u32, needle: *const u32) -> *mut u32;
    fn wmemcmp(s1: *const u32, s2: *const u32, n: usize) -> i32;
}

/// Pre-lever wmemcmp: scalar wchar_t (u32) element-at-a-time bounded compare.
#[inline(never)]
fn old_scalar_wmemcmp(a: &[u32], b: &[u32]) -> i32 {
    for i in 0..a.len() {
        if a[i] != b[i] {
            return if (a[i] as i32) < (b[i] as i32) { -1 } else { 1 };
        }
    }
    0
}

/// Pre-lever wcsstr: brute-force O(n*m) double-loop (absent needle => full scan).
#[inline(never)]
unsafe fn old_bruteforce_wcsstr(hay: *const u32, hay_len: usize, needle: &[u32]) -> *const u32 {
    unsafe {
        let m = needle.len();
        if m == 0 {
            return hay;
        }
        let mut h = 0usize;
        while h + m <= hay_len {
            let mut k = 0usize;
            while k < m && *hay.add(h + k) == needle[k] {
                k += 1;
            }
            if k == m {
                return hay.add(h);
            }
            h += 1;
        }
        std::ptr::null()
    }
}

/// New-lever wcsstr: SIMD first-element prefilter (mirrors the shipped wcsstr).
#[inline(never)]
unsafe fn new_prefilter_wcsstr(hay: *const u32, hay_len: usize, needle: &[u32]) -> *const u32 {
    unsafe {
        let m = needle.len();
        if m == 0 {
            return hay;
        }
        let n0 = needle[0];
        let mut h = 0usize;
        loop {
            let (idx, found) = bench_wide_find_or_nul_simd(hay.add(h), n0);
            if !found {
                return std::ptr::null();
            }
            let pos = h + idx;
            if pos + m > hay_len {
                return std::ptr::null();
            }
            let mut k = 1usize;
            while k < m && *hay.add(pos + k) == needle[k] {
                k += 1;
            }
            if k == m {
                return hay.add(pos);
            }
            h = pos + 1;
        }
    }
}

/// Pre-lever wcschr: scalar wchar_t (u32) scan to target-or-NUL.
#[inline(never)]
unsafe fn old_scalar_wcschr(s: *const u32, c: u32) -> Option<usize> {
    unsafe {
        let mut i = 0usize;
        loop {
            let ch = *s.add(i);
            if ch == c {
                return Some(i);
            }
            if ch == 0 {
                return None;
            }
            i += 1;
        }
    }
}

/// Pre-lever wcsrchr: scalar wchar_t (u32) scan to NUL, tracking last target.
#[inline(never)]
unsafe fn old_scalar_wcsrchr(s: *const u32, c: u32) -> Option<usize> {
    unsafe {
        let mut last = None;
        let mut i = 0usize;
        loop {
            let ch = *s.add(i);
            if ch == c {
                last = Some(i);
            }
            if ch == 0 {
                return last;
            }
            i += 1;
        }
    }
}

/// Pre-lever strncpy copy+pad: byte-at-a-time copy to NUL then byte NUL-pad.
#[inline(never)]
unsafe fn old_byte_strncpy(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        let mut i = 0usize;
        while i < n {
            let ch = *src.add(i);
            *dst.add(i) = ch;
            i += 1;
            if ch == 0 {
                break;
            }
        }
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
    }
}

/// New-lever strncpy: SWAR scan + wide copy + wide pad (the shipped composition).
#[inline(never)]
unsafe fn new_strncpy(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        let k = bench_scan_c_string(src.cast::<std::os::raw::c_char>(), Some(n)).0;
        let copy_len = k.min(n);
        bench_raw_memcpy_bytes(dst, src, copy_len);
        if copy_len < n {
            bench_raw_memset_bytes(dst.add(copy_len), 0, n - copy_len);
        }
    }
}

/// Pre-lever strncasecmp scan: byte-at-a-time tolower compare to first diff/NUL.
#[inline(never)]
unsafe fn old_byte_strcasecmp(
    p1: *const std::os::raw::c_char,
    p2: *const std::os::raw::c_char,
) -> i32 {
    unsafe {
        let mut i = 0usize;
        loop {
            let a = (*p1.add(i) as u8).to_ascii_lowercase();
            let b = (*p2.add(i) as u8).to_ascii_lowercase();
            if a != b {
                return (a as i32) - (b as i32);
            }
            if a == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// Pre-lever strrchr scan: byte-at-a-time, tracking the last target before NUL.
#[inline(never)]
unsafe fn old_byte_strrchr(p: *const std::os::raw::c_char, target: u8) -> Option<usize> {
    unsafe {
        let mut last = None;
        let mut i = 0usize;
        loop {
            let b = *p.add(i) as u8;
            if b == target {
                last = Some(i);
            }
            if b == 0 {
                return last;
            }
            i += 1;
        }
    }
}

/// Pre-lever strcmp scan: byte-at-a-time compare to first diff/NUL.
#[inline(never)]
unsafe fn old_byte_strcmp(
    p1: *const std::os::raw::c_char,
    p2: *const std::os::raw::c_char,
) -> usize {
    unsafe {
        let mut i = 0usize;
        loop {
            let a = *p1.add(i) as u8;
            let b = *p2.add(i) as u8;
            if a != b || a == 0 {
                return i;
            }
            i += 1;
        }
    }
}

/// Pre-lever strchr scan: byte-at-a-time search for target-or-NUL.
#[inline(never)]
unsafe fn old_byte_scan_for_byte(p: *const std::os::raw::c_char, target: u8) -> usize {
    unsafe {
        let mut i = 0usize;
        loop {
            let b = *p.add(i) as u8;
            if b == target || b == 0 {
                return i;
            }
            i += 1;
        }
    }
}

/// Pre-lever NUL scan: byte-at-a-time (the old scan_c_string unbounded body).
#[inline(never)]
unsafe fn old_byte_scan(p: *const std::os::raw::c_char) -> usize {
    unsafe {
        let mut i = 0usize;
        while *p.add(i) != 0 {
            i += 1;
        }
        i
    }
}

/// The pre-lever implementation: one volatile store per byte.
#[inline(never)]
unsafe fn old_byte_volatile_fill(dst: *mut u8, value: u8, n: usize) {
    unsafe {
        let mut i = 0usize;
        while i < n {
            std::ptr::write_volatile(dst.add(i), value);
            i += 1;
        }
    }
}

/// The pre-lever memmove: one volatile load+store per byte (forward, disjoint).
#[inline(never)]
unsafe fn old_byte_volatile_move(dst: *mut u8, src: *const u8, n: usize) {
    unsafe {
        let mut i = 0usize;
        while i < n {
            std::ptr::write_volatile(dst.add(i), std::ptr::read_volatile(src.add(i)));
            i += 1;
        }
    }
}

/// Median of `rounds` measurements, each timing `iters` calls of `f`.
fn median_ns_per_op(rounds: usize, iters: u64, mut f: impl FnMut()) -> f64 {
    let mut samples: Vec<f64> = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let elapsed = t.elapsed().as_nanos() as f64;
        samples.push(elapsed / iters as f64);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn bench_wcsrchr_table(sizes: &[usize], rounds: usize) {
    println!("\nwcsrchr (absent target -> full wide scan to NUL):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10}",
        "wchars", "old(ns)", "fl(ns)", "glibc(ns)", "fl/glibc"
    );
    for &n in sizes {
        let mut s: Vec<u32> = vec![0x61u32; n + 1];
        s[n] = 0;
        let p = s.as_ptr();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_scalar_wcsrchr(p, 0x5A) });
        });
        // fl's deployed wcsrchr scan helper (the folded-128 SIMD lever target).
        let fl = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_wide_last_before_nul_simd(p, 0x5A) });
        });
        // host glibc wcsrchr (the `wcsrchr` extern resolves to libc, not fl).
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: NUL-terminated wide string.
            black_box(unsafe { wcsrchr(p, 0x5A) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x",
            n,
            old,
            fl,
            gl,
            gl / fl,
        );
    }
}

fn main() {
    let sizes = [16usize, 64, 256, 1024, 4096, 16384, 65536];
    let rounds = 15;
    if std::env::var("FRANKENLIBC_ABI_BENCH_ONLY").as_deref() == Ok("wcsrchr") {
        bench_wcsrchr_table(&sizes, rounds);
        return;
    }

    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "bytes", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut buf = vec![0u8; n];
        let p = buf.as_mut_ptr();
        // Scale iterations so each round does ~constant work.
        let iters = (4_000_000u64 / n as u64).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            unsafe { old_byte_volatile_fill(p, 0x5A, n) };
            black_box(buf[0]);
        });
        let new = median_ns_per_op(rounds, iters, || {
            unsafe { bench_raw_memset_bytes(p, 0x5A, n) };
            black_box(buf[0]);
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: buf valid for n bytes.
            unsafe { libc::memset(p.cast::<c_void>(), 0x5A, n) };
            black_box(buf[0]);
        });

        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nmemmove (disjoint forward):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "bytes", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut src = vec![0u8; n];
        let mut dst = vec![0u8; n];
        let sp = src.as_mut_ptr();
        let dp = dst.as_mut_ptr();
        let iters = (4_000_000u64 / n as u64).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            unsafe { old_byte_volatile_move(dp, sp, n) };
            black_box(dst[0]);
        });
        let new = median_ns_per_op(rounds, iters, || {
            unsafe { bench_raw_memmove_bytes(dp, sp, n) };
            black_box(dst[0]);
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: disjoint n-byte buffers.
            unsafe { libc::memmove(dp.cast::<c_void>(), sp.cast::<c_void>(), n) };
            black_box(dst[0]);
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nmemcpy (raw_memcpy_bytes — strcpy/strcat bulk copy):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "bytes", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut src = vec![0u8; n];
        let mut dst = vec![0u8; n];
        let sp = src.as_mut_ptr();
        let dp = dst.as_mut_ptr();
        let iters = (4_000_000u64 / n as u64).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            unsafe { old_byte_volatile_move(dp, sp, n) };
            black_box(dst[0]);
        });
        let new = median_ns_per_op(rounds, iters, || {
            unsafe { bench_raw_memcpy_bytes(dp, sp, n) };
            black_box(dst[0]);
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: disjoint n-byte buffers.
            unsafe { libc::memcpy(dp.cast::<c_void>(), sp.cast::<c_void>(), n) };
            black_box(dst[0]);
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nscan_c_string (NUL scan — behind strcpy/stpcpy/strncat):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "strlen", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        // NUL-terminated string of length n (no embedded NUL).
        let mut s = vec![0x61u8; n + 1];
        s[n] = 0;
        let p = s.as_ptr().cast::<std::os::raw::c_char>();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_byte_scan(p) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_c_string(p, None) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: NUL-terminated.
            black_box(unsafe { libc::strlen(p) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nstrchr (target absent → full scan to NUL, behind public strchr):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "len", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        // 'a'*n + NUL; search for an absent byte 'Z' so the scan runs the full length.
        let mut s = vec![0x61u8; n + 1];
        s[n] = 0;
        let p = s.as_ptr().cast::<std::os::raw::c_char>();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_byte_scan_for_byte(p, b'Z') });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_c_string_for_byte(p, b'Z', None) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: NUL-terminated.
            black_box(unsafe { libc::strchr(p, b'Z' as i32) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nstrcmp (equal strings → full scan to NUL, behind public strcmp/strncmp):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "len", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut a = vec![0x61u8; n + 1];
        a[n] = 0;
        let b = a.clone();
        let pa = a.as_ptr().cast::<std::os::raw::c_char>();
        let pb = b.as_ptr().cast::<std::os::raw::c_char>();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_byte_strcmp(pa, pb) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_strcmp(pa, pb, usize::MAX) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: both NUL-terminated.
            black_box(unsafe { libc::strcmp(pa, pb) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nstrrchr (absent target → full scan to NUL, behind public strrchr):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>12} | {:>10}",
        "len", "unbnd(ns)", "bnded(ns)", "glibc(ns)", "bnd/unbnd", "unbnd/gl"
    );
    for &n in &sizes {
        let mut s = vec![0x61u8; n + 1];
        s[n] = 0;
        let p = s.as_ptr().cast::<std::os::raw::c_char>();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        // Unbounded path (already 32B SIMD).
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_c_string_last_byte(p, b'Z', None) });
        });
        // Bounded path (membrane-tracked buffer supplies a known extent): this is
        // the strrchr scan hit when `known_remaining` is Some — historically still
        // 8B SWAR while the unbounded path got the SIMD skip.
        let new_b = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_c_string_last_byte(p, b'Z', Some(n)) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: NUL-terminated.
            black_box(unsafe { libc::strrchr(p, b'Z' as i32) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>11.2}x | {:>9.2}x",
            n,
            new,
            new_b,
            gl,
            new_b / new,
            new / gl,
        );
    }

    println!("\nstrcasecmp (equal mod case → full scan, behind strcasecmp/strncasecmp):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "len", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut a = vec![0x41u8; n + 1]; // 'A'*n
        a[n] = 0;
        let mut b = vec![0x61u8; n + 1]; // 'a'*n (equal mod case)
        b[n] = 0;
        let pa = a.as_ptr().cast::<std::os::raw::c_char>();
        let pb = b.as_ptr().cast::<std::os::raw::c_char>();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_byte_strcasecmp(pa, pb) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_strcasecmp(pa, pb, usize::MAX) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: both NUL-terminated.
            black_box(unsafe { libc::strcasecmp(pa, pb) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nstrncpy (copy-heavy: strlen==n, full copy no pad):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "n", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut src = vec![0x61u8; n + 1];
        src[n] = 0;
        let mut dst = vec![0u8; n + 1];
        let sp = src.as_ptr();
        let dp = dst.as_mut_ptr();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            unsafe { old_byte_strncpy(dp, sp, n) };
            black_box(dst[0]);
        });
        let new = median_ns_per_op(rounds, iters, || {
            unsafe { new_strncpy(dp, sp, n) };
            black_box(dst[0]);
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: src NUL-terminated, dst valid for n bytes.
            unsafe {
                libc::strncpy(
                    dp.cast::<std::os::raw::c_char>(),
                    sp.cast::<std::os::raw::c_char>(),
                    n,
                )
            };
            black_box(dst[0]);
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nwcschr (absent target -> full wide scan to NUL):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "wchars", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut s: Vec<u32> = vec![0x61u32; n + 1];
        s[n] = 0;
        let p = s.as_ptr();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_scalar_wcschr(p, 0x5A) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_wide_find_or_nul_simd(p, 0x5A) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: NUL-terminated wide string.
            black_box(unsafe { wcschr(p, 0x5A) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    bench_wcsrchr_table(&sizes, rounds);

    println!("\nwcscmp (equal wide strings → full scan, wchar_t = u32):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "wchars", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut a: Vec<u32> = vec![0x61u32; n + 1];
        a[n] = 0;
        let b = a.clone();
        let pa = a.as_ptr();
        let pb = b.as_ptr();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_scalar_wcscmp(pa, pb) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_wcscmp_simd(pa, pb, usize::MAX) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: both NUL-terminated wide strings.
            black_box(unsafe { wcscmp(pa, pb) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nwcscasecmp (equal-mod-case wide strings → full scan, wchar_t = u32):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "wchars", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let mut a: Vec<u32> = vec![0x41u32; n + 1]; // 'A'
        a[n] = 0;
        let mut b: Vec<u32> = vec![0x61u32; n + 1]; // 'a' (equal mod case)
        b[n] = 0;
        let pa = a.as_ptr();
        let pb = b.as_ptr();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_scalar_wcscasecmp(pa, pb) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { bench_scan_wcscasecmp_simd(pa, pb, usize::MAX) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: both NUL-terminated wide strings.
            black_box(unsafe { wcscasecmp(pa, pb) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n,
            old,
            new,
            gl,
            old / new,
            gl / new,
        );
    }

    println!("\nwcsstr (absent 4-elem needle, needle[0] rare => full scan, wchar_t=u32):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "wchars", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    let needle: Vec<u32> = b"QRST".iter().map(|&x| x as u32).collect();
    let mut needle_w = needle.clone();
    needle_w.push(0);
    for &n in &sizes {
        let mut hay: Vec<u32> = vec![0x61u32; n + 1]; // 'a' * n; needle[0]='Q' absent
        hay[n] = 0;
        let hp = hay.as_ptr();
        let np = needle_w.as_ptr();
        let iters = (2_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { old_bruteforce_wcsstr(hp, n, &needle) });
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(unsafe { new_prefilter_wcsstr(hp, n, &needle) });
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: both NUL-terminated wide strings.
            black_box(unsafe { wcsstr(hp, np) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n, old, new, gl, old / new, gl / new,
        );
    }

    println!("\nwmemcmp (equal wide buffers => full scan, wchar_t = u32):");
    println!(
        "{:>8} | {:>12} | {:>12} | {:>12} | {:>10} | {:>10}",
        "wchars", "old(ns)", "new(ns)", "glibc(ns)", "self x", "vs glibc"
    );
    for &n in &sizes {
        let a: Vec<u32> = vec![0x61u32; n];
        let b = a.clone();
        let pa = a.as_ptr();
        let pb = b.as_ptr();
        let iters = (4_000_000u64 / (n as u64 + 1)).max(2000);

        let old = median_ns_per_op(rounds, iters, || {
            black_box(old_scalar_wmemcmp(&a, &b));
        });
        let new = median_ns_per_op(rounds, iters, || {
            black_box(frankenlibc_core::string::wide::wmemcmp(&a, &b, n));
        });
        let gl = median_ns_per_op(rounds, iters, || {
            // SAFETY: both buffers valid for n wchars.
            black_box(unsafe { wmemcmp(pa, pb, n) });
        });
        println!(
            "{:>8} | {:>12.1} | {:>12.1} | {:>12.1} | {:>9.2}x | {:>9.2}x",
            n, old, new, gl, old / new, gl / new,
        );
    }
}
