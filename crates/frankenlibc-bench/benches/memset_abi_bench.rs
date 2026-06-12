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
};

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

fn main() {
    let sizes = [16usize, 64, 256, 1024, 4096, 16384, 65536];
    let rounds = 15;
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
            n, old, new, gl, old / new, gl / new,
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
            n, old, new, gl, old / new, gl / new,
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
            n, old, new, gl, old / new, gl / new,
        );
    }
}
