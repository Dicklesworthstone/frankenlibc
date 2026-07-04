//! In-process A/B for the `wmemrchr` ABI strict path.
//!
//! ORIG is the old scalar reverse loop from `wchar_abi.rs`; NEW calls the deployed
//! ABI entrypoint, which should route through the core SIMD reverse scanner.

use std::hint::black_box;
use std::time::Instant;

fn pctl(samples: &[f64], q: f64) -> f64 {
    let mut s = samples.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let r = q * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    if lo == hi {
        s[lo]
    } else {
        s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
    }
}

fn offset(ptr: *mut u32, base: *const u32) -> isize {
    if ptr.is_null() {
        -1
    } else {
        ((ptr as isize) - (base as isize)) / std::mem::size_of::<u32>() as isize
    }
}

fn old_scalar(s: &[u32], c: u32, n: usize) -> *mut u32 {
    match (0..n.min(s.len())).rev().find(|&i| s[i] == c) {
        Some(i) => unsafe { s.as_ptr().add(i) as *mut u32 },
        None => std::ptr::null_mut(),
    }
}

fn measure<F: Fn() -> usize>(iters: u64, f: F) -> f64 {
    let t = Instant::now();
    for _ in 0..iters {
        black_box(f());
    }
    t.elapsed().as_nanos() as f64 / iters as f64
}

fn main() {
    let cases: &[(usize, Option<usize>)] = &[
        (64, None),
        (256, None),
        (1024, None),
        (4096, None),
        (1024, Some(32)),
        (1024, Some(900)),
    ];

    for &(n, hit) in cases {
        let mut buf = vec![0x41u32; n];
        let needle = 0x7fffu32;
        if let Some(pos) = hit {
            buf[pos] = needle;
        }
        let base = buf.as_ptr();
        let old = old_scalar(&buf, needle, n);
        let new = unsafe { frankenlibc_abi::wchar_abi::wmemrchr(base, needle, n) };
        assert_eq!(
            offset(old, base),
            offset(new, base),
            "old/new n={n} hit={hit:?}"
        );

        let iters = if n <= 256 { 450_000 } else { 140_000 };
        let (mut old_s, mut new_s) = (Vec::new(), Vec::new());
        for round in 0..40 {
            let old_run = || measure(iters, || old_scalar(black_box(&buf), needle, n) as usize);
            let new_run = || {
                measure(iters, || unsafe {
                    frankenlibc_abi::wchar_abi::wmemrchr(
                        black_box(base),
                        black_box(needle),
                        black_box(n),
                    ) as usize
                })
            };
            match round & 1 {
                0 => {
                    old_s.push(old_run());
                    new_s.push(new_run());
                }
                _ => {
                    old_s.push(old_run());
                    new_s.push(new_run());
                }
            }
        }

        let old_p = pctl(&old_s, 0.10);
        let new_p = pctl(&new_s, 0.10);
        println!(
            "WMEMRCHR_AB n={n:<5} hit={hit:?} old_scalar={old_p:.2}ns new_abi={new_p:.2}ns new/old={:.3}",
            new_p / old_p
        );
    }
}
