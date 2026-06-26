//! Same-process A/B to test the ledger's claim that fl qsort's string-sort loss
//! is "pdqsort slower than glibc merge for an expensive comparator". Compares,
//! on the SAME 16-byte string records with the SAME lexicographic comparator:
//!   - pdqsort   : std `sort_unstable_by` (same algorithm class as fl's fallback)
//!   - merge     : std `sort_by` (timsort/merge — what a merge fallback would be)
//!   - glibc     : host `qsort` (glibc mergesort)
//! Clone is excluded from timing via `iter_batched`. If merge << pdqsort here,
//! switching fl's non-radix fallback to a merge sort is a real lever on the
//! biggest measured qsort gap.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench sort_fallback_ab_bench`

use std::cmp::Ordering;
use std::ffi::c_void;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

const W: usize = 16;

unsafe extern "C" {
    fn qsort(
        base: *mut c_void,
        nmemb: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> i32,
    );
}

unsafe extern "C" fn cmp_c(a: *const c_void, b: *const c_void) -> i32 {
    let (pa, pb) = (a as *const u8, b as *const u8);
    for i in 0..W {
        let (x, y) = unsafe { (*pa.add(i), *pb.add(i)) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

#[inline]
fn cmp_rs(a: &[u8; W], b: &[u8; W]) -> Ordering {
    a.cmp(b)
}

fn make(n: usize) -> Vec<[u8; W]> {
    let mut s: u64 = 0xDEAD_BEEF_1234_5678;
    let mut next = || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    };
    (0..n)
        .map(|_| {
            let mut r = [0u8; W];
            for b in r.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            r
        })
        .collect()
}

fn bench(c: &mut Criterion) {
    // Decisive metric: comparison COUNT (algorithm-intrinsic). With an EXPENSIVE
    // FFI comparator (fl and glibc both call a C fn pointer, no inlining), total
    // time ≈ count × per-call-cost, so the count gap IS the algorithm gap.
    use std::sync::atomic::{AtomicU64, Ordering as AOrd};
    for n in [2000usize, 20000] {
        let d = make(n);
        let cnt = AtomicU64::new(0);
        let mut v1 = d.clone();
        v1.sort_unstable_by(|a, b| {
            cnt.fetch_add(1, AOrd::Relaxed);
            cmp_rs(a, b)
        });
        let pdq = cnt.swap(0, AOrd::Relaxed);
        let mut v2 = d.clone();
        v2.sort_by(|a, b| {
            cnt.fetch_add(1, AOrd::Relaxed);
            cmp_rs(a, b)
        });
        let mrg = cnt.load(AOrd::Relaxed);
        eprintln!(
            "CMPCOUNT n={n}: pdqsort={pdq} merge={mrg} ratio_pdq/merge={:.3}",
            pdq as f64 / mrg as f64
        );
    }

    for n in [2000usize, 20000] {
        let data = make(n);

        let mut g = c.benchmark_group(format!("sortfb_n{n}"));
        g.bench_function("pdqsort_unstable", |b| {
            b.iter_batched(
                || data.clone(),
                |mut v| {
                    v.sort_unstable_by(|a, b| cmp_rs(a, b));
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        g.bench_function("merge_stable", |b| {
            b.iter_batched(
                || data.clone(),
                |mut v| {
                    v.sort_by(|a, b| cmp_rs(a, b));
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        g.bench_function("host_glibc_qsort", |b| {
            b.iter_batched(
                || data.clone(),
                |mut v| {
                    unsafe { qsort(v.as_mut_ptr().cast(), v.len(), W, cmp_c) };
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        g.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
