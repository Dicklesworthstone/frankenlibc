//! Same-process A/B for LARGE-element qsort (width not in {1,2,4,8,16}, so fl
//! currently uses `pdqsort_recurse` which moves full width-byte elements per
//! swap). Compares, on the same width-32 struct records with the same key
//! comparator:
//!   - fl_pdqsort  : `frankenlibc_core::stdlib::sort::qsort` (full-element moves)
//!   - index_sort  : std `sort_unstable_by` over u32 INDICES, then one permute
//!                   (moves 4-byte indices during the sort, elements once at end)
//!   - glibc       : host `qsort`
//! If index_sort << fl_pdqsort, extending the fallback to index-sort for
//! arbitrary widths is a real lever for struct-array sorting.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench qsort_indexsort_ab_bench`

use std::cmp::Ordering;
use std::ffi::c_void;
use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const W: usize = 12;

unsafe extern "C" {
    fn qsort(
        base: *mut c_void,
        nmemb: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> i32,
    );
}

// Order by a key field: bytes [4..8] then [0..4] (a struct sorted by a member,
// so the integer-of-all-32-bytes order does NOT match — pure pdqsort fallback).
const ORDER: [usize; 8] = [4, 5, 6, 7, 0, 1, 2, 3];

#[inline]
fn cmp_i32(a: &[u8], b: &[u8]) -> i32 {
    for &i in &ORDER {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
    }
    0
}
unsafe extern "C" fn cmp_c(a: *const c_void, b: *const c_void) -> i32 {
    cmp_i32(
        unsafe { std::slice::from_raw_parts(a as *const u8, W) },
        unsafe { std::slice::from_raw_parts(b as *const u8, W) },
    )
}

fn index_sort(base: &mut [u8], width: usize, num: usize, compare: impl Fn(&[u8], &[u8]) -> i32) {
    let elem = |k: usize| &base[k * width..k * width + width];
    let mut idx: Vec<u32> = (0..num as u32).collect();
    idx.sort_unstable_by(|&i, &j| compare(elem(i as usize), elem(j as usize)).cmp(&0));
    let mut out = vec![0u8; num * width];
    for (dst, &src) in idx.iter().enumerate() {
        let s = src as usize;
        out[dst * width..dst * width + width].copy_from_slice(&base[s * width..s * width + width]);
    }
    base[..num * width].copy_from_slice(&out);
}

fn make(n: usize) -> Vec<u8> {
    let mut s: u64 = 0x0BAD_F00D_DEAD_BEEF;
    let mut next = || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    (0..n * W).map(|_| (next() >> 24) as u8).collect()
}

fn bench(c: &mut Criterion) {
    for n in [64usize, 256, 4096, 20000] {
        let data = make(n);

        // parity: all three produce the same sorted-by-key order (distinct keys w.h.p.;
        // verify sortedness rather than exact bytes since ties are unspecified).
        {
            let mut a = data.clone();
            frankenlibc_core::stdlib::sort::qsort(&mut a, W, cmp_i32);
            let mut b = data.clone();
            index_sort(&mut b, W, n, cmp_i32);
            let mut g = data.clone();
            unsafe { qsort(g.as_mut_ptr().cast(), n, W, cmp_c) };
            let sorted = |v: &[u8]| {
                (1..n).all(|k| cmp_i32(&v[(k - 1) * W..k * W], &v[k * W..k * W + W]) <= 0)
            };
            assert!(sorted(&a) && sorted(&b) && sorted(&g), "not sorted");
        }

        let mut grp = c.benchmark_group(format!("idxsort_w{W}_n{n}"));
        grp.bench_function("fl_pdqsort", |bn| {
            bn.iter_batched(
                || data.clone(),
                |mut v| {
                    frankenlibc_core::stdlib::sort::qsort(&mut v, W, cmp_i32);
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        grp.bench_function("index_sort", |bn| {
            bn.iter_batched(
                || data.clone(),
                |mut v| {
                    index_sort(&mut v, W, n, cmp_i32);
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        grp.bench_function("host_glibc_qsort", |bn| {
            bn.iter_batched(
                || data.clone(),
                |mut v| {
                    unsafe { qsort(v.as_mut_ptr().cast(), n, W, cmp_c) };
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        grp.finish();
    }
    let _ = Ordering::Equal;
}

criterion_group!(benches, bench);
criterion_main!(benches);
