//! Same-process A/B for the qsort non-radix FALLBACK: fl's custom `pdqsort_recurse`
//! (reached via `frankenlibc_core::stdlib::sort::qsort` once the gate skips the
//! radix) vs Rust std `sort_unstable_by` on the SAME width-8 char*-pointer data
//! with the SAME strcmp comparator, vs host glibc `qsort` (mergesort). Tests
//! whether swapping fl's custom pdqsort for std's highly-tuned one closes the
//! residual string-sort loss. Clone excluded via `iter_batched`.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench qsort_pdqsort_ab_bench`

use std::cmp::Ordering;
use std::ffi::c_void;
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

unsafe extern "C" {
    fn qsort(
        base: *mut c_void,
        nmemb: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> i32,
    );
}

// Comparator: element bytes hold a `*const u8` to a NUL-terminated string; order
// by strcmp of the pointed-to strings (the classic `qsort(char**, ..., strcmp)`).
#[inline]
fn strcmp_bytes(a: &[u8]) -> *const u8 {
    usize::from_ne_bytes(a[..8].try_into().unwrap()) as *const u8
}
#[inline]
fn cmp_i32(a: &[u8], b: &[u8]) -> i32 {
    let (mut pa, mut pb) = (strcmp_bytes(a), strcmp_bytes(b));
    loop {
        let (x, y) = unsafe { (*pa, *pb) };
        if x != y {
            return x as i32 - y as i32;
        }
        if x == 0 {
            return 0;
        }
        unsafe {
            pa = pa.add(1);
            pb = pb.add(1);
        }
    }
}
#[inline]
fn cmp_ord(a: &[u8; 8], b: &[u8; 8]) -> Ordering {
    cmp_i32(a, b).cmp(&0)
}
unsafe extern "C" fn cmp_c(a: *const c_void, b: *const c_void) -> i32 {
    cmp_i32(
        unsafe { std::slice::from_raw_parts(a as *const u8, 8) },
        unsafe { std::slice::from_raw_parts(b as *const u8, 8) },
    )
}

fn bench(c: &mut Criterion) {
    let n = 20000usize;
    // Distinct random 8-hex-char strings, kept alive; element = its pointer bytes.
    let mut s: u64 = 0xABCD_1234_5678_9F01;
    let mut next = || {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        s
    };
    let strings: Vec<std::ffi::CString> = (0..n)
        .map(|_| std::ffi::CString::new(format!("{:08x}", (next() >> 16) as u32)).unwrap())
        .collect();
    let elems: Vec<[u8; 8]> = strings
        .iter()
        .map(|cs| (cs.as_ptr() as usize).to_ne_bytes())
        .collect();

    // parity: all three produce the same strcmp-sorted order (distinct strings).
    {
        let mut a: Vec<[u8; 8]> = elems.clone();
        let bytes = unsafe { std::slice::from_raw_parts_mut(a.as_mut_ptr().cast::<u8>(), n * 8) };
        frankenlibc_core::stdlib::sort::qsort(bytes, 8, cmp_i32);
        let mut b = elems.clone();
        b.sort_unstable_by(cmp_ord);
        let mut g = elems.clone();
        unsafe { qsort(g.as_mut_ptr().cast(), n, 8, cmp_c) };
        assert!(a == b && b == g, "sort order mismatch across implementations");
    }

    let mut grp = c.benchmark_group(format!("pdq_n{n}"));
    grp.bench_function("fl_custom_pdqsort", |bn| {
        bn.iter_batched(
            || elems.clone(),
            |mut v| {
                let bytes =
                    unsafe { std::slice::from_raw_parts_mut(v.as_mut_ptr().cast::<u8>(), n * 8) };
                frankenlibc_core::stdlib::sort::qsort(bytes, 8, cmp_i32);
                black_box(v.len())
            },
            BatchSize::LargeInput,
        )
    });
    grp.bench_function("std_sort_unstable", |bn| {
        bn.iter_batched(
            || elems.clone(),
            |mut v| {
                v.sort_unstable_by(cmp_ord);
                black_box(v.len())
            },
            BatchSize::LargeInput,
        )
    });
    grp.bench_function("host_glibc_qsort", |bn| {
        bn.iter_batched(
            || elems.clone(),
            |mut v| {
                unsafe { qsort(v.as_mut_ptr().cast(), n, 8, cmp_c) };
                black_box(v.len())
            },
            BatchSize::LargeInput,
        )
    });
    grp.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
