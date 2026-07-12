//! Head-to-head `bsearch` benchmark: deployed FrankenLibC vs pristine host glibc.
//!
//! Lever (bd-n40in2 family): fl `bsearch` calls `runtime_policy::decide()` TWICE
//! (base + key) plus an `observe()` per call — the always-Allow Stdlib membrane is
//! pure overhead on top of the region-bounded binary search (the regions are already
//! validated by `tracked_region_fits`). getenv/strtod/math/ctype already skip it via
//! `stdlib_membrane_fastpath()`; this measures applying the same skip to bsearch.
//!
//! fl `bsearch` is the release `no_mangle` symbol (bare `extern bsearch` resolves to
//! it under `abi-bench`); glibc is loaded via `dlmopen(LM_ID_NEWLM)` so the two never
//! cross. The glibc arm normalises per-worker variance — compare the fl/glibc RATIO
//! across the baseline (2 decide) and patched (fast-path) builds.

use std::ffi::c_void;
use std::hint::black_box;
use std::os::raw::c_int;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};

type CompareFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;
type BsearchFn =
    unsafe extern "C" fn(*const c_void, *const c_void, usize, usize, CompareFn) -> *mut c_void;

unsafe extern "C" {
    fn bsearch(
        key: *const c_void,
        base: *const c_void,
        nmemb: usize,
        size: usize,
        compar: CompareFn,
    ) -> *mut c_void;
}

fn host_bsearch() -> BsearchFn {
    static H: OnceLock<usize> = OnceLock::new();
    let p = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let s = libc::dlsym(handle, b"bsearch\0".as_ptr().cast());
        assert!(!s.is_null(), "dlsym bsearch failed");
        s as usize
    });
    unsafe { std::mem::transmute::<usize, BsearchFn>(p) }
}

unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
    let (x, y) = unsafe { (*(a as *const i32), *(b as *const i32)) };
    (x > y) as c_int - (x < y) as c_int
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if s.is_empty() {
        return 0.0;
    }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

fn bench(c: &mut Criterion) {
    // Sorted array; look up every element (each lookup = one bsearch call).
    let arr: Vec<i32> = (0..256i32).map(|k| k * 2).collect();
    let keys: Vec<i32> = (0..256i32).map(|k| k * 2).collect();
    let hostb = host_bsearch();

    // parity check
    for k in &keys {
        let a = unsafe {
            bsearch(
                k as *const i32 as *const c_void,
                arr.as_ptr().cast(),
                arr.len(),
                4,
                cmp_i32,
            )
        };
        let b = unsafe {
            hostb(
                k as *const i32 as *const c_void,
                arr.as_ptr().cast(),
                arr.len(),
                4,
                cmp_i32,
            )
        };
        assert!(
            !a.is_null() && !b.is_null(),
            "bsearch parity: both must find {k}"
        );
    }

    let run = |name: &str, f: BsearchFn| {
        let one = || {
            let mut acc = 0usize;
            for k in &keys {
                let p = unsafe {
                    f(
                        k as *const i32 as *const c_void,
                        arr.as_ptr().cast(),
                        arr.len(),
                        4,
                        cmp_i32,
                    )
                };
                acc = acc.wrapping_add(p as usize);
            }
            acc
        };
        for _ in 0..50 {
            black_box(one());
        }
        let mut s = Vec::new();
        for _ in 0..200 {
            let t = Instant::now();
            black_box(one());
            s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / keys.len() as f64);
        }
        println!(
            "BSEARCH_BENCH impl={name} p50_ns_per_lookup={:.4}",
            p50(&mut s)
        );
    };
    run("fl_deployed", bsearch);
    run("glibc", hostb);

    let mut g = c.benchmark_group("bsearch");
    g.sample_size(30);
    g.bench_function("fl_deployed", |b| {
        b.iter(|| {
            black_box(unsafe {
                bsearch(
                    black_box(&keys[100]) as *const i32 as *const c_void,
                    arr.as_ptr().cast(),
                    arr.len(),
                    4,
                    cmp_i32,
                )
            })
        })
    });
    g.bench_function("glibc", |b| {
        b.iter(|| {
            black_box(unsafe {
                hostb(
                    black_box(&keys[100]) as *const i32 as *const c_void,
                    arr.as_ptr().cast(),
                    arr.len(),
                    4,
                    cmp_i32,
                )
            })
        })
    });
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
