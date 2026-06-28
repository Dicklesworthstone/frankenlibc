//! POSIX `tsearch` insert-or-find: OLD (fl `RbTree::insert` THEN a separate `find` =
//! two tree walks / 2x the C `compar` callbacks) vs NEW (`RbTree::insert_find` = one
//! walk) vs host glibc `tsearch` — all in ONE process. tsearch's comparator is an
//! indirect C callback, so halving the comparisons is the lever. No `abi-bench` → bare
//! `extern tsearch` resolves to host glibc directly.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench tsearch_ab_bench`

use std::cmp::Ordering;
use std::ffi::c_void;
use std::hint::black_box;
use std::os::raw::c_int;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::search::RbTree;

unsafe extern "C" {
    fn tsearch(key: *const c_void, rootp: *mut *mut c_void, compar: CompareFn) -> *mut c_void;
    fn tdestroy(root: *mut c_void, free_node: unsafe extern "C" fn(*mut c_void));
}
unsafe extern "C" fn free_noop(_: *mut c_void) {}
type CompareFn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

// C-ABI comparator over i64 pointers — the indirect call both fl (via the fn-pointer
// closure) and glibc pay per comparison.
unsafe extern "C" fn cmp_i64(a: *const c_void, b: *const c_void) -> c_int {
    let (x, y) = unsafe { (*(a as *const i64), *(b as *const i64)) };
    if x < y { -1 } else if x > y { 1 } else { 0 }
}

#[inline]
fn rust_cmp_via_cb(a: &i64, b: &i64) -> Ordering {
    // Route through the SAME C callback (black-boxed fn pointer) so the fl arms pay the
    // identical indirect-call cost glibc pays — the comparison is fair.
    let f: CompareFn = black_box(cmp_i64);
    let r = unsafe { f(a as *const i64 as *const c_void, b as *const i64 as *const c_void) };
    r.cmp(&0)
}

fn keys(n: usize) -> Vec<i64> {
    // Deterministic pseudo-random distinct-ish keys (xorshift).
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 11) as i64
        })
        .collect()
}

fn p50(s: &mut [f64]) -> f64 {
    s.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    if s.is_empty() { return 0.0; }
    let r = 0.5 * (s.len() - 1) as f64;
    let (lo, hi) = (r.floor() as usize, r.ceil() as usize);
    s[lo] * (1.0 - (r - lo as f64)) + s[hi] * (r - lo as f64)
}

// OLD deployed shape: insert then a separate find (two walks).
fn build_old(ks: &[i64]) -> usize {
    let mut t: RbTree<i64> = RbTree::new();
    let mut acc = 0usize;
    for &k in ks {
        t.insert(k, &rust_cmp_via_cb);
        if let Some(found) = t.find(&k, &rust_cmp_via_cb) {
            acc = acc.wrapping_add(*found as usize);
        }
    }
    acc
}
// NEW: single-walk insert_find.
fn build_new(ks: &[i64]) -> usize {
    let mut t: RbTree<i64> = RbTree::new();
    let mut acc = 0usize;
    for &k in ks {
        let p = t.insert_find(k, &rust_cmp_via_cb);
        acc = acc.wrapping_add(unsafe { *p } as usize);
    }
    acc
}
// glibc tsearch over a fresh tree; keys must outlive the tree.
fn build_glibc(ks: &[i64]) -> usize {
    let mut root: *mut c_void = std::ptr::null_mut();
    let mut acc = 0usize;
    for k in ks {
        let p = unsafe { tsearch(k as *const i64 as *const c_void, &mut root, cmp_i64) };
        if !p.is_null() {
            acc = acc.wrapping_add(unsafe { **(p as *const *const i64) } as usize);
        }
    }
    // free the whole glibc tree in one shot (no comparator calls — fair vs fl's tree
    // drop, which also frees without comparisons); keys are caller-owned so free is noop.
    if !root.is_null() {
        unsafe { tdestroy(root, free_noop) };
    }
    acc
}

fn run(g: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>, name: &str, ks: &[i64], f: impl Fn(&[i64]) -> usize) {
    for _ in 0..10 { black_box(f(black_box(ks))); }
    let mut s = Vec::new();
    for _ in 0..200 { let t = Instant::now(); black_box(f(black_box(ks))); s.push(t.elapsed().max(Duration::from_nanos(1)).as_nanos() as f64 / ks.len() as f64); }
    println!("TSEARCH_BENCH impl={name} p50_ns_per_key={:.4}", p50(&mut s));
    g.bench_function(name, |b| b.iter(|| black_box(f(black_box(ks)))));
}

fn bench(c: &mut Criterion) {
    let ks = keys(2000);
    // parity: old and new must agree on the retained-key value for every key.
    assert_eq!(build_old(&ks), build_new(&ks), "insert_find disagrees with insert+find");

    let mut g = c.benchmark_group("tsearch_2000");
    g.sample_size(30);
    run(&mut g, "old_insert_then_find", &ks, build_old);
    run(&mut g, "candidate_insert_find", &ks, build_new);
    run(&mut g, "glibc_tsearch", &ks, build_glibc);
    g.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
