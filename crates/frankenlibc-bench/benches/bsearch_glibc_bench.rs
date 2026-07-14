//! Same-binary `bsearch` benchmark: incumbent slice loop vs strict raw-pointer
//! candidate vs pristine host glibc.
//!
//! The strict membrane bypass already shipped. This measures the remaining
//! representation seam: the incumbent constructs byte slices and a range slice
//! for every probe although the C comparator consumes only raw pointers.
//!
//! fl `bsearch` is the release `no_mangle` symbol (bare `extern bsearch` resolves to
//! it under `abi-bench`); glibc is loaded via `dlmopen(LM_ID_NEWLM)` so the two never
//! cross. The retained strict slice body gives a same-process incumbent control,
//! so no ratio is formed across separate binaries or workers.

use std::cell::RefCell;
use std::ffi::c_void;
use std::hint::black_box;
use std::os::raw::c_int;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdlib_abi as fl;

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
    // SAFETY: benchmark records contain an i32 key in their first four bytes;
    // use unaligned reads so the parity oracle can exercise odd element widths.
    let (x, y) = unsafe {
        (
            a.cast::<i32>().read_unaligned(),
            b.cast::<i32>().read_unaligned(),
        )
    };
    (x > y) as c_int - (x < y) as c_int
}

thread_local! {
    static COMPARE_TRACE: RefCell<Vec<i32>> = const { RefCell::new(Vec::new()) };
}

unsafe extern "C" fn cmp_i32_traced(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: same record contract as `cmp_i32`.
    let y = unsafe { b.cast::<i32>().read_unaligned() };
    COMPARE_TRACE.with(|trace| trace.borrow_mut().push(y));
    // SAFETY: forwarded under the same comparator contract.
    unsafe { cmp_i32(a, b) }
}

fn take_compare_trace() -> Vec<i32> {
    COMPARE_TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

#[inline(never)]
unsafe extern "C" fn bsearch_slice_control(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    compar: CompareFn,
) -> *mut c_void {
    // SAFETY: forwards the benchmark's valid bsearch inputs to the retained
    // pre-candidate strict body.
    unsafe { fl::bsearch_strict_slice_for_bench(key, base, nmemb, size, Some(compar)) }
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

    // Executable equivalence oracle before any timer: exact pointer parity for
    // unique records across empty/small/power-of-two-adjacent counts and odd
    // widths, plus found/not-found parity with host glibc.
    for width in [4usize, 8, 17] {
        for count in [0usize, 1, 2, 3, 255, 256, 257] {
            let mut records = vec![0xa5u8; count * width];
            for index in 0..count {
                records[index * width..index * width + 4]
                    .copy_from_slice(&((index as i32) * 2).to_ne_bytes());
            }
            let last = count.saturating_sub(1) as i32 * 2;
            for key in [
                -1i32,
                0,
                (count / 2) as i32 * 2,
                last,
                last.saturating_add(1),
            ] {
                let old = unsafe {
                    bsearch_slice_control(
                        (&key as *const i32).cast(),
                        records.as_ptr().cast(),
                        count,
                        width,
                        cmp_i32,
                    )
                };
                let candidate = unsafe {
                    bsearch(
                        (&key as *const i32).cast(),
                        records.as_ptr().cast(),
                        count,
                        width,
                        cmp_i32,
                    )
                };
                let glibc = unsafe {
                    hostb(
                        (&key as *const i32).cast(),
                        records.as_ptr().cast(),
                        count,
                        width,
                        cmp_i32,
                    )
                };
                assert_eq!(
                    old, candidate,
                    "old/new pointer: count={count} width={width} key={key}"
                );
                assert_eq!(
                    candidate, glibc,
                    "new/glibc pointer: count={count} width={width} key={key}"
                );
            }
        }
    }

    // Comparator calls are observable to C code. Preserve their exact order for
    // both hits and misses, including the incumbent's chosen duplicate.
    for key in [-1i32, 0, 200, 510, 511] {
        let old = unsafe {
            bsearch_slice_control(
                (&key as *const i32).cast(),
                arr.as_ptr().cast(),
                arr.len(),
                std::mem::size_of::<i32>(),
                cmp_i32_traced,
            )
        };
        let old_trace = take_compare_trace();
        let candidate = unsafe {
            bsearch(
                (&key as *const i32).cast(),
                arr.as_ptr().cast(),
                arr.len(),
                std::mem::size_of::<i32>(),
                cmp_i32_traced,
            )
        };
        let candidate_trace = take_compare_trace();
        assert_eq!(old, candidate, "trace pointer parity for key={key}");
        assert_eq!(
            old_trace, candidate_trace,
            "comparator trace parity for key={key}"
        );
    }

    let duplicates = [1i32, 7, 7, 7, 9];
    let duplicate_key = 7i32;
    let old = unsafe {
        bsearch_slice_control(
            (&duplicate_key as *const i32).cast(),
            duplicates.as_ptr().cast(),
            duplicates.len(),
            std::mem::size_of::<i32>(),
            cmp_i32_traced,
        )
    };
    let old_trace = take_compare_trace();
    let candidate = unsafe {
        bsearch(
            (&duplicate_key as *const i32).cast(),
            duplicates.as_ptr().cast(),
            duplicates.len(),
            std::mem::size_of::<i32>(),
            cmp_i32_traced,
        )
    };
    let candidate_trace = take_compare_trace();
    let glibc = unsafe {
        hostb(
            (&duplicate_key as *const i32).cast(),
            duplicates.as_ptr().cast(),
            duplicates.len(),
            std::mem::size_of::<i32>(),
            cmp_i32,
        )
    };
    assert_eq!(old, candidate, "duplicate pointer parity");
    assert_eq!(
        old_trace, candidate_trace,
        "duplicate comparator trace parity"
    );
    assert!(
        !candidate.is_null() && !glibc.is_null(),
        "duplicate key must be found"
    );

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
    run("incumbent_slice_control", bsearch_slice_control);
    run("raw_pointer_candidate", bsearch);
    run("glibc", hostb);

    let mut g = c.benchmark_group("bsearch");
    g.sample_size(30);
    g.bench_function("incumbent_slice_control", |b| {
        b.iter(|| {
            black_box(unsafe {
                bsearch_slice_control(
                    black_box(&keys[100]) as *const i32 as *const c_void,
                    arr.as_ptr().cast(),
                    arr.len(),
                    4,
                    cmp_i32,
                )
            })
        })
    });
    g.bench_function("raw_pointer_candidate", |b| {
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
