//! Same-process measurement of the qsort integer-radix prefix gate:
//!  - `radix_attempt_wasted` : cost of ONE integer-radix-lane attempt on
//!     width-8 NON-integer data (build keys + LSD radix + verify-fail) — the work
//!     the gate skips.
//!  - `gate_probe`           : cost of the prefix integer-order gate itself.
//!  - `full_qsort_fl` / `full_qsort_glibc` : end-to-end on the same data.
//! Savings per sort = radix_attempt_wasted − gate_probe. All in one process so
//! per-worker load cancels.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench qsort_gate_ab_bench`

use std::ffi::c_void;
use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const W: usize = 8;

unsafe extern "C" {
    fn qsort(
        base: *mut c_void,
        nmemb: usize,
        size: usize,
        cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> i32,
    );
}

// NON-integer order: sort by byte[2], then [5],[0],[1] (a struct-key-style
// comparator). The integer value of all 8 bytes does NOT match this order, so
// the radix lane's signed+unsigned attempts both verify-fail (the wasted case).
const ORDER: [usize; 4] = [2, 5, 0, 1];

fn cmp_rs(a: &[u8], b: &[u8]) -> i32 {
    for &i in &ORDER {
        if a[i] != b[i] {
            return a[i] as i32 - b[i] as i32;
        }
    }
    0
}

unsafe extern "C" fn cmp_c(a: *const c_void, b: *const c_void) -> i32 {
    let (pa, pb) = (a as *const u8, b as *const u8);
    for &i in &ORDER {
        let (x, y) = unsafe { (*pa.add(i), *pb.add(i)) };
        if x != y {
            return x as i32 - y as i32;
        }
    }
    0
}

fn make(n: usize) -> Vec<u8> {
    let mut s: u64 = 0x1234_5678_9ABC_DEF0;
    let mut next = || {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        s
    };
    (0..n * W).map(|_| (next() >> 24) as u8).collect()
}

fn bench(c: &mut Criterion) {
    for n in [20000usize] {
        let data = make(n);

        // Sanity: the gate must SKIP (return false) for this non-integer order,
        // and the radix attempt must FAIL (return false) on the same data.
        {
            let mut v = data.clone();
            let attempted =
                frankenlibc_core::stdlib::sort::__bench_integer_radix_attempt(&mut v, W, &cmp_rs);
            let gate =
                frankenlibc_core::stdlib::sort::__bench_integer_order_gate(&data, W, &cmp_rs);
            assert!(
                !attempted,
                "radix lane unexpectedly committed (data is non-integer)"
            );
            assert!(!gate, "gate should skip a non-integer comparator");
        }

        let mut g = c.benchmark_group(format!("qsortgate_n{n}"));
        g.bench_function("radix_attempt_wasted", |b| {
            b.iter_batched(
                || data.clone(),
                |mut v| {
                    black_box(
                        frankenlibc_core::stdlib::sort::__bench_integer_radix_attempt(
                            &mut v, W, &cmp_rs,
                        ),
                    )
                },
                BatchSize::LargeInput,
            )
        });
        g.bench_function("gate_probe", |b| {
            b.iter(|| {
                black_box(frankenlibc_core::stdlib::sort::__bench_integer_order_gate(
                    black_box(&data),
                    W,
                    &cmp_rs,
                ))
            })
        });
        g.bench_function("full_qsort_fl", |b| {
            b.iter_batched(
                || data.clone(),
                |mut v| {
                    frankenlibc_core::stdlib::sort::qsort(&mut v, W, cmp_rs);
                    black_box(v.len())
                },
                BatchSize::LargeInput,
            )
        });
        g.bench_function("full_qsort_glibc", |b| {
            b.iter_batched(
                || data.clone(),
                |mut v| {
                    unsafe { qsort(v.as_mut_ptr().cast(), n, W, cmp_c) };
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
