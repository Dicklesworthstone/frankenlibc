//! Head-to-head stdio microbenchmark: frankenlibc vs host glibc.
//!
//! stdio was a blind spot in `glibc_baseline_bench` (which only covers
//! frankenlibc-core functions). This isolates the per-byte cost of buffered
//! reads — the hot path for `while ((c = getc(fp)) != EOF)` parsers — using
//! `fmemopen`-backed streams so there is no real I/O, only the wrapper overhead.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench stdio_glibc_baseline_bench
//!       --features abi-bench`
//!
//! Quantifies bd-2g7oyh.131: every frankenlibc `fgetc` byte pays a global
//! registry `Mutex` (often twice) plus a per-byte membrane `decide()`, vs
//! glibc's lock-free inline buffer-pointer bump.

use std::ffi::{CString, c_void};
use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdio_abi as fl;

const N: usize = 4096;

fn bench_fgetc(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdio_glibc_baseline_fgetc_4096");
    let data = vec![b'x'; N];
    let mode = CString::new("r").expect("mode");

    // frankenlibc: fmemopen-backed read stream, full sequential getc sweep.
    let fl_buf = data.clone();
    let fl_fp = unsafe { fl::fmemopen(fl_buf.as_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!fl_fp.is_null(), "fl::fmemopen returned NULL");
    assert_eq!(unsafe { fl::fgetc(fl_fp) }, b'x' as i32, "fl::fgetc sanity");
    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            unsafe { fl::rewind(fl_fp) };
            let mut sum = 0i64;
            for _ in 0..N {
                sum += unsafe { fl::fgetc(fl_fp) } as i64;
            }
            black_box(sum);
        });
    });
    unsafe { fl::fclose(fl_fp) };

    // host glibc: identical fmemopen + getc sweep.
    let gl_buf = data.clone();
    let gl_fp = unsafe { libc::fmemopen(gl_buf.as_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!gl_fp.is_null(), "libc::fmemopen returned NULL");
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            unsafe { libc::rewind(gl_fp) };
            let mut sum = 0i64;
            for _ in 0..N {
                sum += unsafe { libc::fgetc(gl_fp) } as i64;
            }
            black_box(sum);
        });
    });
    unsafe { libc::fclose(gl_fp) };

    // Keep the backing buffers alive until both streams are closed above.
    drop(fl_buf);
    drop(gl_buf);
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(150))
        .measurement_time(Duration::from_millis(400));
    targets = bench_fgetc
}
criterion_main!(benches);
