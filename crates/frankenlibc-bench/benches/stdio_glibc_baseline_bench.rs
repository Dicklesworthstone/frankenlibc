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

use std::ffi::c_int;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    // Host glibc inline-fast-path getc (skips the per-FILE lock). The libc crate
    // does not surface this, so bind the host symbol directly.
    fn getc_unlocked(stream: *mut libc::FILE) -> c_int;
    #[link_name = "swprintf"]
    fn host_swprintf(
        s: *mut libc::wchar_t,
        n: usize,
        format: *const libc::wchar_t,
        ...
    ) -> c_int;
}

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

/// Unlocked fast-path sweep: `getc_unlocked` is the idiom performance-conscious
/// C code uses (flockfile + getc_unlocked loop). glibc's is a true inline
/// buffer-pointer bump; frankenlibc's `fgetc_unlocked` currently delegates to
/// the full locked `fgetc`. This is the only stdio path where a real gap can
/// exist (bd-2g7oyh.131).
fn bench_fgetc_unlocked(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdio_glibc_baseline_fgetc_unlocked_4096");
    let data = vec![b'x'; N];
    let mode = CString::new("r").expect("mode");

    let fl_buf = data.clone();
    let fl_fp = unsafe { fl::fmemopen(fl_buf.as_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!fl_fp.is_null(), "fl::fmemopen returned NULL");
    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            unsafe { fl::rewind(fl_fp) };
            let mut sum = 0i64;
            for _ in 0..N {
                sum += unsafe { fl::fgetc_unlocked(fl_fp) } as i64;
            }
            black_box(sum);
        });
    });
    unsafe { fl::fclose(fl_fp) };

    let gl_buf = data.clone();
    let gl_fp = unsafe { libc::fmemopen(gl_buf.as_ptr() as *mut c_void, N, mode.as_ptr()) };
    assert!(!gl_fp.is_null(), "libc::fmemopen returned NULL");
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            unsafe { libc::rewind(gl_fp) };
            let mut sum = 0i64;
            for _ in 0..N {
                sum += unsafe { getc_unlocked(gl_fp) } as i64;
            }
            black_box(sum);
        });
    });
    unsafe { libc::fclose(gl_fp) };

    drop(fl_buf);
    drop(gl_buf);
    group.finish();
}

fn bench_snprintf_s_newline(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdio_glibc_baseline_snprintf_s_newline");
    let payload = CString::new("frankenlibc canonical log line payload").expect("payload");
    let fmt = c"%s\n";

    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe {
                fl::snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt.as_ptr(),
                    payload.as_ptr(),
                )
            };
            black_box((rc, buf[0]));
        });
    });

    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe {
                libc::snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt.as_ptr(),
                    payload.as_ptr(),
                )
            };
            black_box((rc, buf[0]));
        });
    });

    group.finish();
}

fn bench_swprintf_wide_format(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdio_glibc_baseline_swprintf_wide_format");
    let fmt: [libc::wchar_t; 10] = [
        b'v' as libc::wchar_t,
        b'a' as libc::wchar_t,
        b'l' as libc::wchar_t,
        b'u' as libc::wchar_t,
        b'e' as libc::wchar_t,
        b'=' as libc::wchar_t,
        b'%' as libc::wchar_t,
        b'd' as libc::wchar_t,
        b'\n' as libc::wchar_t,
        0,
    ];

    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            let mut buf = [0 as libc::wchar_t; 32];
            let rc = unsafe {
                frankenlibc_abi::wchar_abi::swprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt.as_ptr(),
                    12345 as c_int,
                )
            };
            black_box((rc, buf[0]));
        });
    });

    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0 as libc::wchar_t; 32];
            let rc = unsafe {
                host_swprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt.as_ptr(),
                    12345 as c_int,
                )
            };
            black_box((rc, buf[0]));
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_millis(150))
        .measurement_time(Duration::from_millis(400));
    targets = bench_fgetc, bench_fgetc_unlocked, bench_snprintf_s_newline,
        bench_swprintf_wide_format
}
criterion_main!(benches);
