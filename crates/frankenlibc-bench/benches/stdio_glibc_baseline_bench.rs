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
//! `snprintf` host arms resolve glibc through `dlmopen(LM_ID_NEWLM)` so
//! frankenlibc's exported symbols cannot shadow the baseline.
//!
//! Quantifies bd-2g7oyh.131: every frankenlibc `fgetc` byte pays a global
//! registry `Mutex` (often twice) plus a per-byte membrane `decide()`, vs
//! glibc's lock-free inline buffer-pointer bump.

use std::ffi::{CString, c_char, c_int, c_void};
use std::hint::black_box;
use std::sync::OnceLock;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_abi::stdio_abi as fl;

type SnprintfFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, ...) -> c_int;
type SprintfFn = unsafe extern "C" fn(*mut c_char, *const c_char, ...) -> c_int;

unsafe extern "C" {
    // Host glibc inline-fast-path getc (skips the per-FILE lock). The libc crate
    // does not surface this, so bind the host symbol directly.
    fn getc_unlocked(stream: *mut libc::FILE) -> c_int;
    #[link_name = "swprintf"]
    fn host_swprintf(s: *mut libc::wchar_t, n: usize, format: *const libc::wchar_t, ...) -> c_int;
}

const N: usize = 4096;

fn host_snprintf() -> SnprintfFn {
    static HOST_SNPRINTF: OnceLock<usize> = OnceLock::new();
    let addr = *HOST_SNPRINTF.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"snprintf\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym snprintf failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, SnprintfFn>(addr as *mut c_void) }
}

fn host_sprintf() -> SprintfFn {
    static HOST_SPRINTF: OnceLock<usize> = OnceLock::new();
    let addr = *HOST_SPRINTF.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"sprintf\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym sprintf failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, SprintfFn>(addr as *mut c_void) }
}

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
    let host = host_snprintf();

    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe {
                fl::snprintf(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), payload.as_ptr())
            };
            black_box((rc, buf[0]));
        });
    });

    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe { host(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), payload.as_ptr()) };
            black_box((rc, buf[0]));
        });
    });

    group.finish();
}

fn bench_snprintf_s_bare(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdio_glibc_baseline_snprintf_s_bare");
    let payload = CString::new("frankenlibc canonical log line payload").expect("payload");
    let fmt = c"%s";
    let host = host_snprintf();

    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe {
                fl::snprintf(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), payload.as_ptr())
            };
            black_box((rc, buf[0]));
        });
    });

    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe { host(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), payload.as_ptr()) };
            black_box((rc, buf[0]));
        });
    });

    group.finish();
}

fn bench_snprintf_literal(c: &mut Criterion) {
    let mut group = c.benchmark_group("stdio_glibc_baseline_snprintf_literal");
    let fmt = c"frankenlibc fixed log line without conversions\n";
    let host = host_snprintf();

    group.bench_function("frankenlibc_abi", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe { fl::snprintf(buf.as_mut_ptr(), buf.len(), fmt.as_ptr()) };
            black_box((rc, buf[0]));
        });
    });

    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 128];
            let rc = unsafe { host(buf.as_mut_ptr(), buf.len(), fmt.as_ptr()) };
            black_box((rc, buf[0]));
        });
    });

    group.finish();
}

fn bench_snprintf_c_bare(c: &mut Criterion) {
    let host = host_snprintf();
    let exact_fmt = c"%c";
    let generic_fmt = c"%1c";

    // Width one is semantically identical to bare %c but deliberately misses
    // the exact-format route, retaining the deployed generic pipeline as the
    // same-binary control. Check truncation, embedded NUL, and int-to-byte
    // conversion before entering any timer.
    for value in [0, b'A' as c_int, 0xff, 0x1234, -1] {
        for size in [0usize, 1, 2, 8] {
            let mut exact = [0x55_i8; 8];
            let mut generic = [0x55_i8; 8];
            let mut glibc = [0x55_i8; 8];
            let exact_rc =
                unsafe { fl::snprintf(exact.as_mut_ptr(), size, exact_fmt.as_ptr(), value) };
            let generic_rc =
                unsafe { fl::snprintf(generic.as_mut_ptr(), size, generic_fmt.as_ptr(), value) };
            let glibc_rc = unsafe { host(glibc.as_mut_ptr(), size, exact_fmt.as_ptr(), value) };
            assert_eq!(
                exact_rc, generic_rc,
                "exact/generic rc: value={value} size={size}"
            );
            assert_eq!(
                exact, generic,
                "exact/generic bytes: value={value} size={size}"
            );
            assert_eq!(
                exact_rc, glibc_rc,
                "exact/glibc rc: value={value} size={size}"
            );
            assert_eq!(exact, glibc, "exact/glibc bytes: value={value} size={size}");
        }
    }

    let mut group = c.benchmark_group("stdio_glibc_baseline_snprintf_c_bare");
    group.bench_function("generic_width1_control", |b| {
        b.iter(|| {
            let mut buf = [0i8; 8];
            let rc = unsafe {
                fl::snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    generic_fmt.as_ptr(),
                    black_box(b'A' as c_int),
                )
            };
            black_box((rc, buf[0]));
        });
    });
    group.bench_function("exact_c_candidate", |b| {
        b.iter(|| {
            let mut buf = [0i8; 8];
            let rc = unsafe {
                fl::snprintf(
                    buf.as_mut_ptr(),
                    buf.len(),
                    exact_fmt.as_ptr(),
                    black_box(b'A' as c_int),
                )
            };
            black_box((rc, buf[0]));
        });
    });
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 8];
            let rc = unsafe {
                host(
                    buf.as_mut_ptr(),
                    buf.len(),
                    exact_fmt.as_ptr(),
                    black_box(b'A' as c_int),
                )
            };
            black_box((rc, buf[0]));
        });
    });
    group.finish();
}

fn bench_sprintf_c_bare(c: &mut Criterion) {
    let host = host_sprintf();
    let exact_fmt = c"%c";
    let generic_fmt = c"%1c";

    // Width one is semantically identical to bare %c but deliberately misses
    // the exact-format route, retaining the deployed generic pipeline as the
    // same-binary control. Prove embedded NUL and int-to-byte conversion before
    // entering any timer.
    for value in [0, b'A' as c_int, 0xff, 0x1234, -1] {
        let mut exact = [0x55_i8; 8];
        let mut generic = [0x55_i8; 8];
        let mut glibc = [0x55_i8; 8];
        let exact_rc = unsafe { fl::sprintf(exact.as_mut_ptr(), exact_fmt.as_ptr(), value) };
        let generic_rc = unsafe { fl::sprintf(generic.as_mut_ptr(), generic_fmt.as_ptr(), value) };
        let glibc_rc = unsafe { host(glibc.as_mut_ptr(), exact_fmt.as_ptr(), value) };
        assert_eq!(exact_rc, generic_rc, "exact/generic rc: value={value}");
        assert_eq!(exact, generic, "exact/generic bytes: value={value}");
        assert_eq!(exact_rc, glibc_rc, "exact/glibc rc: value={value}");
        assert_eq!(exact, glibc, "exact/glibc bytes: value={value}");
    }

    let mut group = c.benchmark_group("stdio_glibc_baseline_sprintf_c_bare");
    group.bench_function("generic_width1_control", |b| {
        b.iter(|| {
            let mut buf = [0i8; 8];
            let rc = unsafe {
                fl::sprintf(
                    buf.as_mut_ptr(),
                    generic_fmt.as_ptr(),
                    black_box(b'A' as c_int),
                )
            };
            black_box((rc, buf[0]));
        });
    });
    group.bench_function("exact_c_candidate", |b| {
        b.iter(|| {
            let mut buf = [0i8; 8];
            let rc = unsafe {
                fl::sprintf(
                    buf.as_mut_ptr(),
                    exact_fmt.as_ptr(),
                    black_box(b'A' as c_int),
                )
            };
            black_box((rc, buf[0]));
        });
    });
    group.bench_function("host_glibc", |b| {
        b.iter(|| {
            let mut buf = [0i8; 8];
            let rc = unsafe {
                host(
                    buf.as_mut_ptr(),
                    exact_fmt.as_ptr(),
                    black_box(b'A' as c_int),
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
            let rc =
                unsafe { host_swprintf(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 12345 as c_int) };
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
        bench_snprintf_s_bare, bench_snprintf_literal, bench_snprintf_c_bare,
        bench_sprintf_c_bare, bench_swprintf_wide_format
}
criterion_main!(benches);
