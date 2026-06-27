//! Head-to-head end-to-end `strftime` benchmark: frankenlibc vs host glibc
//! (cc/BlackThrush, BOLD-VERIFY). Validates the `ApiFamily::Time` membrane
//! fast-path additions (observe() + STRICT decide(), commit 47b89e129): `strftime`
//! is a hot, pure-computation (no syscall) timestamp formatter, so the per-call
//! membrane overhead it previously paid was a meaningful fraction.
//!
//! Numeric-only format ("%Y-%m-%d %H:%M:%S") so it is locale-independent and safe
//! to resolve glibc through `dlmopen(LM_ID_NEWLM)` (no LC_TIME month/day names).
//!
//! Run: `cargo bench -p frankenlibc-bench --bench strftime_glibc_bench --features abi-bench`
//! (PENDING: authored during the disk-low window; to be RUN when disk recovers.)

use std::ffi::{c_char, c_void};
use std::hint::black_box;
use std::sync::OnceLock;

use criterion::{criterion_group, criterion_main, Criterion};
use frankenlibc_abi::time_abi as fl;

type StrftimeFn = unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm) -> usize;

/// Host glibc `strftime` via dlmopen so frankenlibc's exported `strftime` cannot
/// shadow the baseline.
fn host_strftime() -> StrftimeFn {
    static H: OnceLock<usize> = OnceLock::new();
    let addr = *H.get_or_init(|| unsafe {
        let handle = libc::dlmopen(
            libc::LM_ID_NEWLM,
            b"libc.so.6\0".as_ptr().cast(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        );
        assert!(!handle.is_null(), "dlmopen libc.so.6 failed");
        let sym = libc::dlsym(handle, b"strftime\0".as_ptr().cast());
        assert!(!sym.is_null(), "dlsym strftime failed");
        sym as usize
    });
    unsafe { std::mem::transmute::<*mut c_void, StrftimeFn>(addr as *mut c_void) }
}

fn make_tm() -> libc::tm {
    // 2026-06-21 14:30:45, a Sunday (wday=0), yday=171. SAFETY: zeroed tm is a valid
    // all-fields-present value; we set the meaningful fields below.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = 45;
    tm.tm_min = 30;
    tm.tm_hour = 14;
    tm.tm_mday = 21;
    tm.tm_mon = 5; // June (0-based)
    tm.tm_year = 126; // 2026 - 1900
    tm.tm_wday = 0;
    tm.tm_yday = 171;
    tm.tm_isdst = 0;
    tm
}

fn bench(c: &mut Criterion) {
    let fmt = c"%Y-%m-%d %H:%M:%S";
    let fmt_hms = c"%H:%M:%S";
    let tm = make_tm();
    let host = host_strftime();

    // Sanity: both produce the same output for this numeric format.
    {
        let mut a = [0i8; 64];
        let mut b = [0i8; 64];
        let na = unsafe { fl::strftime(a.as_mut_ptr(), a.len(), fmt.as_ptr(), &tm) };
        let nb = unsafe { host(b.as_mut_ptr(), b.len(), fmt.as_ptr(), &tm) };
        assert_eq!(na, nb, "strftime length mismatch fl vs glibc");
        assert_eq!(a, b, "strftime bytes mismatch fl vs glibc");
    }
    {
        let mut a = [0i8; 64];
        let mut b = [0i8; 64];
        let na = unsafe { fl::strftime(a.as_mut_ptr(), a.len(), fmt_hms.as_ptr(), &tm) };
        let nb = unsafe { host(b.as_mut_ptr(), b.len(), fmt_hms.as_ptr(), &tm) };
        assert_eq!(na, nb, "strftime %H:%M:%S length mismatch fl vs glibc");
        assert_eq!(a, b, "strftime %H:%M:%S bytes mismatch fl vs glibc");
    }

    let mut group = c.benchmark_group("strftime_numeric_19");
    group.bench_function("frankenlibc_abi", |bencher| {
        bencher.iter(|| {
            let mut buf = [0i8; 64];
            let n = unsafe { fl::strftime(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), black_box(&tm)) };
            black_box((n, buf[0]));
        });
    });
    group.bench_function("host_glibc", |bencher| {
        bencher.iter(|| {
            let mut buf = [0i8; 64];
            let n = unsafe { host(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), black_box(&tm)) };
            black_box((n, buf[0]));
        });
    });
    group.finish();

    let mut group = c.benchmark_group("strftime_time_hms");
    group.bench_function("frankenlibc_abi", |bencher| {
        bencher.iter(|| {
            let mut buf = [0i8; 64];
            let n = unsafe {
                fl::strftime(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt_hms.as_ptr(),
                    black_box(&tm),
                )
            };
            black_box((n, buf[0]));
        });
    });
    group.bench_function("host_glibc", |bencher| {
        bencher.iter(|| {
            let mut buf = [0i8; 64];
            let n = unsafe {
                host(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt_hms.as_ptr(),
                    black_box(&tm),
                )
            };
            black_box((n, buf[0]));
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(50)
        .warm_up_time(std::time::Duration::from_millis(500))
        .measurement_time(std::time::Duration::from_secs(2));
    targets = bench
}
criterion_main!(benches);
