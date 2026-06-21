//! RELIABLE in-process survey: frankenlibc CORE string fns vs REAL in-process glibc
//! (cc/BlackThrush, BOLD-VERIFY). No `abi-bench` feature → no fl no_mangle shadowing,
//! so the `extern "C"` glibc fns resolve to REAL ifunc-resolved in-process glibc and
//! `frankenlibc_core::string::*` is callable directly = trustworthy A/B (unlike the
//! dlmopen gauntlet, which inflates ifunc/locale baselines).
//!
//! Surveys strspn / strcspn / strpbrk (bitmap) + strstr / strcasestr (search) for any
//! real loss the dlmopen gauntlet may have masked.
//!
//! Run: `cargo bench -p frankenlibc-bench --bench string_inprocess_survey_bench`

use std::ffi::{c_char, c_int, c_void};
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use frankenlibc_core::string::str as core_str;

unsafe extern "C" {
    fn strspn(s: *const c_char, accept: *const c_char) -> usize;
    fn strcspn(s: *const c_char, reject: *const c_char) -> usize;
    fn strpbrk(s: *const c_char, accept: *const c_char) -> *const c_char;
    fn strstr(h: *const c_char, n: *const c_char) -> *const c_char;
    fn strcasestr(h: *const c_char, n: *const c_char) -> *const c_char;
}

fn bench(c: &mut Criterion) {
    // ---- strspn (bitmap) ----
    let span = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXbcd"; // 31 accept chars then 'X'
    let accept = c"abc";
    assert_eq!(
        core_str::strspn(span.to_bytes(), accept.to_bytes()),
        unsafe { strspn(span.as_ptr(), accept.as_ptr()) },
        "strspn mismatch"
    );
    let mut g = c.benchmark_group("survey_strspn");
    g.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strspn(black_box(span.to_bytes()), accept.to_bytes())))
    });
    g.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strspn(black_box(span.as_ptr()), accept.as_ptr()) }))
    });
    g.finish();
    let _ = (strcspn, strpbrk); // (kept for future arms; referenced to avoid dead-code)

    // ---- strstr (search) ----
    let hay = c"the quick brown fox jumps over the lazy dog and then some more text needle_here";
    let needle = c"needle_here";
    let core_pos = core_str::strstr(hay.to_bytes(), needle.to_bytes());
    let gl = unsafe { strstr(hay.as_ptr(), needle.as_ptr()) };
    assert_eq!(core_pos.is_some(), !gl.is_null(), "strstr found-ness mismatch");
    let mut g2 = c.benchmark_group("survey_strstr");
    g2.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strstr(black_box(hay.to_bytes()), needle.to_bytes())))
    });
    g2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strstr(black_box(hay.as_ptr()), needle.as_ptr()) }))
    });
    g2.finish();

    // ---- strcasestr (case-insensitive search) ----
    let core_cp = core_str::strcasestr(hay.to_bytes(), c"NEEDLE_HERE".to_bytes());
    let gl2 = unsafe { strcasestr(hay.as_ptr(), c"NEEDLE_HERE".as_ptr()) };
    assert_eq!(core_cp.is_some(), !gl2.is_null(), "strcasestr found-ness mismatch");
    let mut g3 = c.benchmark_group("survey_strcasestr");
    g3.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strcasestr(black_box(hay.to_bytes()), c"NEEDLE_HERE".to_bytes())))
    });
    g3.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcasestr(black_box(hay.as_ptr()), c"NEEDLE_HERE".as_ptr()) }))
    });
    g3.finish();
    let _: c_int = 0;
    let _ = std::ptr::null::<c_void>();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(std::time::Duration::from_millis(400))
        .measurement_time(std::time::Duration::from_secs(1));
    targets = bench
}
criterion_main!(benches);
