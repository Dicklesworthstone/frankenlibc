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
    fn memrchr(s: *const c_void, c: c_int, n: usize) -> *const c_void;
    fn wcschr(wcs: *const i32, wc: i32) -> *const i32;
    fn wcsrchr(wcs: *const i32, wc: i32) -> *const i32;
}

fn bench(c: &mut Criterion) {
    // ---- strspn (bitmap) ---- match IN-CHUNK at index 15 (exercises the SIMD
    // mask trailing_zeros position, not just the scalar remainder tail).
    let span = c"aaaaaaaaaaaaaaaXaaaaaaaaaaaaaaaaaaaa"; // 15 accept then 'X' (non-accept)
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

    // ---- strcspn (bitmap, len-3 reject) ----
    let cspan = c"abcdefghijklmnopqrstuvwwwwwwwwwXyz"; // run of non-reject then 'X' in reject
    let reject = c"XYZ";
    assert_eq!(
        core_str::strcspn(cspan.to_bytes(), reject.to_bytes()),
        unsafe { strcspn(cspan.as_ptr(), reject.as_ptr()) },
        "strcspn mismatch"
    );
    let mut gc = c.benchmark_group("survey_strcspn");
    gc.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strcspn(black_box(cspan.to_bytes()), reject.to_bytes())))
    });
    gc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcspn(black_box(cspan.as_ptr()), reject.as_ptr()) }))
    });
    gc.finish();

    // ---- strpbrk (len-3 accept) ----
    let pstr = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXyz"; // run then 'X' (in accept)
    let pacc = c"XYZ";
    let core_pb = core_str::strpbrk(pstr.to_bytes(), pacc.to_bytes());
    let gl_pb = unsafe { strpbrk(pstr.as_ptr(), pacc.as_ptr()) };
    assert_eq!(core_pb.is_some(), !gl_pb.is_null(), "strpbrk found-ness mismatch");
    let mut gp = c.benchmark_group("survey_strpbrk");
    gp.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strpbrk(black_box(pstr.to_bytes()), pacc.to_bytes())))
    });
    gp.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strpbrk(black_box(pstr.as_ptr()), pacc.as_ptr()) }))
    });
    gp.finish();

    // ---- strcspn with a 6-char reject set (exercises span_general/span_scan, not
    // the len<=4 fast paths) — in-chunk match at index 15.
    let cspan6 = c"aaaaaaaaaaaaaaaXaaaaaaaaaaaaaaaaaaaa"; // 'X' (in reject) at 15
    let reject6 = c"XYZ123";
    assert_eq!(
        core_str::strcspn(cspan6.to_bytes(), reject6.to_bytes()),
        unsafe { strcspn(cspan6.as_ptr(), reject6.as_ptr()) },
        "strcspn(6-set) mismatch"
    );
    let mut gs = c.benchmark_group("survey_strcspn_set6");
    gs.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strcspn(black_box(cspan6.to_bytes()), reject6.to_bytes())))
    });
    gs.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcspn(black_box(cspan6.as_ptr()), reject6.as_ptr()) }))
    });
    gs.finish();

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
    // ---- memrchr (reverse byte search) — match IN-CHUNK near the start so the
    // reverse scan reaches a flagged chunk (exercises the rposition re-scan).
    let mbuf: Vec<u8> = {
        let mut v = vec![b'a'; 200]; // >=128 so memrchr's folded block + inner loop runs
        v[100] = b'X';
        v
    };
    let core_mr = frankenlibc_core::string::mem::memrchr(&mbuf, b'X', mbuf.len());
    let gl_mr = unsafe { memrchr(mbuf.as_ptr().cast::<c_void>(), b'X' as c_int, mbuf.len()) };
    assert_eq!(core_mr.is_some(), !gl_mr.is_null(), "memrchr found-ness mismatch");
    assert_eq!(core_mr, Some(100), "memrchr position wrong");
    let mut gm = c.benchmark_group("survey_memrchr");
    gm.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memrchr(black_box(&mbuf), b'X', mbuf.len())))
    });
    gm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memrchr(black_box(mbuf.as_ptr().cast::<c_void>()), b'X' as c_int, mbuf.len()) }))
    });
    gm.finish();

    // ---- wcschr (wide char search) — removed the redundant wmemchr existence
    // pre-scan (was a 2nd full pass). NUL-terminated wide string, 'X' at index 30.
    let wbuf: Vec<u32> = {
        let mut v = vec![b'a' as u32; 60];
        v[30] = b'X' as u32;
        v[59] = 0; // NUL terminator
        v
    };
    let core_wc = frankenlibc_core::string::wide::wcschr(&wbuf, b'X' as u32);
    let gl_wc = unsafe { wcschr(wbuf.as_ptr().cast::<i32>(), b'X' as i32) };
    assert_eq!(core_wc, Some(30), "wcschr core position wrong");
    assert_eq!(!gl_wc.is_null(), core_wc.is_some(), "wcschr found-ness mismatch");
    let mut gw = c.benchmark_group("survey_wcschr");
    gw.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcschr(black_box(&wbuf), b'X' as u32)))
    });
    gw.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcschr(black_box(wbuf.as_ptr().cast::<i32>()), b'X' as i32) }))
    });
    gw.finish();

    // ---- wcsrchr (reverse wide search) — removed redundant wmemrchr pre-scan.
    let core_wr = frankenlibc_core::string::wide::wcsrchr(&wbuf, b'X' as u32);
    let gl_wr = unsafe { wcsrchr(wbuf.as_ptr().cast::<i32>(), b'X' as i32) };
    assert_eq!(core_wr, Some(30), "wcsrchr core position wrong");
    assert_eq!(!gl_wr.is_null(), core_wr.is_some(), "wcsrchr found-ness mismatch");
    let mut gwr = c.benchmark_group("survey_wcsrchr");
    gwr.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcsrchr(black_box(&wbuf), b'X' as u32)))
    });
    gwr.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsrchr(black_box(wbuf.as_ptr().cast::<i32>()), b'X' as i32) }))
    });
    gwr.finish();

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
