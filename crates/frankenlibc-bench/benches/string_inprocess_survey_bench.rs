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
    fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int;
    fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int;
    fn strncasecmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int;
    fn memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
    fn wcscmp(s1: *const i32, s2: *const i32) -> c_int;
    fn wcsncmp(s1: *const i32, s2: *const i32, n: usize) -> c_int;
    fn wmemcmp(s1: *const i32, s2: *const i32, n: usize) -> c_int;
    fn wcscasecmp(s1: *const i32, s2: *const i32) -> c_int;
    fn wcslen(s: *const i32) -> usize;
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

    // ---- strncmp — two strings equal for 30 bytes then differ IN the first
    // 32-byte SIMD panel (exercises the scalar re-scan of the broken panel).
    let s1n: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'X';
        v
    };
    let s2n: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'Y';
        v
    };
    let core_nc = frankenlibc_core::string::str::strncmp(&s1n, &s2n, 64);
    let gl_nc = unsafe { strncmp(s1n.as_ptr().cast::<c_char>(), s2n.as_ptr().cast::<c_char>(), 64) };
    assert_eq!(core_nc.signum(), gl_nc.signum(), "strncmp sign mismatch");
    let mut gn = c.benchmark_group("survey_strncmp");
    gn.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::str::strncmp(black_box(&s1n), &s2n, 64)))
    });
    gn.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strncmp(black_box(s1n.as_ptr().cast::<c_char>()), s2n.as_ptr().cast::<c_char>(), 64) }))
    });
    gn.finish();

    // ---- strcmp — NUL-terminated, equal for 30 bytes then differ at byte 30
    // (deep in the first panel). Verifies whether strcmp's tier-cascade keeps it
    // ~parity (unlike strncmp's ≤32B rescan).
    let s1c: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'X';
        v[63] = 0;
        v
    };
    let s2c: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'Y';
        v[63] = 0;
        v
    };
    let core_sc = frankenlibc_core::string::str::strcmp(&s1c, &s2c);
    let gl_sc = unsafe { strcmp(s1c.as_ptr().cast::<c_char>(), s2c.as_ptr().cast::<c_char>()) };
    assert_eq!(core_sc.signum(), gl_sc.signum(), "strcmp sign mismatch");
    let mut gsc = c.benchmark_group("survey_strcmp");
    gsc.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::str::strcmp(black_box(&s1c), &s2c)))
    });
    gsc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcmp(black_box(s1c.as_ptr().cast::<c_char>()), s2c.as_ptr().cast::<c_char>()) }))
    });
    gsc.finish();

    // ---- strncasecmp — case-insensitively equal for 30 bytes (a vs A) then differ
    // at byte 30 (deep in the first panel). Checks the case-fold fast-path's break.
    let s1ic: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'X';
        v
    };
    let s2ic: Vec<u8> = {
        let mut v = vec![b'A'; 64]; // 'A' == 'a' case-insensitively for the first 30
        v[30] = b'Y';
        v
    };
    let core_ic = frankenlibc_core::string::str::strncasecmp(&s1ic, &s2ic, 64);
    let gl_ic = unsafe { strncasecmp(s1ic.as_ptr().cast::<c_char>(), s2ic.as_ptr().cast::<c_char>(), 64) };
    assert_eq!(core_ic.signum(), gl_ic.signum(), "strncasecmp sign mismatch");
    let mut gic = c.benchmark_group("survey_strncasecmp");
    gic.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::str::strncasecmp(black_box(&s1ic), &s2ic, 64)))
    });
    gic.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strncasecmp(black_box(s1ic.as_ptr().cast::<c_char>()), s2ic.as_ptr().cast::<c_char>(), 64) }))
    });
    gic.finish();

    // ---- memcmp — binary buffers equal for 30 bytes then differ at byte 30 (deep
    // in the first panel; exercises the compare_bytes scalar re-scan of the panel).
    let m1: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'X';
        v
    };
    let m2: Vec<u8> = {
        let mut v = vec![b'a'; 64];
        v[30] = b'Y';
        v
    };
    let core_mc = frankenlibc_core::string::mem::memcmp(&m1, &m2, 64);
    let gl_mc = unsafe { memcmp(m1.as_ptr().cast::<c_void>(), m2.as_ptr().cast::<c_void>(), 64) };
    assert_eq!(
        core_mc == std::cmp::Ordering::Less,
        gl_mc < 0,
        "memcmp sign mismatch"
    );
    let mut gm = c.benchmark_group("survey_memcmp");
    gm.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memcmp(black_box(&m1), &m2, 64)))
    });
    gm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memcmp(black_box(m1.as_ptr().cast::<c_void>()), m2.as_ptr().cast::<c_void>(), 64) }))
    });
    gm.finish();

    // ---- wcscmp — wide strings equal for 30 then differ at byte 30, NUL-term.
    let w1: Vec<u32> = {
        let mut v = vec![b'a' as u32; 64];
        v[30] = b'X' as u32;
        v[63] = 0;
        v
    };
    let w2: Vec<u32> = {
        let mut v = vec![b'a' as u32; 64];
        v[30] = b'Y' as u32;
        v[63] = 0;
        v
    };
    let core_wcc = frankenlibc_core::string::wide::wcscmp(&w1, &w2);
    let gl_wcc = unsafe { wcscmp(w1.as_ptr().cast::<i32>(), w2.as_ptr().cast::<i32>()) };
    assert_eq!(core_wcc.signum(), gl_wcc.signum(), "wcscmp sign mismatch");
    let mut gwc = c.benchmark_group("survey_wcscmp");
    gwc.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcscmp(black_box(&w1), &w2)))
    });
    gwc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcscmp(black_box(w1.as_ptr().cast::<i32>()), w2.as_ptr().cast::<i32>()) }))
    });
    gwc.finish();

    // ---- wcsncmp + wmemcmp — reuse the w1/w2 wide buffers (differ at byte 30).
    let core_wnc = frankenlibc_core::string::wide::wcsncmp(&w1, &w2, 64);
    let gl_wnc = unsafe { wcsncmp(w1.as_ptr().cast::<i32>(), w2.as_ptr().cast::<i32>(), 64) };
    assert_eq!(core_wnc.signum(), gl_wnc.signum(), "wcsncmp sign mismatch");
    let mut gwn = c.benchmark_group("survey_wcsncmp");
    gwn.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcsncmp(black_box(&w1), &w2, 64)))
    });
    gwn.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsncmp(black_box(w1.as_ptr().cast::<i32>()), w2.as_ptr().cast::<i32>(), 64) }))
    });
    gwn.finish();

    let core_wm = frankenlibc_core::string::wide::wmemcmp(&w1, &w2, 64);
    let gl_wm = unsafe { wmemcmp(w1.as_ptr().cast::<i32>(), w2.as_ptr().cast::<i32>(), 64) };
    assert_eq!(core_wm.signum(), gl_wm.signum(), "wmemcmp sign mismatch");
    let mut gwm = c.benchmark_group("survey_wmemcmp");
    gwm.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wmemcmp(black_box(&w1), &w2, 64)))
    });
    gwm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wmemcmp(black_box(w1.as_ptr().cast::<i32>()), w2.as_ptr().cast::<i32>(), 64) }))
    });
    gwm.finish();

    // ---- wcscasecmp — wide, case-insensitively equal (a vs A) for 30 then differ
    // at byte 30, NUL-term.
    let wic1: Vec<u32> = {
        let mut v = vec![b'a' as u32; 64];
        v[30] = b'X' as u32;
        v[63] = 0;
        v
    };
    let wic2: Vec<u32> = {
        let mut v = vec![b'A' as u32; 64];
        v[30] = b'Y' as u32;
        v[63] = 0;
        v
    };
    let core_wic = frankenlibc_core::string::wide::wcscasecmp(&wic1, &wic2);
    let gl_wic = unsafe { wcscasecmp(wic1.as_ptr().cast::<i32>(), wic2.as_ptr().cast::<i32>()) };
    assert_eq!(core_wic.signum(), gl_wic.signum(), "wcscasecmp sign mismatch");
    let mut gwic = c.benchmark_group("survey_wcscasecmp");
    gwic.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcscasecmp(black_box(&wic1), &wic2)))
    });
    gwic.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcscasecmp(black_box(wic1.as_ptr().cast::<i32>()), wic2.as_ptr().cast::<i32>()) }))
    });
    gwic.finish();

    // ---- wcslen — LONG wide string (NUL at 250 of 300) so the 256-element folded
    // block runs and its NUL-position scalar re-scan is exercised.
    let wl: Vec<u32> = {
        let mut v = vec![b'a' as u32; 300];
        v[250] = 0;
        v
    };
    let core_wl = frankenlibc_core::string::wide::wcslen(&wl);
    let gl_wl = unsafe { wcslen(wl.as_ptr().cast::<i32>()) };
    assert_eq!(core_wl, 250, "wcslen core wrong");
    assert_eq!(core_wl, gl_wl, "wcslen vs glibc mismatch");
    let mut gwl = c.benchmark_group("survey_wcslen_long");
    gwl.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcslen(black_box(&wl))))
    });
    gwl.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcslen(black_box(wl.as_ptr().cast::<i32>())) }))
    });
    gwl.finish();

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
