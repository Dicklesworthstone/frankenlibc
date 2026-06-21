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
    fn wmemchr(s: *const i32, c: i32, n: usize) -> *const i32;
    fn wcsspn(s: *const i32, accept: *const i32) -> usize;
    fn wmemset(s: *mut i32, c: i32, n: usize) -> *mut i32;
    fn wmemcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
    fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *const c_void;
    fn fnmatch(pat: *const c_char, s: *const c_char, flags: c_int) -> c_int;
    fn wcsstr(h: *const i32, n: *const i32) -> *const i32;
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

    // ---- wcsrchr (reverse wide search) — 128 wide chars so the 64-lane chunk loop
    // runs; single 'X' at 100, NUL at 127 (last X before NUL = 100).
    let wrbuf: Vec<u32> = {
        let mut v = vec![b'a' as u32; 128];
        v[100] = b'X' as u32;
        v[127] = 0;
        v
    };
    let core_wr = frankenlibc_core::string::wide::wcsrchr(&wrbuf, b'X' as u32);
    let gl_wr = unsafe { wcsrchr(wrbuf.as_ptr().cast::<i32>(), b'X' as i32) };
    assert_eq!(core_wr, Some(100), "wcsrchr core position wrong");
    assert_eq!(!gl_wr.is_null(), core_wr.is_some(), "wcsrchr found-ness mismatch");
    let mut gwr = c.benchmark_group("survey_wcsrchr");
    gwr.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcsrchr(black_box(&wrbuf), b'X' as u32)))
    });
    gwr.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsrchr(black_box(wrbuf.as_ptr().cast::<i32>()), b'X' as i32) }))
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

    // ---- wmemchr — LONG (match 'X' at 250 of 300) so the 256-element folded block runs.
    let wm2: Vec<u32> = {
        let mut v = vec![b'a' as u32; 300];
        v[250] = b'X' as u32;
        v
    };
    let core_wmc = frankenlibc_core::string::wide::wmemchr(&wm2, b'X' as u32, 300);
    let gl_wmc = unsafe { wmemchr(wm2.as_ptr().cast::<i32>(), b'X' as i32, 300) };
    assert_eq!(core_wmc, Some(250), "wmemchr core wrong");
    assert_eq!(core_wmc.is_some(), !gl_wmc.is_null(), "wmemchr found-ness mismatch");
    let mut gwm2 = c.benchmark_group("survey_wmemchr_long");
    gwm2.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wmemchr(black_box(&wm2), b'X' as u32, 300)))
    });
    gwm2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wmemchr(black_box(wm2.as_ptr().cast::<i32>()), b'X' as i32, 300) }))
    });
    gwm2.finish();

    // ---- wcsspn — accepted run of 'a' then a non-member 'Z' at 30 (deep in a panel).
    let wsp: Vec<u32> = {
        let mut v = vec![b'a' as u32; 64];
        v[30] = b'Z' as u32;
        v[63] = 0;
        v
    };
    let wacc: Vec<u32> = vec![b'a' as u32, 0];
    let core_sp = frankenlibc_core::string::wide::wcsspn(&wsp, &wacc);
    let gl_sp = unsafe { wcsspn(wsp.as_ptr().cast::<i32>(), wacc.as_ptr().cast::<i32>()) };
    assert_eq!(core_sp, 30, "wcsspn core wrong");
    assert_eq!(core_sp, gl_sp, "wcsspn vs glibc mismatch");
    let mut gsp = c.benchmark_group("survey_wcsspn");
    gsp.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcsspn(black_box(&wsp), &wacc)))
    });
    gsp.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsspn(black_box(wsp.as_ptr().cast::<i32>()), wacc.as_ptr().cast::<i32>()) }))
    });
    gsp.finish();

    // ---- wmemset / wmemcpy — 256 wide chars (fill / copy throughput vs glibc).
    let mut wset_dst = vec![0u32; 256];
    let mut wset_gl = vec![0i32; 256];
    {
        frankenlibc_core::string::wide::wmemset(&mut wset_dst, b'q' as u32, 256);
        unsafe { wmemset(wset_gl.as_mut_ptr(), b'q' as i32, 256) };
        assert!(wset_dst.iter().all(|&x| x == b'q' as u32), "wmemset core wrong");
    }
    let mut gws = c.benchmark_group("survey_wmemset");
    gws.bench_function("frankenlibc_core", |b| {
        b.iter(|| frankenlibc_core::string::wide::wmemset(black_box(&mut wset_dst), b'q' as u32, 256))
    });
    gws.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| unsafe { wmemset(black_box(wset_gl.as_mut_ptr()), b'q' as i32, 256) })
    });
    gws.finish();

    let wcp_src = vec![b'z' as u32; 256];
    let mut wcp_dst = vec![0u32; 256];
    let wcp_src_i = vec![b'z' as i32; 256];
    let mut wcp_gl = vec![0i32; 256];
    let mut gwcp = c.benchmark_group("survey_wmemcpy");
    gwcp.bench_function("frankenlibc_core", |b| {
        b.iter(|| frankenlibc_core::string::wide::wmemcpy(black_box(&mut wcp_dst), &wcp_src, 256))
    });
    gwcp.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| unsafe { wmemcpy(black_box(wcp_gl.as_mut_ptr()), wcp_src_i.as_ptr(), 256) })
    });
    gwcp.finish();

    // ---- memmem DIRECT (isolates from strstr's strlen) — same 79-byte hay, 11-byte
    // needle at the end. Localizes whether the strstr 3.1x gap is memmem itself.
    let mmhay = b"the quick brown fox jumps over the lazy dog and then some more text needle_here";
    let mmndl = b"needle_here";
    let core_mm = frankenlibc_core::string::mem::memmem(mmhay, mmhay.len(), mmndl, mmndl.len());
    let gl_mm = unsafe { memmem(mmhay.as_ptr().cast(), mmhay.len(), mmndl.as_ptr().cast(), mmndl.len()) };
    assert_eq!(core_mm.is_some(), !gl_mm.is_null(), "memmem found-ness mismatch");
    let mut gmm = c.benchmark_group("survey_memmem");
    gmm.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memmem(black_box(mmhay), mmhay.len(), mmndl, mmndl.len())))
    });
    gmm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memmem(black_box(mmhay.as_ptr().cast()), mmhay.len(), mmndl.as_ptr().cast(), mmndl.len()) }))
    });
    gmm.finish();

    // ---- memmem diagnostics: dual-anchor FLOOR (rare last byte 'X' → 1 candidate)
    // vs Two-Way-forced (adversarial: needle "aaaa...ab" first byte common 'a').
    let mm_rl_hay = b"the quick brown fox jumps over the lazy dog and then some text needle_herX";
    let mm_rl_ndl = b"needle_herX"; // last byte 'X' occurs only at the match
    let mut grl = c.benchmark_group("survey_memmem_rarelast");
    grl.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memmem(black_box(mm_rl_hay), mm_rl_hay.len(), mm_rl_ndl, mm_rl_ndl.len())))
    });
    grl.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memmem(black_box(mm_rl_hay.as_ptr().cast()), mm_rl_hay.len(), mm_rl_ndl.as_ptr().cast(), mm_rl_ndl.len()) }))
    });
    grl.finish();

    // Adversarial: 'a'-run haystack, needle "aaaaaaaaab" — first byte 'a' is every
    // position → first-byte path bails to Two-Way fast → measures ~Two-Way.
    let mm_tw_hay: Vec<u8> = {
        let mut v = vec![b'a'; 79];
        v[68..79].copy_from_slice(b"aaaaaaaaaab");
        v
    };
    let mm_tw_ndl = b"aaaaaaaaab";
    let mut gtw = c.benchmark_group("survey_memmem_twoway");
    gtw.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memmem(black_box(&mm_tw_hay), mm_tw_hay.len(), mm_tw_ndl, mm_tw_ndl.len())))
    });
    gtw.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memmem(black_box(mm_tw_hay.as_ptr().cast()), mm_tw_hay.len(), mm_tw_ndl.as_ptr().cast(), mm_tw_ndl.len()) }))
    });
    gtw.finish();

    // ---- memmem per-candidate cost (controlled): needle "qXXXXXXXXe" (first 'q'
    // rare=4, last 'e' common=16 → first-byte path on 'q'). Both haystacks 70 B,
    // match at 60; vary ONLY decoy 'q' count (1 vs 4 candidates). (cand4-cand1)/3
    // isolates per-candidate (memchr-restart + verify) cost at equal bytes scanned.
    let mmc_ndl = b"qXXXXXXXXe";
    let mk = |qpos: &[usize]| -> Vec<u8> {
        let mut v = vec![b'.'; 70];
        v[60..70].copy_from_slice(mmc_ndl);
        for &p in qpos {
            v[p] = b'q'; // decoy 'q' followed by '.' (!= 'X') → verify fails fast
        }
        v
    };
    let cand1 = mk(&[]); // only the match's 'q' at 60
    let cand4 = mk(&[0, 20, 40]); // 3 decoy 'q's + the match
    assert_eq!(frankenlibc_core::string::mem::memmem(&cand1, 70, mmc_ndl, 10), Some(60));
    assert_eq!(frankenlibc_core::string::mem::memmem(&cand4, 70, mmc_ndl, 10), Some(60));
    let mut gc1 = c.benchmark_group("survey_memmem_cand1");
    gc1.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memmem(black_box(&cand1), 70, mmc_ndl, 10)))
    });
    gc1.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memmem(black_box(cand1.as_ptr().cast()), 70, mmc_ndl.as_ptr().cast(), 10) }))
    });
    gc1.finish();
    let mut gc4 = c.benchmark_group("survey_memmem_cand4");
    gc4.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::mem::memmem(black_box(&cand4), 70, mmc_ndl, 10)))
    });
    gc4.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memmem(black_box(cand4.as_ptr().cast()), 70, mmc_ndl.as_ptr().cast(), 10) }))
    });
    gc4.finish();

    // ---- fnmatch (pure, non-ifunc) — typical glob + a backtrack-heavy star pattern.
    use frankenlibc_core::string::fnmatch::{fnmatch_match, FnmatchFlags};
    let fm_pat = c"*_2024_*.txt";
    let fm_txt = c"report_2024_final.txt";
    let core_fm = fnmatch_match(b"*_2024_*.txt", b"report_2024_final.txt", FnmatchFlags::NONE);
    let gl_fm = unsafe { fnmatch(fm_pat.as_ptr(), fm_txt.as_ptr(), 0) };
    assert_eq!(core_fm, gl_fm == 0, "fnmatch mismatch");
    let mut gfm = c.benchmark_group("survey_fnmatch_glob");
    gfm.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(fnmatch_match(black_box(b"*_2024_*.txt"), b"report_2024_final.txt", FnmatchFlags::NONE)))
    });
    gfm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { fnmatch(black_box(fm_pat.as_ptr()), fm_txt.as_ptr(), 0) }))
    });
    gfm.finish();

    // Backtrack-heavy: many stars over a long text (stresses the matcher).
    let fm_pat2 = c"*a*b*c*d*e*";
    let fm_txt2 = c"xxaxxbxxcxxdxxexxxxxxxxxxxxxxxxxxxxxxxxxxxxend";
    let mut gfm2 = c.benchmark_group("survey_fnmatch_stars");
    gfm2.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(fnmatch_match(black_box(b"*a*b*c*d*e*"), b"xxaxxbxxcxxdxxexxxxxxxxxxxxxxxxxxxxxxxxxxxxend", FnmatchFlags::NONE)))
    });
    gfm2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { fnmatch(black_box(fm_pat2.as_ptr()), fm_txt2.as_ptr(), 0) }))
    });
    gfm2.finish();

    // ---- wcsstr (wide substring, non-ifunc) — same text as the strstr survey.
    let wss_hay: Vec<u32> = "the quick brown fox jumps over the lazy dog and then some more text needle_here"
        .bytes().map(|b| b as u32).chain(std::iter::once(0)).collect();
    let wss_ndl: Vec<u32> = "needle_here".bytes().map(|b| b as u32).chain(std::iter::once(0)).collect();
    let core_wss = frankenlibc_core::string::wide::wcsstr(&wss_hay, &wss_ndl);
    let gl_wss = unsafe { wcsstr(wss_hay.as_ptr().cast::<i32>(), wss_ndl.as_ptr().cast::<i32>()) };
    assert_eq!(core_wss.is_some(), !gl_wss.is_null(), "wcsstr found-ness mismatch");
    let mut gwss = c.benchmark_group("survey_wcsstr");
    gwss.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcsstr(black_box(&wss_hay), &wss_ndl)))
    });
    gwss.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsstr(black_box(wss_hay.as_ptr().cast::<i32>()), wss_ndl.as_ptr().cast::<i32>()) }))
    });
    gwss.finish();

    // wcsstr rare-last guard (needle ends in rare 'X') — must NOT regress vs the
    // last-anchor path (the commonness gate should still pick last here).
    let wss_hay2: Vec<u32> = "the quick brown fox jumps over the lazy dog and then text needle_herX"
        .bytes().map(|b| b as u32).chain(std::iter::once(0)).collect();
    let wss_ndl2: Vec<u32> = "needle_herX".bytes().map(|b| b as u32).chain(std::iter::once(0)).collect();
    let mut gwss2 = c.benchmark_group("survey_wcsstr_rarelast");
    gwss2.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::wide::wcsstr(black_box(&wss_hay2), &wss_ndl2)))
    });
    gwss2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsstr(black_box(wss_hay2.as_ptr().cast::<i32>()), wss_ndl2.as_ptr().cast::<i32>()) }))
    });
    gwss2.finish();

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
