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

use criterion::{Criterion, criterion_group, criterion_main};
use frankenlibc_core::string::str as core_str;

unsafe extern "C" {
    fn strspn(s: *const c_char, accept: *const c_char) -> usize;
    fn strcspn(s: *const c_char, reject: *const c_char) -> usize;
    fn strpbrk(s: *const c_char, accept: *const c_char) -> *const c_char;
    fn strstr(h: *const c_char, n: *const c_char) -> *const c_char;
    fn strcasestr(h: *const c_char, n: *const c_char) -> *const c_char;
    fn memrchr(s: *const c_void, c: c_int, n: usize) -> *const c_void;
    fn rawmemchr(s: *const c_void, c: c_int) -> *const c_void;
    fn strlen(s: *const c_char) -> usize;
    fn memfrob(s: *mut c_void, n: usize) -> *mut c_void;
    fn strchr(s: *const c_char, c: c_int) -> *const c_char;
    fn memchr(s: *const c_void, c: c_int, n: usize) -> *const c_void;
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
    fn wcsnlen(s: *const i32, maxlen: usize) -> usize;
    fn wmemchr(s: *const i32, c: i32, n: usize) -> *const i32;
    fn wcsspn(s: *const i32, accept: *const i32) -> usize;
    fn wcscspn(s: *const i32, reject: *const i32) -> usize;
    fn wcspbrk(s: *const i32, accept: *const i32) -> *const i32;
    fn wcschrnul(s: *const i32, wc: i32) -> *const i32;
    fn wmemset(s: *mut i32, c: i32, n: usize) -> *mut i32;
    fn wmemcpy(d: *mut i32, s: *const i32, n: usize) -> *mut i32;
    fn memmem(h: *const c_void, hl: usize, n: *const c_void, nl: usize) -> *const c_void;
    fn fnmatch(pat: *const c_char, s: *const c_char, flags: c_int) -> c_int;
    fn wcsstr(h: *const i32, n: *const i32) -> *const i32;
    fn strtok_r(s: *mut c_char, delim: *const c_char, saveptr: *mut *mut c_char) -> *mut c_char;
    fn wcstok(wcs: *mut i32, delim: *const i32, ptr: *mut *mut i32) -> *mut i32;
    fn asctime_r(tm: *const libc::tm, buf: *mut c_char) -> *mut c_char;
    fn gmtime_r(t: *const i64, tm: *mut libc::tm) -> *mut libc::tm;
    fn random() -> std::ffi::c_long;
    fn strrchr(s: *const c_char, c: c_int) -> *const c_char;
    fn strchrnul(s: *const c_char, c: c_int) -> *const c_char;
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
        b.iter(|| {
            black_box(core_str::strspn(
                black_box(span.to_bytes()),
                accept.to_bytes(),
            ))
        })
    });
    g.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strspn(black_box(span.as_ptr()), accept.as_ptr()) }))
    });
    g.finish();

    // ---- strspn len-3 accept, 60-byte all-accept run (find_non_any_of4 dual): scans
    // all 60 -> 1 chunk + 28-byte REMAINDER. Exercises the of4-dual overlapping-tail.
    let span60 = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 60 'a'
    let accept3 = c"abc";
    assert_eq!(core_str::strspn(span60.to_bytes(), accept3.to_bytes()), 60);
    let mut gsp = c.benchmark_group("survey_strspn_set3_60");
    gsp.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strspn(
                black_box(span60.to_bytes()),
                accept3.to_bytes(),
            ))
        })
    });
    gsp.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strspn(black_box(span60.as_ptr()), accept3.as_ptr()) }))
    });
    gsp.finish();

    // ---- strspn len-1 accept, 60-byte all-accept run (find_non_byte_or_nul dual of
    // find_byte_or_nul): 28-byte remainder -> the of-1 overlapping-tail.
    let accept1 = c"a";
    assert_eq!(core_str::strspn(span60.to_bytes(), accept1.to_bytes()), 60);
    let mut gsp1 = c.benchmark_group("survey_strspn_set1_60");
    gsp1.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strspn(
                black_box(span60.to_bytes()),
                accept1.to_bytes(),
            ))
        })
    });
    gsp1.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strspn(black_box(span60.as_ptr()), accept1.as_ptr()) }))
    });
    gsp1.finish();

    // ---- strspn len-6 accept (find_non_any_of6 dual), 64-byte all-accept run. of6 has
    // a 16-B prologue, so 64 = 16 + 32-chunk + 16-B remainder -> the of6-dual tail.
    let span64 = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64 'a'
    let accept6 = c"a \t\n\r\x0b"; // 6-char accept set including 'a'
    assert_eq!(core_str::strspn(span64.to_bytes(), accept6.to_bytes()), 64);
    let mut gsp6 = c.benchmark_group("survey_strspn_set6_64");
    gsp6.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strspn(
                black_box(span64.to_bytes()),
                accept6.to_bytes(),
            ))
        })
    });
    gsp6.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strspn(black_box(span64.as_ptr()), accept6.as_ptr()) }))
    });
    gsp6.finish();

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
        b.iter(|| {
            black_box(core_str::strcspn(
                black_box(cspan.to_bytes()),
                reject.to_bytes(),
            ))
        })
    });
    gc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcspn(black_box(cspan.as_ptr()), reject.as_ptr()) }))
    });
    gc.finish();

    // ---- strcspn len-6 reject (find_any_of6 path), 64-byte non-reject run so the
    // scan reaches the sub-32-byte REMAINDER (64 = 16 prologue + 32 chunk + 16 tail).
    // Exercises the overlapping-tail SIMD over the of6 scanner.
    let cspan6 = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 64 'a'
    let reject6 = c" \t\n\r\x0c\x0b"; // 6-char whitespace set, none == 'a'
    assert_eq!(
        core_str::strcspn(cspan6.to_bytes(), reject6.to_bytes()),
        unsafe { strcspn(cspan6.as_ptr(), reject6.as_ptr()) },
        "strcspn len-6 mismatch"
    );
    assert_eq!(core_str::strcspn(cspan6.to_bytes(), reject6.to_bytes()), 64);
    let mut gc6 = c.benchmark_group("survey_strcspn_set6");
    gc6.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strcspn(
                black_box(cspan6.to_bytes()),
                reject6.to_bytes(),
            ))
        })
    });
    gc6.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcspn(black_box(cspan6.as_ptr()), reject6.as_ptr()) }))
    });
    gc6.finish();

    // ---- strcspn len-3 reject (find_any_of4 path), 60-byte non-reject run. find_any_of4
    // has NO prologue, so 60 = 1x 32-chunk + 28-byte REMAINDER -> exercises the of4
    // overlapping-tail (the hottest, len-2..4, path). (A 64-byte run would be 2 exact
    // chunks with zero remainder and would NOT test the fix.)
    let cspan60 = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 60 'a'
    let reject3 = c"XYZ";
    assert_eq!(
        core_str::strcspn(cspan60.to_bytes(), reject3.to_bytes()),
        60
    );
    let mut gc3 = c.benchmark_group("survey_strcspn_set3_60");
    gc3.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strcspn(
                black_box(cspan60.to_bytes()),
                reject3.to_bytes(),
            ))
        })
    });
    gc3.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcspn(black_box(cspan60.as_ptr()), reject3.as_ptr()) }))
    });
    gc3.finish();

    // ---- strcspn len-1 reject (find_byte_or_nul path), 60-byte non-reject run ->
    // 28-byte remainder. Exercises the find_byte_or_nul overlapping-tail (strchr/
    // memchr/strcspn-1 share this scanner).
    let reject1 = c"X";
    assert_eq!(
        core_str::strcspn(cspan60.to_bytes(), reject1.to_bytes()),
        60
    );
    let mut gc1 = c.benchmark_group("survey_strcspn_set1_60");
    gc1.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strcspn(
                black_box(cspan60.to_bytes()),
                reject1.to_bytes(),
            ))
        })
    });
    gc1.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcspn(black_box(cspan60.as_ptr()), reject1.as_ptr()) }))
    });
    gc1.finish();

    // ---- strpbrk (len-3 accept) ----
    let pstr = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaXyz"; // run then 'X' (in accept)
    let pacc = c"XYZ";
    let core_pb = core_str::strpbrk(pstr.to_bytes(), pacc.to_bytes());
    let gl_pb = unsafe { strpbrk(pstr.as_ptr(), pacc.as_ptr()) };
    assert_eq!(
        core_pb.is_some(),
        !gl_pb.is_null(),
        "strpbrk found-ness mismatch"
    );
    let mut gp = c.benchmark_group("survey_strpbrk");
    gp.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strpbrk(
                black_box(pstr.to_bytes()),
                pacc.to_bytes(),
            ))
        })
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
        b.iter(|| {
            black_box(core_str::strcspn(
                black_box(cspan6.to_bytes()),
                reject6.to_bytes(),
            ))
        })
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
    assert_eq!(
        core_pos.is_some(),
        !gl.is_null(),
        "strstr found-ness mismatch"
    );
    let mut g2 = c.benchmark_group("survey_strstr");
    g2.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strstr(
                black_box(hay.to_bytes()),
                needle.to_bytes(),
            ))
        })
    });
    g2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strstr(black_box(hay.as_ptr()), needle.as_ptr()) }))
    });
    g2.finish();

    // ---- strcasestr (case-insensitive search) ----
    let core_cp = core_str::strcasestr(hay.to_bytes(), c"NEEDLE_HERE".to_bytes());
    let gl2 = unsafe { strcasestr(hay.as_ptr(), c"NEEDLE_HERE".as_ptr()) };
    assert_eq!(
        core_cp.is_some(),
        !gl2.is_null(),
        "strcasestr found-ness mismatch"
    );
    let mut g3 = c.benchmark_group("survey_strcasestr");
    g3.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strcasestr(
                black_box(hay.to_bytes()),
                c"NEEDLE_HERE".to_bytes(),
            ))
        })
    });
    g3.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { strcasestr(black_box(hay.as_ptr()), c"NEEDLE_HERE".as_ptr()) })
        })
    });
    g3.finish();

    // ---- strcasestr where the needle's first char is ABSENT from a 60-byte haystack:
    // find_ascii_folded scans all 60 (-> 28-byte remainder) for 'z'/'Z', finds none.
    // Exercises the find_ascii_folded overlapping-tail (strcasestr first-char scan).
    let hay60 = c"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 60 'a'
    let needle_z = c"zoo";
    assert!(core_str::strcasestr(hay60.to_bytes(), needle_z.to_bytes()).is_none());
    let mut g3b = c.benchmark_group("survey_strcasestr_absent60");
    g3b.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(core_str::strcasestr(
                black_box(hay60.to_bytes()),
                needle_z.to_bytes(),
            ))
        })
    });
    g3b.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strcasestr(black_box(hay60.as_ptr()), needle_z.as_ptr()) }))
    });
    g3b.finish();
    // ---- memrchr (reverse byte search) — match IN-CHUNK near the start so the
    // reverse scan reaches a flagged chunk (exercises the rposition re-scan).
    let mbuf: Vec<u8> = {
        let mut v = vec![b'a'; 200]; // >=128 so memrchr's folded block + inner loop runs
        v[100] = b'X';
        v
    };
    let core_mr = frankenlibc_core::string::mem::memrchr(&mbuf, b'X', mbuf.len());
    let gl_mr = unsafe { memrchr(mbuf.as_ptr().cast::<c_void>(), b'X' as c_int, mbuf.len()) };
    assert_eq!(
        core_mr.is_some(),
        !gl_mr.is_null(),
        "memrchr found-ness mismatch"
    );
    assert_eq!(core_mr, Some(100), "memrchr position wrong");
    let mut gm = c.benchmark_group("survey_memrchr");
    gm.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memrchr(
                black_box(&mbuf),
                b'X',
                mbuf.len(),
            ))
        })
    });
    gm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memrchr(
                    black_box(mbuf.as_ptr().cast::<c_void>()),
                    b'X' as c_int,
                    mbuf.len(),
                )
            })
        })
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
    assert_eq!(
        !gl_wc.is_null(),
        core_wc.is_some(),
        "wcschr found-ness mismatch"
    );
    let mut gw = c.benchmark_group("survey_wcschr");
    gw.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcschr(
                black_box(&wbuf),
                b'X' as u32,
            ))
        })
    });
    gw.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcschr(black_box(wbuf.as_ptr().cast::<i32>()), b'X' as i32) }))
    });
    gw.finish();

    // ---- wcschr ABSENT needle: scans the whole 60-wc string to the NUL at 59 —
    // which lies in the sub-32-lane REMAINDER. Exercises the overlapping-tail SIMD
    // (the original scalar tail left ~28 of 60 wc scalar).
    let core_wa = frankenlibc_core::string::wide::wcschr(&wbuf, b'Z' as u32);
    assert_eq!(core_wa, None, "wcschr absent should be None");
    let mut gwa = c.benchmark_group("survey_wcschr_absent");
    gwa.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcschr(
                black_box(&wbuf),
                b'Z' as u32,
            ))
        })
    });
    gwa.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcschr(black_box(wbuf.as_ptr().cast::<i32>()), b'Z' as i32) }))
    });
    gwa.finish();

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
    assert_eq!(
        !gl_wr.is_null(),
        core_wr.is_some(),
        "wcsrchr found-ness mismatch"
    );
    let mut gwr = c.benchmark_group("survey_wcsrchr");
    gwr.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcsrchr(
                black_box(&wrbuf),
                b'X' as u32,
            ))
        })
    });
    gwr.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { wcsrchr(black_box(wrbuf.as_ptr().cast::<i32>()), b'X' as i32) })
        })
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
    let gl_nc = unsafe {
        strncmp(
            s1n.as_ptr().cast::<c_char>(),
            s2n.as_ptr().cast::<c_char>(),
            64,
        )
    };
    assert_eq!(core_nc.signum(), gl_nc.signum(), "strncmp sign mismatch");
    let mut gn = c.benchmark_group("survey_strncmp");
    gn.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::str::strncmp(
                black_box(&s1n),
                &s2n,
                64,
            ))
        })
    });
    gn.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                strncmp(
                    black_box(s1n.as_ptr().cast::<c_char>()),
                    s2n.as_ptr().cast::<c_char>(),
                    64,
                )
            })
        })
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
        b.iter(|| {
            black_box(unsafe {
                strcmp(
                    black_box(s1c.as_ptr().cast::<c_char>()),
                    s2c.as_ptr().cast::<c_char>(),
                )
            })
        })
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
    let gl_ic = unsafe {
        strncasecmp(
            s1ic.as_ptr().cast::<c_char>(),
            s2ic.as_ptr().cast::<c_char>(),
            64,
        )
    };
    assert_eq!(
        core_ic.signum(),
        gl_ic.signum(),
        "strncasecmp sign mismatch"
    );
    let mut gic = c.benchmark_group("survey_strncasecmp");
    gic.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::str::strncasecmp(
                black_box(&s1ic),
                &s2ic,
                64,
            ))
        })
    });
    gic.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                strncasecmp(
                    black_box(s1ic.as_ptr().cast::<c_char>()),
                    s2ic.as_ptr().cast::<c_char>(),
                    64,
                )
            })
        })
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
    let gl_mc = unsafe {
        memcmp(
            m1.as_ptr().cast::<c_void>(),
            m2.as_ptr().cast::<c_void>(),
            64,
        )
    };
    assert_eq!(
        core_mc == std::cmp::Ordering::Less,
        gl_mc < 0,
        "memcmp sign mismatch"
    );
    let mut gm = c.benchmark_group("survey_memcmp");
    gm.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memcmp(
                black_box(&m1),
                &m2,
                64,
            ))
        })
    });
    gm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memcmp(
                    black_box(m1.as_ptr().cast::<c_void>()),
                    m2.as_ptr().cast::<c_void>(),
                    64,
                )
            })
        })
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
        b.iter(|| {
            black_box(unsafe {
                wcscmp(
                    black_box(w1.as_ptr().cast::<i32>()),
                    w2.as_ptr().cast::<i32>(),
                )
            })
        })
    });
    gwc.finish();

    // ---- wcsncmp + wmemcmp — reuse the w1/w2 wide buffers (differ at byte 30).
    let core_wnc = frankenlibc_core::string::wide::wcsncmp(&w1, &w2, 64);
    let gl_wnc = unsafe { wcsncmp(w1.as_ptr().cast::<i32>(), w2.as_ptr().cast::<i32>(), 64) };
    assert_eq!(core_wnc.signum(), gl_wnc.signum(), "wcsncmp sign mismatch");
    let mut gwn = c.benchmark_group("survey_wcsncmp");
    gwn.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcsncmp(
                black_box(&w1),
                &w2,
                64,
            ))
        })
    });
    gwn.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcsncmp(
                    black_box(w1.as_ptr().cast::<i32>()),
                    w2.as_ptr().cast::<i32>(),
                    64,
                )
            })
        })
    });
    gwn.finish();

    let core_wm = frankenlibc_core::string::wide::wmemcmp(&w1, &w2, 64);
    let gl_wm = unsafe { wmemcmp(w1.as_ptr().cast::<i32>(), w2.as_ptr().cast::<i32>(), 64) };
    assert_eq!(core_wm.signum(), gl_wm.signum(), "wmemcmp sign mismatch");
    let mut gwm = c.benchmark_group("survey_wmemcmp");
    gwm.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wmemcmp(
                black_box(&w1),
                &w2,
                64,
            ))
        })
    });
    gwm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wmemcmp(
                    black_box(w1.as_ptr().cast::<i32>()),
                    w2.as_ptr().cast::<i32>(),
                    64,
                )
            })
        })
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
    assert_eq!(
        core_wic.signum(),
        gl_wic.signum(),
        "wcscasecmp sign mismatch"
    );
    let mut gwic = c.benchmark_group("survey_wcscasecmp");
    gwic.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcscasecmp(
                black_box(&wic1),
                &wic2,
            ))
        })
    });
    gwic.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcscasecmp(
                    black_box(wic1.as_ptr().cast::<i32>()),
                    wic2.as_ptr().cast::<i32>(),
                )
            })
        })
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
    assert_eq!(
        core_wmc.is_some(),
        !gl_wmc.is_null(),
        "wmemchr found-ness mismatch"
    );
    let mut gwm2 = c.benchmark_group("survey_wmemchr_long");
    gwm2.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wmemchr(
                black_box(&wm2),
                b'X' as u32,
                300,
            ))
        })
    });
    gwm2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { wmemchr(black_box(wm2.as_ptr().cast::<i32>()), b'X' as i32, 300) })
        })
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
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcsspn(
                black_box(&wsp),
                &wacc,
            ))
        })
    });
    gsp.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcsspn(
                    black_box(wsp.as_ptr().cast::<i32>()),
                    wacc.as_ptr().cast::<i32>(),
                )
            })
        })
    });
    gsp.finish();

    // ---- wcscspn — non-reject run of 'a' then a reject 'Z' at 30 (deep in a panel).
    let wcsp: Vec<u32> = {
        let mut v = vec![b'a' as u32; 64];
        v[30] = b'Z' as u32;
        v[63] = 0;
        v
    };
    let wrej: Vec<u32> = vec![b'Z' as u32, 0];
    let core_csp = frankenlibc_core::string::wide::wcscspn(&wcsp, &wrej);
    let gl_csp = unsafe { wcscspn(wcsp.as_ptr().cast::<i32>(), wrej.as_ptr().cast::<i32>()) };
    assert_eq!(core_csp, 30, "wcscspn core wrong");
    assert_eq!(core_csp, gl_csp, "wcscspn vs glibc mismatch");
    let mut gcsp = c.benchmark_group("survey_wcscspn");
    gcsp.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcscspn(
                black_box(&wcsp),
                &wrej,
            ))
        })
    });
    gcsp.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcscspn(
                    black_box(wcsp.as_ptr().cast::<i32>()),
                    wrej.as_ptr().cast::<i32>(),
                )
            })
        })
    });
    gcsp.finish();

    // ---- wcspbrk — first accept-member 'Z' at 30 (deep in a panel).
    let wpb: Vec<u32> = {
        let mut v = vec![b'a' as u32; 64];
        v[30] = b'Z' as u32;
        v[63] = 0;
        v
    };
    let wpacc: Vec<u32> = vec![b'Z' as u32, 0];
    let core_pb = frankenlibc_core::string::wide::wcspbrk(&wpb, &wpacc);
    let gl_pb = unsafe { wcspbrk(wpb.as_ptr().cast::<i32>(), wpacc.as_ptr().cast::<i32>()) };
    assert_eq!(core_pb, Some(30), "wcspbrk core wrong");
    assert_eq!(
        core_pb.is_some(),
        !gl_pb.is_null(),
        "wcspbrk vs glibc found-ness mismatch"
    );
    let mut gpb = c.benchmark_group("survey_wcspbrk");
    gpb.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcspbrk(
                black_box(&wpb),
                &wpacc,
            ))
        })
    });
    gpb.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcspbrk(
                    black_box(wpb.as_ptr().cast::<i32>()),
                    wpacc.as_ptr().cast::<i32>(),
                )
            })
        })
    });
    gpb.finish();

    // ---- wmemset / wmemcpy — 256 wide chars (fill / copy throughput vs glibc).
    let mut wset_dst = vec![0u32; 256];
    let mut wset_gl = vec![0i32; 256];
    {
        frankenlibc_core::string::wide::wmemset(&mut wset_dst, b'q' as u32, 256);
        unsafe { wmemset(wset_gl.as_mut_ptr(), b'q' as i32, 256) };
        assert!(
            wset_dst.iter().all(|&x| x == b'q' as u32),
            "wmemset core wrong"
        );
    }
    let mut gws = c.benchmark_group("survey_wmemset");
    gws.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            frankenlibc_core::string::wide::wmemset(black_box(&mut wset_dst), b'q' as u32, 256)
        })
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
    let gl_mm = unsafe {
        memmem(
            mmhay.as_ptr().cast(),
            mmhay.len(),
            mmndl.as_ptr().cast(),
            mmndl.len(),
        )
    };
    assert_eq!(
        core_mm.is_some(),
        !gl_mm.is_null(),
        "memmem found-ness mismatch"
    );
    let mut gmm = c.benchmark_group("survey_memmem");
    gmm.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memmem(
                black_box(mmhay),
                mmhay.len(),
                mmndl,
                mmndl.len(),
            ))
        })
    });
    gmm.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memmem(
                    black_box(mmhay.as_ptr().cast()),
                    mmhay.len(),
                    mmndl.as_ptr().cast(),
                    mmndl.len(),
                )
            })
        })
    });
    gmm.finish();

    // ---- memmem diagnostics: dual-anchor FLOOR (rare last byte 'X' → 1 candidate)
    // vs Two-Way-forced (adversarial: needle "aaaa...ab" first byte common 'a').
    let mm_rl_hay = b"the quick brown fox jumps over the lazy dog and then some text needle_herX";
    let mm_rl_ndl = b"needle_herX"; // last byte 'X' occurs only at the match
    let mut grl = c.benchmark_group("survey_memmem_rarelast");
    grl.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memmem(
                black_box(mm_rl_hay),
                mm_rl_hay.len(),
                mm_rl_ndl,
                mm_rl_ndl.len(),
            ))
        })
    });
    grl.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memmem(
                    black_box(mm_rl_hay.as_ptr().cast()),
                    mm_rl_hay.len(),
                    mm_rl_ndl.as_ptr().cast(),
                    mm_rl_ndl.len(),
                )
            })
        })
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
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memmem(
                black_box(&mm_tw_hay),
                mm_tw_hay.len(),
                mm_tw_ndl,
                mm_tw_ndl.len(),
            ))
        })
    });
    gtw.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memmem(
                    black_box(mm_tw_hay.as_ptr().cast()),
                    mm_tw_hay.len(),
                    mm_tw_ndl.as_ptr().cast(),
                    mm_tw_ndl.len(),
                )
            })
        })
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
    assert_eq!(
        frankenlibc_core::string::mem::memmem(&cand1, 70, mmc_ndl, 10),
        Some(60)
    );
    assert_eq!(
        frankenlibc_core::string::mem::memmem(&cand4, 70, mmc_ndl, 10),
        Some(60)
    );
    let mut gc1 = c.benchmark_group("survey_memmem_cand1");
    gc1.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memmem(
                black_box(&cand1),
                70,
                mmc_ndl,
                10,
            ))
        })
    });
    gc1.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memmem(
                    black_box(cand1.as_ptr().cast()),
                    70,
                    mmc_ndl.as_ptr().cast(),
                    10,
                )
            })
        })
    });
    gc1.finish();
    let mut gc4 = c.benchmark_group("survey_memmem_cand4");
    gc4.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memmem(
                black_box(&cand4),
                70,
                mmc_ndl,
                10,
            ))
        })
    });
    gc4.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memmem(
                    black_box(cand4.as_ptr().cast()),
                    70,
                    mmc_ndl.as_ptr().cast(),
                    10,
                )
            })
        })
    });
    gc4.finish();

    // ---- fnmatch (pure, non-ifunc) — typical glob + a backtrack-heavy star pattern.
    use frankenlibc_core::string::fnmatch::{FnmatchFlags, fnmatch_match};
    let fm_pat = c"*_2024_*.txt";
    let fm_txt = c"report_2024_final.txt";
    let core_fm = fnmatch_match(
        b"*_2024_*.txt",
        b"report_2024_final.txt",
        FnmatchFlags::NONE,
    );
    let gl_fm = unsafe { fnmatch(fm_pat.as_ptr(), fm_txt.as_ptr(), 0) };
    assert_eq!(core_fm, gl_fm == 0, "fnmatch mismatch");
    let mut gfm = c.benchmark_group("survey_fnmatch_glob");
    gfm.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(fnmatch_match(
                black_box(b"*_2024_*.txt"),
                b"report_2024_final.txt",
                FnmatchFlags::NONE,
            ))
        })
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
        b.iter(|| {
            black_box(fnmatch_match(
                black_box(b"*a*b*c*d*e*"),
                b"xxaxxbxxcxxdxxexxxxxxxxxxxxxxxxxxxxxxxxxxxxend",
                FnmatchFlags::NONE,
            ))
        })
    });
    gfm2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { fnmatch(black_box(fm_pat2.as_ptr()), fm_txt2.as_ptr(), 0) }))
    });
    gfm2.finish();

    // ---- wcsstr (wide substring, non-ifunc) — same text as the strstr survey.
    let wss_hay: Vec<u32> =
        "the quick brown fox jumps over the lazy dog and then some more text needle_here"
            .bytes()
            .map(|b| b as u32)
            .chain(std::iter::once(0))
            .collect();
    let wss_ndl: Vec<u32> = "needle_here"
        .bytes()
        .map(|b| b as u32)
        .chain(std::iter::once(0))
        .collect();
    let core_wss = frankenlibc_core::string::wide::wcsstr(&wss_hay, &wss_ndl);
    let gl_wss = unsafe {
        wcsstr(
            wss_hay.as_ptr().cast::<i32>(),
            wss_ndl.as_ptr().cast::<i32>(),
        )
    };
    assert_eq!(
        core_wss.is_some(),
        !gl_wss.is_null(),
        "wcsstr found-ness mismatch"
    );
    let mut gwss = c.benchmark_group("survey_wcsstr");
    gwss.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcsstr(
                black_box(&wss_hay),
                &wss_ndl,
            ))
        })
    });
    gwss.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcsstr(
                    black_box(wss_hay.as_ptr().cast::<i32>()),
                    wss_ndl.as_ptr().cast::<i32>(),
                )
            })
        })
    });
    gwss.finish();

    // wcsstr rare-last guard (needle ends in rare 'X') — must NOT regress vs the
    // last-anchor path (the commonness gate should still pick last here).
    let wss_hay2: Vec<u32> =
        "the quick brown fox jumps over the lazy dog and then text needle_herX"
            .bytes()
            .map(|b| b as u32)
            .chain(std::iter::once(0))
            .collect();
    let wss_ndl2: Vec<u32> = "needle_herX"
        .bytes()
        .map(|b| b as u32)
        .chain(std::iter::once(0))
        .collect();
    let mut gwss2 = c.benchmark_group("survey_wcsstr_rarelast");
    gwss2.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcsstr(
                black_box(&wss_hay2),
                &wss_ndl2,
            ))
        })
    });
    gwss2.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wcsstr(
                    black_box(wss_hay2.as_ptr().cast::<i32>()),
                    wss_ndl2.as_ptr().cast::<i32>(),
                )
            })
        })
    });
    gwss2.finish();

    // ---- strtok_r — first token is a LONG (56-char) delimiter-free run, then ','.
    // Both impls write a NUL at the delim, so each iter resets from the template
    // (reset cost is in BOTH arms → cancels in the ratio). Measures the token-end
    // scan: fl's scalar DelimSet loop vs glibc's (SIMD strspn/strcspn-based).
    let tok_template: &[u8] = b"this_is_a_fairly_long_token_without_any_delimiters_here,tail\0";
    let mut tok_buf = tok_template.to_vec();
    let r0 =
        frankenlibc_core::string::strtok::strtok_r(&mut tok_buf[..tok_template.len() - 1], b",", 0);
    assert_eq!(
        r0.map(|(s, l, _)| (s, l)),
        Some((0usize, 55usize)),
        "strtok_r core wrong"
    );
    let mut gtk = c.benchmark_group("survey_strtok_r");
    gtk.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            tok_buf.copy_from_slice(tok_template);
            black_box(frankenlibc_core::string::strtok::strtok_r(
                black_box(&mut tok_buf[..tok_template.len() - 1]),
                b",",
                0,
            ))
        })
    });
    let mut gtk_buf = tok_template.to_vec();
    gtk.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            gtk_buf.copy_from_slice(tok_template);
            let mut sp: *mut c_char = std::ptr::null_mut();
            black_box(unsafe {
                strtok_r(
                    black_box(gtk_buf.as_mut_ptr().cast::<c_char>()),
                    c",".as_ptr(),
                    &mut sp,
                )
            })
        })
    });
    gtk.finish();

    // ---- wcstok — wide first token is a long delimiter-free run then ','. Reset
    // each iter (both write NUL → reset cost cancels).
    let wtok_template: Vec<u32> = "this_is_a_fairly_long_wide_token_without_any_delims,tail"
        .bytes()
        .map(|b| b as u32)
        .chain(std::iter::once(0))
        .collect();
    let mut wtok_buf = wtok_template.clone();
    let wdelim: Vec<u32> = vec![b',' as u32, 0];
    let r0 = frankenlibc_core::string::wide::wcstok(
        &mut wtok_buf[..wtok_template.len() - 1],
        &wdelim,
        0,
    );
    assert_eq!(r0.map(|(s, _)| s), Some(0usize), "wcstok core wrong");
    let mut gwtk = c.benchmark_group("survey_wcstok");
    gwtk.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            wtok_buf.copy_from_slice(&wtok_template);
            black_box(frankenlibc_core::string::wide::wcstok(
                black_box(&mut wtok_buf[..wtok_template.len() - 1]),
                &wdelim,
                0,
            ))
        })
    });
    let wtok_template_i: Vec<i32> = wtok_template.iter().map(|&x| x as i32).collect();
    let mut gwtk_buf: Vec<i32> = wtok_template_i.clone();
    let wdelim_i: Vec<i32> = vec![b',' as i32, 0];
    gwtk.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            // Symmetric reset: copy_from_slice (memcpy) matches the fl arm exactly so
            // the reset cost cancels in the ratio (was a slower per-element loop).
            gwtk_buf.copy_from_slice(&wtok_template_i);
            let mut sp: *mut i32 = std::ptr::null_mut();
            black_box(unsafe {
                wcstok(black_box(gwtk_buf.as_mut_ptr()), wdelim_i.as_ptr(), &mut sp)
            })
        })
    });
    gwtk.finish();

    // ---- asctime (fixed 26-byte formatter, pure/non-ifunc, English-only). fl uses
    // core::fmt::write into a stack buffer; glibc uses a manual sprintf.
    use frankenlibc_core::time::{BrokenDownTime, format_asctime};
    let bd = BrokenDownTime {
        tm_sec: 45,
        tm_min: 30,
        tm_hour: 14,
        tm_mday: 21,
        tm_mon: 5,
        tm_year: 126,
        tm_wday: 0,
        tm_yday: 171,
        ..Default::default()
    };
    let mut atm: libc::tm = unsafe { std::mem::zeroed() };
    atm.tm_sec = 45;
    atm.tm_min = 30;
    atm.tm_hour = 14;
    atm.tm_mday = 21;
    atm.tm_mon = 5;
    atm.tm_year = 126;
    atm.tm_wday = 0;
    atm.tm_yday = 171;
    {
        let mut cb = [0u8; 32];
        let n = format_asctime(&bd, &mut cb);
        let mut gb = [0i8; 32];
        unsafe { asctime_r(&atm, gb.as_mut_ptr()) };
        let gbytes: &[u8] = unsafe { std::ffi::CStr::from_ptr(gb.as_ptr()).to_bytes() };
        assert_eq!(&cb[..n], gbytes, "asctime byte mismatch");
    }
    let mut gat = c.benchmark_group("survey_asctime");
    gat.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            let mut cb = [0u8; 32];
            let n = format_asctime(black_box(&bd), &mut cb);
            black_box((n, cb[0]))
        })
    });
    gat.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut gb = [0i8; 32];
            let p = unsafe { asctime_r(black_box(&atm), gb.as_mut_ptr()) };
            black_box((p, gb[0]))
        })
    });
    gat.finish();

    // ---- gmtime (epoch -> calendar, pure/non-ifunc, O(1) civil_from_days both sides).
    let g_epoch: i64 = 1_750_000_000; // 2025-ish
    {
        let bd = frankenlibc_core::time::epoch_to_broken_down(g_epoch);
        let mut gt: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { gmtime_r(&g_epoch, &mut gt) };
        assert_eq!(bd.tm_year, gt.tm_year, "gmtime year mismatch");
        assert_eq!(bd.tm_mon, gt.tm_mon, "gmtime mon mismatch");
        assert_eq!(bd.tm_mday, gt.tm_mday, "gmtime mday mismatch");
        assert_eq!(bd.tm_hour, gt.tm_hour, "gmtime hour mismatch");
        assert_eq!(bd.tm_wday, gt.tm_wday, "gmtime wday mismatch");
    }
    let mut ggt = c.benchmark_group("survey_gmtime");
    ggt.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::time::epoch_to_broken_down(black_box(
                g_epoch,
            )))
        })
    });
    ggt.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            let mut gt: libc::tm = unsafe { std::mem::zeroed() };
            unsafe { gmtime_r(black_box(&g_epoch), &mut gt) };
            black_box(gt.tm_year)
        })
    });
    ggt.finish();

    // ---- random() (PRNG state update; both fl and glibc lock per call).
    let _ = frankenlibc_core::stdlib::sv_random();
    let _ = unsafe { random() };
    let mut grnd = c.benchmark_group("survey_random");
    grnd.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::stdlib::sv_random()))
    });
    grnd.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { random() }))
    });
    grnd.finish();

    // ---- strrchr — 300-byte string, '/' at 100, NUL at 299 (folded block flagged
    // → exercises the scalar block re-scan; also the redundant memchr pre-check).
    let rr: Vec<u8> = {
        let mut v = vec![b'a'; 300];
        v[100] = b'/';
        v[299] = 0;
        v
    };
    let core_rr = core_str::strrchr(&rr, b'/');
    let gl_rr = unsafe { strrchr(rr.as_ptr().cast::<c_char>(), b'/' as c_int) };
    assert_eq!(core_rr, Some(100), "strrchr core wrong");
    assert_eq!(
        core_rr.is_some(),
        !gl_rr.is_null(),
        "strrchr found-ness mismatch"
    );
    let mut grr = c.benchmark_group("survey_strrchr");
    grr.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strrchr(black_box(&rr), b'/')))
    });
    grr.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { strrchr(black_box(rr.as_ptr().cast::<c_char>()), b'/' as c_int) })
        })
    });
    grr.finish();

    // ---- strchrnul — 300-byte string, 'q' at 100, NUL at 299 (folded block flagged
    // → exercises find_byte_or_nul's scalar block re-scan; deep target at 100).
    let cn: Vec<u8> = {
        let mut v = vec![b'a'; 300];
        v[100] = b'q';
        v[299] = 0;
        v
    };
    let core_cn = core_str::strchrnul(&cn, b'q');
    let gl_cn = unsafe { strchrnul(cn.as_ptr().cast::<c_char>(), b'q' as c_int) };
    assert_eq!(core_cn, 100, "strchrnul core wrong");
    let mut gcn = c.benchmark_group("survey_strchrnul");
    gcn.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strchrnul(black_box(&cn), b'q')))
    });
    gcn.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { strchrnul(black_box(cn.as_ptr().cast::<c_char>()), b'q' as c_int) })
        })
    });
    gcn.finish();

    // ---- strspn(1-char) — 300 'a's with a non-accept 'X' at 100 (find_non_byte_or_nul
    // scalar-block-rescan). accept="a". strspn counts leading 'a's → 100.
    let sp1: Vec<u8> = {
        let mut v = vec![b'a'; 300];
        v[100] = b'X';
        v[299] = 0;
        v
    };
    let sp1_acc = b"a\0";
    let core_sp1 = core_str::strspn(&sp1, sp1_acc);
    let gl_sp1 = unsafe { strspn(sp1.as_ptr().cast::<c_char>(), c"a".as_ptr()) };
    assert_eq!(core_sp1, 100, "strspn1 core wrong");
    assert_eq!(core_sp1, gl_sp1, "strspn1 vs glibc mismatch");
    let mut gsp1 = c.benchmark_group("survey_strspn1");
    gsp1.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strspn(black_box(&sp1), sp1_acc)))
    });
    gsp1.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { strspn(black_box(sp1.as_ptr().cast::<c_char>()), c"a".as_ptr()) })
        })
    });
    gsp1.finish();

    // ---- strspn(range) — 300 digits with a non-digit 'X' at 100, accept "0..9"
    // (contiguous range → span_range scalar-block-resolve).
    let spr: Vec<u8> = {
        let mut v = vec![b'5'; 300];
        v[100] = b'X';
        v[299] = 0;
        v
    };
    let spr_acc = b"0123456789\0";
    let core_spr = core_str::strspn(&spr, spr_acc);
    let gl_spr = unsafe { strspn(spr.as_ptr().cast::<c_char>(), c"0123456789".as_ptr()) };
    assert_eq!(core_spr, 100, "strspn-range core wrong");
    assert_eq!(core_spr, gl_spr, "strspn-range vs glibc mismatch");
    let mut gspr = c.benchmark_group("survey_strspn_range");
    gspr.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(core_str::strspn(black_box(&spr), spr_acc)))
    });
    gspr.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                strspn(
                    black_box(spr.as_ptr().cast::<c_char>()),
                    c"0123456789".as_ptr(),
                )
            })
        })
    });
    gspr.finish();

    // ---- rawmemchr (GNU, find-byte-assume-present). STALE-FIXED (cc/BoldFalcon
    // 2026-06-27): the deployed fl impl (string_abi.rs::rawmemchr) is NOW a 32-byte
    // aligned SIMD scan (bd-2g7oyh), NOT a scalar loop. The `scalar_historical` arm
    // below is the PRE-FIX baseline kept for reference only — it is NOT current
    // deployment, so DO NOT read its ratio as a live deployed gap (it falsely reads
    // ~39x). core::memchr is the SIMD speed proxy (≈ deployed). 1000-byte buf, 'Z' at 900.
    let rmc: Vec<u8> = {
        let mut v = vec![b'a'; 1000];
        v[900] = b'Z';
        v
    };
    let scalar_rawmemchr = |buf: &[u8], needle: u8| -> usize {
        let base = buf.as_ptr();
        let mut q = base;
        unsafe {
            loop {
                if *q == needle {
                    break;
                }
                q = q.add(1);
            }
            q.offset_from(base) as usize
        }
    };
    let off_scalar = scalar_rawmemchr(&rmc, b'Z');
    let off_simd = frankenlibc_core::string::mem::memchr(&rmc, b'Z', rmc.len()).unwrap();
    let off_gl = unsafe {
        rawmemchr(rmc.as_ptr().cast::<c_void>(), b'Z' as c_int) as usize - rmc.as_ptr() as usize
    };
    assert_eq!(off_scalar, 900, "rawmemchr scalar replica wrong");
    assert_eq!(off_simd, 900, "rawmemchr simd proxy wrong");
    assert_eq!(off_gl, 900, "rawmemchr glibc wrong");
    let mut grm = c.benchmark_group("survey_rawmemchr");
    grm.bench_function("frankenlibc_scalar_historical", |b| {
        b.iter(|| black_box(scalar_rawmemchr(black_box(&rmc), b'Z')))
    });
    grm.bench_function("frankenlibc_simd_fix_proxy", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memchr(
                black_box(&rmc),
                b'Z',
                rmc.len(),
            ))
        })
    });
    grm.bench_function("host_glibc", |b| {
        b.iter(|| {
            black_box(unsafe { rawmemchr(black_box(rmc.as_ptr().cast::<c_void>()), b'Z' as c_int) })
        })
    });
    grm.finish();

    // ---- wcschrnul (GNU wide find-wc-or-NUL). STALE-FIXED (cc/BoldFalcon 2026-06-27):
    // the deployed fl impl (wchar_abi.rs::wcschrnul) is NOW a SIMD wide scan
    // (`wide_find_or_nul_simd`, bd-2g7oyh), NOT a scalar loop. The `scalar_historical`
    // arm is the PRE-FIX baseline (NOT current deployment — do not read its ratio as a
    // live gap). glibc's wcschrnul IS scalar, so the deployed SIMD proxy (core wcschr)
    // WINS ~4x vs glibc. 1000 wide chars, 'Z' at 900, NUL at 999.
    let wcn: Vec<u32> = {
        let mut v = vec![b'a' as u32; 1000];
        v[900] = b'Z' as u32;
        v[999] = 0;
        v
    };
    let scalar_wcschrnul = |buf: &[u32], wc: u32| -> usize {
        let mut i = 0usize;
        loop {
            let c = buf[i];
            if c == wc || c == 0 {
                return i;
            }
            i += 1;
        }
    };
    let wcn_scalar = scalar_wcschrnul(&wcn, b'Z' as u32);
    let wcn_simd = frankenlibc_core::string::wide::wcschr(&wcn, b'Z' as u32).unwrap();
    let wcn_gl = unsafe {
        (wcschrnul(wcn.as_ptr().cast::<i32>(), b'Z' as i32) as usize - wcn.as_ptr() as usize) / 4
    };
    assert_eq!(wcn_scalar, 900, "wcschrnul scalar replica wrong");
    assert_eq!(wcn_simd, 900, "wcschrnul simd proxy wrong");
    assert_eq!(wcn_gl, 900, "wcschrnul glibc wrong");
    let mut gwcn = c.benchmark_group("survey_wcschrnul");
    gwcn.bench_function("frankenlibc_scalar_historical", |b| {
        b.iter(|| black_box(scalar_wcschrnul(black_box(&wcn), b'Z' as u32)))
    });
    gwcn.bench_function("frankenlibc_simd_fix_proxy", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcschr(
                black_box(&wcn),
                b'Z' as u32,
            ))
        })
    });
    gwcn.bench_function("host_glibc", |b| {
        b.iter(|| {
            black_box(unsafe { wcschrnul(black_box(wcn.as_ptr().cast::<i32>()), b'Z' as i32) })
        })
    });
    gwcn.finish();

    // ---- wmemchr (bounded wide find). glibc's wmemchr IS SIMD (unlike its scalar
    // wcschrnul) — a real head-to-head. 1000 wide, 'Z' at 900, n=1000.
    let wmc: Vec<u32> = {
        let mut v = vec![b'a' as u32; 1000];
        v[900] = b'Z' as u32;
        v
    };
    let wmc_core = frankenlibc_core::string::wide::wmemchr(&wmc, b'Z' as u32, wmc.len()).unwrap();
    let wmc_gl = unsafe {
        (wmemchr(wmc.as_ptr().cast::<i32>(), b'Z' as i32, wmc.len()) as usize
            - wmc.as_ptr() as usize)
            / 4
    };
    assert_eq!(wmc_core, 900, "wmemchr core wrong");
    assert_eq!(wmc_gl, 900, "wmemchr glibc wrong");
    let mut gwmc = c.benchmark_group("survey_wmemchr");
    gwmc.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wmemchr(
                black_box(&wmc),
                b'Z' as u32,
                wmc.len(),
            ))
        })
    });
    gwmc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                wmemchr(
                    black_box(wmc.as_ptr().cast::<i32>()),
                    b'Z' as i32,
                    wmc.len(),
                )
            })
        })
    });
    gwmc.finish();

    // ---- wcsnlen (bounded wide strlen). Direct 64-lane mask scan (fold removed,
    // same single-condition transform as wcslen). 1000 wide 'a', NUL at 900, maxlen 2000.
    let wnl: Vec<u32> = {
        let mut v = vec![b'a' as u32; 1000];
        v[900] = 0;
        v
    };
    let wnl_core = frankenlibc_core::string::wide::wcsnlen(&wnl, 2000);
    let wnl_gl = unsafe { wcsnlen(wnl.as_ptr().cast::<i32>(), 2000) };
    assert_eq!(wnl_core, 900, "wcsnlen core wrong");
    assert_eq!(wnl_core, wnl_gl, "wcsnlen vs glibc mismatch");
    let mut gwnl = c.benchmark_group("survey_wcsnlen");
    gwnl.bench_function("frankenlibc_core", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::wide::wcsnlen(
                black_box(&wnl),
                2000,
            ))
        })
    });
    gwnl.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { wcsnlen(black_box(wnl.as_ptr().cast::<i32>()), 2000) }))
    });
    gwnl.finish();

    // ---- strlen (THE most-called fn). fl uses a hierarchical min-fold (512/256/64
    // block_has_nul) + narrow; glibc is tuned AVX2. 1000-byte 'a', NUL at 900.
    let sl: Vec<u8> = {
        let mut v = vec![b'a'; 1001];
        v[900] = 0;
        v
    };
    let sl_core = frankenlibc_core::string::str::strlen(&sl);
    let sl_gl = unsafe { strlen(sl.as_ptr().cast::<c_char>()) };
    assert_eq!(sl_core, 900, "strlen core wrong");
    assert_eq!(sl_core, sl_gl, "strlen vs glibc mismatch");
    let mut gsl = c.benchmark_group("survey_strlen");
    gsl.bench_function("frankenlibc_core", |b| {
        b.iter(|| black_box(frankenlibc_core::string::str::strlen(black_box(&sl))))
    });
    gsl.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { strlen(black_box(sl.as_ptr().cast::<c_char>())) }))
    });
    gsl.finish();

    // ---- strchr: core does TWO memchr passes (find c, then re-scan prefix for NUL);
    // strchrnul does it in ONE pass. 1000-byte 'a', 'Z' at 900, NUL at 1000.
    let sc: Vec<u8> = {
        let mut v = vec![b'a'; 1001];
        v[900] = b'Z';
        v[1000] = 0;
        v
    };
    let sc_core = frankenlibc_core::string::str::strchr(&sc, b'Z');
    let sc_1pass = frankenlibc_core::string::str::strchrnul(&sc, b'Z');
    let sc_gl = unsafe { strchr(sc.as_ptr().cast::<c_char>(), b'Z' as c_int) };
    assert_eq!(sc_core, Some(900), "strchr core wrong");
    assert_eq!(sc_1pass, 900, "strchr 1-pass proxy wrong");
    assert!(!sc_gl.is_null(), "strchr glibc wrong");
    // NOTE (cc/BoldFalcon 2026-06-27): the deployed `strchr` is ALREADY 1-pass
    // (single `find_byte_or_nul` scan, bd-2g7oyh) — the old "2pass" label was stale.
    // The ~1.45ns it trails the `strchrnul` arm is just the `Option<usize>` wrap +
    // the `pos<len && s[pos]==c` bounds check (strchr's required null-vs-found
    // distinction), NOT a redundant second pass. Not a lever.
    let mut gsc = c.benchmark_group("survey_strchr");
    gsc.bench_function("frankenlibc_core_1pass", |b| {
        b.iter(|| black_box(frankenlibc_core::string::str::strchr(black_box(&sc), b'Z')))
    });
    gsc.bench_function("strchrnul_lowerbound_proxy", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::str::strchrnul(
                black_box(&sc),
                b'Z',
            ))
        })
    });
    gsc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe { strchr(black_box(sc.as_ptr().cast::<c_char>()), b'Z' as c_int) })
        })
    });
    gsc.finish();

    // ---- memchr (the byte-scan foundation under strchr/strchrnul/strcspn). 1000-byte
    // 'a', 'Z' at 900, n=1000.
    let mc: Vec<u8> = {
        let mut v = vec![b'a'; 1000];
        v[900] = b'Z';
        v
    };
    let mc_core = frankenlibc_core::string::mem::memchr(&mc, b'Z', mc.len()).unwrap();
    let mc_gl = unsafe {
        memchr(mc.as_ptr().cast::<c_void>(), b'Z' as c_int, mc.len()) as usize
            - mc.as_ptr() as usize
    };
    assert_eq!(mc_core, 900, "memchr core wrong");
    assert_eq!(mc_gl, 900, "memchr glibc wrong");
    // strchrnul on this NUL-free buffer is a DIRECT 64-lane c-scan (NUL check never
    // fires), tested as a "fold-free memchr" hypothesis. DISPROVEN (cc/BoldFalcon
    // 2026-06-27): the deployed FOLD memchr (9.1ns) BEATS this direct scan (11.0ns)
    // here, so dropping the fold would REGRESS — do not "simplify" memchr to a flat
    // scan. The residual 1.38x vs glibc (6.6ns) is the saturated deeper-AVX2/ifunc gap.
    let mc_direct = frankenlibc_core::string::str::strchrnul(&mc, b'Z');
    assert_eq!(mc_direct, 900, "memchr direct proxy wrong");
    let mut gmc = c.benchmark_group("survey_memchr");
    gmc.bench_function("frankenlibc_core_fold", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::mem::memchr(
                black_box(&mc),
                b'Z',
                mc.len(),
            ))
        })
    });
    gmc.bench_function("frankenlibc_direct_proxy", |b| {
        b.iter(|| {
            black_box(frankenlibc_core::string::str::strchrnul(
                black_box(&mc),
                b'Z',
            ))
        })
    });
    gmc.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| {
            black_box(unsafe {
                memchr(
                    black_box(mc.as_ptr().cast::<c_void>()),
                    b'Z' as c_int,
                    mc.len(),
                )
            })
        })
    });
    gmc.finish();

    // ---- memfrob (GNU, XOR each byte with 42). Deployed fl is a RAW-POINTER loop
    // (may not auto-vectorize); a slice loop auto-vectorizes. 1000-byte buffer.
    let mut mf = vec![0xA5u8; 1000];
    let mflen = mf.len();
    let mut gmf = c.benchmark_group("survey_memfrob");
    gmf.bench_function("frankenlibc_raw_current", |b| {
        b.iter(|| {
            let p = black_box(mf.as_mut_ptr());
            for i in 0..mflen {
                unsafe { *p.add(i) ^= 42 };
            }
            black_box(&mf);
        })
    });
    gmf.bench_function("frankenlibc_slice_fix", |b| {
        b.iter(|| {
            for byte in black_box(&mut mf).iter_mut() {
                *byte ^= 42;
            }
            black_box(&mf);
        })
    });
    gmf.bench_function("host_glibc_inprocess", |b| {
        b.iter(|| black_box(unsafe { memfrob(black_box(mf.as_mut_ptr()).cast::<c_void>(), mflen) }))
    });
    gmf.finish();

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
