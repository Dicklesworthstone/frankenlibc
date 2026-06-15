//! Differential gate for asctime/ctime range + out-of-range handling vs glibc.
//!
//! Two bugs this pins:
//!  1. The non-reentrant `asctime`/`ctime` wrongly returned NULL for years that
//!     overflow the 26-byte reentrant buffer (e.g. 10000). glibc's non-reentrant
//!     form uses a wider static buffer and succeeds, bounded only by `tm_year +
//!     1900` overflowing `int`. (`asctime_r`/`ctime_r` correctly still cap at 26
//!     and return NULL — also checked here.)
//!  2. An out-of-range `tm_wday`/`tm_mon` wrapped to a real name (rem_euclid)
//!     instead of glibc's literal `"???"`.
//!
//! fl is called via its Rust paths; glibc via dlsym on libc.so.6 (bypassing fl's
//! no_mangle interposition of the same symbols).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::time_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type AscFn = extern "C" fn(*const libc::tm) -> *mut c_char;
type AscRFn = extern "C" fn(*const libc::tm, *mut c_char) -> *mut c_char;

fn sym(h: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "missing libc symbol {name:?}");
    p
}

fn cstr_opt(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

fn mk(year: c_int, mon: c_int, mday: c_int, hour: c_int, min: c_int, sec: c_int, wday: c_int) -> libc::tm {
    let mut t: libc::tm = unsafe { core::mem::zeroed() };
    t.tm_year = year;
    t.tm_mon = mon;
    t.tm_mday = mday;
    t.tm_hour = hour;
    t.tm_min = min;
    t.tm_sec = sec;
    t.tm_wday = wday;
    t
}

#[test]
fn asctime_range_matches_glibc() {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let g_asctime: AscFn = unsafe { core::mem::transmute(sym(h, c"asctime")) };
    let g_asctime_r: AscRFn = unsafe { core::mem::transmute(sym(h, c"asctime_r")) };

    // (tm_year offset from 1900 already applied by caller via raw field)
    let cases = [
        ("normal 2025", mk(125, 0, 2, 3, 4, 5, 3)),
        ("year 10000", mk(10000 - 1900, 0, 2, 3, 4, 5, 3)),
        ("year 100000", mk(100000 - 1900, 0, 2, 3, 4, 5, 3)),
        ("wday=8 out of range", mk(125, 0, 2, 3, 4, 5, 8)),
        ("mon=13 out of range", mk(125, 13, 2, 3, 4, 5, 3)),
        ("wday=-1", mk(125, 0, 2, 3, 4, 5, -1)),
        ("year overflow tm_year=INT_MAX", mk(c_int::MAX, 0, 2, 3, 4, 5, 3)),
        ("year just-overflow", mk(c_int::MAX - 1900 + 1, 0, 2, 3, 4, 5, 3)),
        ("year max non-overflow", mk(c_int::MAX - 1900, 0, 2, 3, 4, 5, 3)),
    ];

    let mut div = Vec::new();
    for (name, tm) in cases {
        // non-reentrant asctime
        let fv = cstr_opt(unsafe { fl::asctime(&tm) });
        let gv = cstr_opt(g_asctime(&tm));
        if fv != gv {
            div.push(format!("asctime[{name}]: fl={fv:?} glibc={gv:?}"));
        }
        // reentrant asctime_r with a 26-byte buffer (must still cap)
        let mut fb = [0 as c_char; 26];
        let mut gb = [0 as c_char; 26];
        let fr = cstr_opt(unsafe { fl::asctime_r(&tm, fb.as_mut_ptr()) });
        let gr = cstr_opt(g_asctime_r(&tm, gb.as_mut_ptr()));
        if fr != gr {
            div.push(format!("asctime_r[{name}]: fl={fr:?} glibc={gr:?}"));
        }
    }
    assert!(div.is_empty(), "asctime divergences ({}):\n  {}", div.len(), div.join("\n  "));
}

#[test]
fn ctime_range_matches_glibc() {
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let g_ctime: extern "C" fn(*const i64) -> *mut c_char =
        unsafe { core::mem::transmute(sym(h, c"ctime")) };

    // ctime is UTC-only in fl (gates run under TZ=UTC); compare a handful of
    // epochs incl. far-future ones whose year exceeds 9999.
    let epochs: [i64; 6] = [
        0,
        1_700_000_000,
        253_402_300_799,    // 9999-12-31T23:59:59Z
        253_402_300_800,    // 10000-01-01T00:00:00Z (year 10000 — was NULL in fl)
        usize::MAX as i64 / 4,
        -1,
    ];
    // Ensure the env matches fl's UTC-only model so glibc ctime is also UTC.
    unsafe { std::env::set_var("TZ", "UTC") };
    unsafe extern "C" {
        fn tzset();
    }
    unsafe { tzset() };

    let mut div = Vec::new();
    for e in epochs {
        let fv = cstr_opt(unsafe { fl::ctime(&e) });
        let gv = cstr_opt(g_ctime(&e));
        if fv != gv {
            div.push(format!("ctime[{e}]: fl={fv:?} glibc={gv:?}"));
        }
    }
    assert!(div.is_empty(), "ctime divergences ({}):\n  {}", div.len(), div.join("\n  "));
}
