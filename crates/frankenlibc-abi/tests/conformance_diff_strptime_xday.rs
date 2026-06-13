#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strptime oracle

//! `strptime` end-of-parse tm_wday / tm_yday parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc fills tm_wday and tm_yday from the resolved calendar date whenever a
//! date was established — a plain "%Y-%m-%d", a partial "%Y-%m"/"%d", "%j", or a
//! "%U"/"%W"+weekday derivation — keeping an explicitly parsed weekday (%a/%A/
//! %w/%u) or %j. fl previously left both fields untouched. This gate drives both
//! engines and compares the full broken-down date + match success.
//!
//! Excluded by design (glibc-idiosyncratic, frankenlibc deliberately diverges):
//!   * week 0 (days before the year's first Sunday/Monday): glibc reads its
//!     internal month table out of bounds (e.g. tm_mday = -370); fl stays sane
//!     (mon 0, small negative mday).
//!   * out-of-range %j (e.g. 400): glibc accepts and wraps; fl rejects.
//!   * ISO %V/%G are parsed but never derive the date in either engine.

use frankenlibc_abi::time_abi as flt;
use std::ffi::CString;

unsafe extern "C" {
    fn strptime(s: *const i8, fmt: *const i8, tm: *mut libc::tm) -> *mut i8;
    fn setlocale(c: i32, l: *const i8) -> *mut i8;
}

// (matched, mon, mday, year, yday, wday). Both engines start from a zero-init
// tm (what real callers pass); glibc reads pre-set fields, so a sentinel fill
// would make the two engines diverge artificially.
fn run(eng: u8, inp: &str, fmt: &str) -> (bool, i32, i32, i32, i32, i32) {
    let s = CString::new(inp).unwrap();
    let f = CString::new(fmt).unwrap();
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let r = if eng == 0 {
        unsafe { flt::strptime(s.as_ptr(), f.as_ptr(), &mut tm) }
    } else {
        unsafe { strptime(s.as_ptr(), f.as_ptr(), &mut tm) }
    };
    (
        !r.is_null(),
        tm.tm_mon,
        tm.tm_mday,
        tm.tm_year,
        tm.tm_yday,
        tm.tm_wday,
    )
}

fn check(inp: &str, fmt: &str) {
    let a = run(0, inp, fmt);
    let b = run(1, inp, fmt);
    assert_eq!(
        a, b,
        "strptime({inp:?}, {fmt:?}) diverged: fl={a:?} glibc={b:?}"
    );
}

#[test]
fn strptime_xday_fill_matches_glibc() {
    unsafe {
        let l = CString::new("C").unwrap();
        setlocale(6, l.as_ptr());
    }

    // Plain / partial explicit dates across a wide span (wday + yday filled).
    let years = [1970, 1999, 2000, 2001, 2004, 2020, 2023, 2024, 2025, 2100];
    for y in years {
        for (mo, d) in [
            (1, 1),
            (2, 28),
            (2, 29),
            (3, 1),
            (6, 15),
            (12, 31),
            (10, 24),
        ] {
            check(&format!("{y}-{mo:02}-{d:02}"), "%Y-%m-%d");
            check(&format!("{mo:02}/{d:02}/{y}"), "%m/%d/%Y");
        }
        check(&format!("{y}-06"), "%Y-%m"); // mday 0 -> glibc treats as last day of prior month
        check(&format!("{y}-01"), "%Y-%m");
    }
    // Day-only / month-only with defaults.
    for d in [1, 15, 28, 31] {
        check(&format!("{d}"), "%d");
    }

    // %j day-of-year (wday filled; yday kept).
    for y in [1999, 2000, 2004, 2023, 2024] {
        for j in [1, 31, 32, 59, 60, 100, 200, 365, 366] {
            check(&format!("{y} {j}"), "%Y %j");
        }
    }

    // %U / %W week + weekday derivation (yday filled; mon/mday derived),
    // weeks 1..=53 only (week 0 is the degenerate excluded case).
    for y in [1999, 2000, 2001, 2004, 2020, 2021, 2023, 2024] {
        for wk in [1, 2, 26, 52, 53] {
            for wd in 0..7 {
                check(&format!("{y} {wk} {wd}"), "%Y %U %w");
                check(&format!("{y} {wk} {wd}"), "%Y %W %w");
            }
            for name in ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] {
                check(&format!("{y} {wk} {name}"), "%Y %U %a");
                check(&format!("{y} {wk} {name}"), "%Y %W %a");
            }
        }
    }

    // ISO %V/%G + %u: the ISO week is never used to derive mon/mday in either
    // engine. %Y still triggers the wday/yday fill from the (zero) mon/mday, so
    // "%Y %V %u" yields yday -1 in BOTH; "%G %V %u" leaves it 0 in both (%G is
    // consumed without setting the year). The differential pins that agreement.
    for y in [1999, 2020, 2024, 2026] {
        for wk in [1, 26, 53] {
            for u in 1..=7 {
                check(&format!("{y} {wk} {u}"), "%Y %V %u");
                check(&format!("{y} {wk} {u}"), "%G %V %u");
            }
        }
    }
}
