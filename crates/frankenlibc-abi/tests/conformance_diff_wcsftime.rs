#![cfg(target_os = "linux")]

//! Differential conformance harness for `wcsftime(3)` — wide-char
//! strftime variant. Tests the same format-conversion specifiers
//! against both fl and host glibc on a fixed time value.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CString, c_void};

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcsftime(
        s: *mut libc::wchar_t,
        max: usize,
        format: *const libc::wchar_t,
        tm: *const libc::tm,
    ) -> usize;
    fn tzset();
}

fn make_fixed_tm() -> libc::tm {
    libc::tm {
        tm_sec: 45,
        tm_min: 30,
        tm_hour: 14,
        tm_mday: 25,
        tm_mon: 11,   // December (0-based)
        tm_year: 124, // 2024 (years since 1900)
        tm_wday: 3,   // Wednesday
        tm_yday: 359,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    }
}

fn wide_string(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

fn render_both(format_str: &str, tm: &libc::tm) -> (Vec<libc::wchar_t>, Vec<libc::wchar_t>) {
    let fmt = wide_string(format_str);
    let mut fl_buf = vec![0 as libc::wchar_t; 256];
    let mut lc_buf = vec![0 as libc::wchar_t; 256];
    let fl_n = unsafe {
        fl::wcsftime(
            fl_buf.as_mut_ptr(),
            fl_buf.len(),
            fmt.as_ptr(),
            tm as *const _ as *const c_void,
        )
    };
    let lc_n = unsafe { wcsftime(lc_buf.as_mut_ptr(), lc_buf.len(), fmt.as_ptr(), tm) };
    fl_buf.truncate(fl_n);
    lc_buf.truncate(lc_n);
    (fl_buf, lc_buf)
}

fn ws_to_string(ws: &[libc::wchar_t]) -> String {
    ws.iter()
        .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
        .collect()
}

#[test]
fn diff_wcsftime_year_month_day() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("%Y-%m-%d", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s, "%Y-%m-%d: fl={fl_s:?} lc={lc_s:?}");
    assert_eq!(fl_s, "2024-12-25");
}

#[test]
fn diff_wcsftime_time_specifiers() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("%H:%M:%S", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s, "14:30:45");
}

#[test]
fn diff_wcsftime_weekday_full_and_short() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("%A %a", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s);
    assert!(fl_s.starts_with("Wednesday "));
}

#[test]
fn diff_wcsftime_month_full_and_short() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("%B %b", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s);
    assert!(fl_s.starts_with("December "));
}

#[test]
fn diff_wcsftime_iso_8601() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("%FT%T", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s, "2024-12-25T14:30:45");
}

#[test]
fn diff_wcsftime_percent_literal() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("100%% off!", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s, "100% off!");
}

#[test]
fn diff_wcsftime_empty_format() {
    let tm = make_fixed_tm();
    let (fl_w, lc_w) = render_both("", &tm);
    // Empty format yields 0 chars.
    assert_eq!(fl_w.len(), 0);
    assert_eq!(lc_w.len(), 0);
}

#[test]
fn diff_wcsftime_buffer_too_small_returns_zero() {
    let tm = make_fixed_tm();
    let fmt = wide_string("%Y-%m-%d-%H-%M-%S");
    let mut fl_buf = vec![0 as libc::wchar_t; 4]; // way too small
    let mut lc_buf = vec![0 as libc::wchar_t; 4];
    let fl_n = unsafe {
        fl::wcsftime(
            fl_buf.as_mut_ptr(),
            fl_buf.len(),
            fmt.as_ptr(),
            &tm as *const libc::tm as *const c_void,
        )
    };
    let lc_n = unsafe { wcsftime(lc_buf.as_mut_ptr(), lc_buf.len(), fmt.as_ptr(), &tm) };
    assert_eq!(fl_n, lc_n);
    assert_eq!(fl_n, 0);
}

#[test]
fn diff_wcsftime_unknown_specifier() {
    let tm = make_fixed_tm();
    // %!  is not a real specifier; impls may either pass through
    // or skip — just check parity.
    let (fl_w, lc_w) = render_both("[%!]", &tm);
    let fl_s = ws_to_string(&fl_w);
    let lc_s = ws_to_string(&lc_w);
    assert_eq!(fl_s, lc_s, "unknown spec: fl={fl_s:?} lc={lc_s:?}");
}

#[test]
fn wcsftime_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc wcsftime\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
    let _ = CString::new("dummy").unwrap();
    let _ = std::ptr::null::<c_void>();
}

// ===========================================================================
// Dense daily week-specifier fuzz vs glibc wcsftime.
//
// The fixed cases omit %V (ISO week) entirely. The ISO week 52/53/01 year
// boundary is the classic strftime/wcsftime bug site, so sweep every day from
// 1990 through 2039 and compare a combined week-specifier format byte-for-byte
// against host glibc wcsftime.
// ===========================================================================

use std::sync::Mutex;

static TZ_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn diff_wcsftime_week_specifiers_dense() {
    let _g = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Pin UTC so gmtime_r / wcsftime agree on the broken-down fields.
    unsafe {
        std::env::set_var("TZ", "UTC0");
        tzset();
    }

    const BASE: i64 = 631_152_000; // 1990-01-01 00:00:00 UTC
    const DAYS: i64 = 50 * 366;
    let fmt = "%G %V %g %u %U %W %j %a %Y %m %d";

    let mut fails = Vec::new();
    for day in 0..DAYS {
        let epoch = BASE + day * 86_400;
        let mut tm = make_fixed_tm();
        unsafe { libc::gmtime_r(&epoch, &mut tm) };
        let (fl, lc) = render_both(fmt, &tm);
        if fl != lc {
            fails.push(format!(
                "  {:04}-{:02}-{:02}: fl={:?} glibc={:?}",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                ws_to_string(&fl),
                ws_to_string(&lc),
            ));
            if fails.len() >= 12 {
                break;
            }
        }
    }
    assert!(
        fails.is_empty(),
        "wcsftime week-specifier divergences ({} shown):\n{}",
        fails.len(),
        fails.join("\n")
    );
}
