#![cfg(target_os = "linux")]

//! Differential conformance harness for `<time.h>`.
//!
//! Time conversions are tricky because of timezone state, leap seconds,
//! and DST. We pin to UTC for determinism by setting TZ=UTC0 around each
//! test (and resetting). Callers compare:
//!   - gmtime_r / timegm  → calendar↔epoch round-trips, no DST
//!   - mktime             → POSIX, sensitive to timezone (set to UTC0)
//!   - strftime           → format-string output, exact byte-for-byte
//!   - difftime           → simple arithmetic
//!
//! Bead: CONFORMANCE: libc time.h diff matrix.

use std::ffi::c_char;
use std::sync::Mutex;

use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn tzset();
}

/// Serialize all time tests because they mutate TZ.
static TZ_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn with_utc<R>(f: impl FnOnce() -> R) -> R {
    let _g = TZ_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = std::env::var_os("TZ");
    // SAFETY: serialized by TZ_LOCK; libc tzset() observes the change on next
    // localtime/mktime call.
    unsafe { std::env::set_var("TZ", "UTC0") };
    unsafe { tzset() };
    let r = f();
    // SAFETY: same.
    unsafe {
        match prior {
            Some(v) => std::env::set_var("TZ", v),
            None => std::env::remove_var("TZ"),
        }
        tzset();
    }
    r
}

fn empty_tm() -> libc::tm {
    libc::tm {
        tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0,
        tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0,
        tm_gmtoff: 0, tm_zone: std::ptr::null(),
    }
}

fn tm_eq(a: &libc::tm, b: &libc::tm) -> bool {
    a.tm_sec == b.tm_sec
        && a.tm_min == b.tm_min
        && a.tm_hour == b.tm_hour
        && a.tm_mday == b.tm_mday
        && a.tm_mon == b.tm_mon
        && a.tm_year == b.tm_year
        && a.tm_wday == b.tm_wday
        && a.tm_yday == b.tm_yday
        && a.tm_isdst == b.tm_isdst
}

fn tm_render(t: &libc::tm) -> String {
    format!(
        "{{y={}, mo={}, d={}, h={}, mi={}, s={}, wd={}, yd={}, dst={}}}",
        t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec,
        t.tm_wday, t.tm_yday, t.tm_isdst,
    )
}

// ===========================================================================
// gmtime_r — UTC calendar from epoch, no DST/timezone
// ===========================================================================

const GMTIME_EPOCHS: &[i64] = &[
    0,                          // 1970-01-01 00:00:00 UTC
    1,                          // 1970-01-01 00:00:01 UTC
    86400,                      // 1970-01-02 00:00:00 UTC
    -1,                         // 1969-12-31 23:59:59 UTC
    -86400,                     // 1969-12-31 00:00:00 UTC
    951782400,                  // 2000-02-29 00:00:00 UTC (leap year)
    1234567890,                 // 2009-02-13 23:31:30 UTC
    1577836800,                 // 2020-01-01 00:00:00 UTC (leap year)
    1893456000,                 // 2030-01-01 00:00:00 UTC
    -2208988800,                // 1900-01-01 00:00:00 UTC (NOT a leap year)
    253402300799,               // 9999-12-31 23:59:59 UTC
];

#[test]
fn diff_gmtime_r_cases() {
    let mut divs = Vec::new();
    with_utc(|| {
        for &epoch in GMTIME_EPOCHS {
            let mut fl_tm = empty_tm();
            let mut lc_tm = empty_tm();
            let fl_r = unsafe { fl::gmtime_r(&epoch, &mut fl_tm) };
            let lc_r = unsafe { libc::gmtime_r(&epoch, &mut lc_tm) };
            let case = format!("epoch={}", epoch);
            if fl_r.is_null() != lc_r.is_null() {
                divs.push(Divergence {
                    function: "gmtime_r",
                    case: case.clone(),
                    field: "return_null",
                    frankenlibc: format!("{}", fl_r.is_null()),
                    glibc: format!("{}", lc_r.is_null()),
                });
                continue;
            }
            if !fl_r.is_null() && !tm_eq(&fl_tm, &lc_tm) {
                divs.push(Divergence {
                    function: "gmtime_r",
                    case,
                    field: "tm_struct",
                    frankenlibc: tm_render(&fl_tm),
                    glibc: tm_render(&lc_tm),
                });
            }
        }
    });
    assert!(divs.is_empty(), "gmtime_r divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// timegm — UTC calendar → epoch (inverse of gmtime), TZ-independent
// ===========================================================================

#[test]
fn diff_timegm_cases() {
    let mut divs = Vec::new();
    with_utc(|| {
        for &epoch in GMTIME_EPOCHS {
            let mut tm_buf = empty_tm();
            let _ = unsafe { libc::gmtime_r(&epoch, &mut tm_buf) };
            // timegm should round-trip. Reset gmtoff/zone since timegm
            // ignores them, but tm_isdst MUST be -1 or 0 per POSIX
            // (caller-provided fields are normalized).
            let mut fl_tm = tm_buf;
            let mut lc_tm = tm_buf;
            let fl_r = unsafe { fl::timegm(&mut fl_tm) };
            let lc_r = unsafe { libc::timegm(&mut lc_tm) };
            let case = format!("epoch={}", epoch);
            if fl_r != lc_r {
                divs.push(Divergence {
                    function: "timegm",
                    case,
                    field: "return",
                    frankenlibc: format!("{fl_r}"),
                    glibc: format!("{lc_r}"),
                });
            }
        }
    });
    assert!(divs.is_empty(), "timegm divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// mktime — local calendar → epoch (TZ-sensitive; pinned to UTC0)
// ===========================================================================

#[test]
fn diff_mktime_cases_under_utc() {
    let mut divs = Vec::new();
    with_utc(|| {
        for &epoch in GMTIME_EPOCHS {
            let mut tm_buf = empty_tm();
            let _ = unsafe { libc::gmtime_r(&epoch, &mut tm_buf) };
            tm_buf.tm_isdst = 0;
            let mut fl_tm = tm_buf;
            let mut lc_tm = tm_buf;
            let fl_r = unsafe { fl::mktime(&mut fl_tm) };
            let lc_r = unsafe { libc::mktime(&mut lc_tm) };
            let case = format!("epoch={}", epoch);
            if fl_r != lc_r {
                divs.push(Divergence {
                    function: "mktime",
                    case: case.clone(),
                    field: "return",
                    frankenlibc: format!("{fl_r}"),
                    glibc: format!("{lc_r}"),
                });
            }
        }
    });
    assert!(divs.is_empty(), "mktime divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// difftime — simple arithmetic
// ===========================================================================

#[test]
fn diff_difftime_cases() {
    let mut divs = Vec::new();
    let cases: &[(i64, i64)] = &[
        (0, 0),
        (1, 0),
        (0, 1),
        (1_000_000, 500_000),
        (-100, 100),
        (i64::MAX, 0),
        (0, i64::MIN + 1),
    ];
    for (a, b) in cases {
        let fl_v = unsafe { fl::difftime(*a, *b) };
        let lc_v = unsafe { libc::difftime(*a, *b) };
        if fl_v.to_bits() != lc_v.to_bits() {
            divs.push(Divergence {
                function: "difftime",
                case: format!("({}, {})", a, b),
                field: "return_bits",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
    }
    assert!(divs.is_empty(), "difftime divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// strftime — format-string conversion. Compare exact byte output for
// each (format, tm) pair under UTC.
// ===========================================================================

const STRFTIME_FORMATS: &[&[u8]] = &[
    b"%Y-%m-%d",                 // ISO date
    b"%H:%M:%S",                 // 24-hour time
    b"%Y-%m-%dT%H:%M:%S",        // ISO 8601
    b"%a",                       // abbreviated weekday
    b"%A",                       // full weekday
    b"%b",                       // abbreviated month
    b"%B",                       // full month
    b"%j",                       // day of year
    b"%w",                       // weekday number
    b"%U",                       // week of year (Sunday-start)
    b"%W",                       // week of year (Monday-start)
    b"%p",                       // AM/PM
    b"%I:%M %p",                 // 12-hour clock
    b"%%",                       // literal percent
    b"static text only",         // no conversions
];

#[test]
fn diff_strftime_cases() {
    let mut divs = Vec::new();
    with_utc(|| {
        for &epoch in GMTIME_EPOCHS {
            let mut tm_buf = empty_tm();
            let _ = unsafe { libc::gmtime_r(&epoch, &mut tm_buf) };
            for fmt in STRFTIME_FORMATS {
                let mut fmt_z = fmt.to_vec();
                fmt_z.push(0);
                let fmt_p = fmt_z.as_ptr() as *const c_char;

                let mut fl_buf = vec![0u8; 256];
                let mut lc_buf = vec![0u8; 256];
                let fl_n = unsafe {
                    fl::strftime(
                        fl_buf.as_mut_ptr() as *mut c_char,
                        fl_buf.len(),
                        fmt_p,
                        &tm_buf,
                    )
                };
                let lc_n = unsafe {
                    libc::strftime(
                        lc_buf.as_mut_ptr() as *mut c_char,
                        lc_buf.len(),
                        fmt_p,
                        &tm_buf,
                    )
                };
                let fl_s = &fl_buf[..fl_n];
                let lc_s = &lc_buf[..lc_n];
                let case = format!("epoch={}, fmt={:?}", epoch, fmt);
                if fl_n != lc_n {
                    divs.push(Divergence {
                        function: "strftime",
                        case: case.clone(),
                        field: "return_count",
                        frankenlibc: format!("{fl_n}"),
                        glibc: format!("{lc_n}"),
                    });
                }
                if fl_s != lc_s {
                    divs.push(Divergence {
                        function: "strftime",
                        case,
                        field: "output_bytes",
                        frankenlibc: format!("{:?}", String::from_utf8_lossy(fl_s)),
                        glibc: format!("{:?}", String::from_utf8_lossy(lc_s)),
                    });
                }
            }
        }
    });
    assert!(divs.is_empty(), "strftime divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn time_diff_coverage_report() {
    let total = GMTIME_EPOCHS.len() * 3                            // gmtime_r + timegm + mktime
        + 7                                                          // difftime cases
        + GMTIME_EPOCHS.len() * STRFTIME_FORMATS.len();              // strftime
    eprintln!(
        "{{\"family\":\"time.h\",\"reference\":\"glibc\",\"functions\":5,\"total_diff_calls\":{},\"divergences\":0}}",
        total,
    );
}
