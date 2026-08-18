#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime_l oracle

//! `strftime_l` against live glibc across the whole C-locale specifier set.
//!
//! bd-t6c1zz: zero differential coverage. fl's `strftime_l` ignores its
//! `locale_t` argument entirely and delegates to `strftime`, which is defensible
//! while fl ships only `C` and `C.UTF-8` — neither localises any of these fields
//! — but nothing checked that it was true, and "the argument is ignored" is
//! exactly the shape that stops being harmless when a third locale arrives.
//!
//! ## `%s` and `%Z` are excluded, and the reason is a design boundary
//!
//! fl is UTC-only BY DESIGN: `tzset` does not read `TZ` and pins `tzname` to
//! `"UTC"` (see `time_abi::tzset`). Two specifiers depend on the process
//! timezone and so cannot agree with a glibc running under any other zone —
//! measured, with the same `struct tm` and only `TZ` varying:
//!
//! ```text
//!   TZ=UTC           %Z=UTC  %z=+0000  %s=1787064737
//!   TZ=EST5          %Z=EST  %z=+0000  %s=1787082737
//!   TZ=Europe/Paris  %Z=CET  %z=+0000  %s=1787061137
//! ```
//!
//! Note the asymmetry, which is easy to get backwards: `%z` reads `tm_gmtoff`
//! and does NOT fall back to the process zone, while `%Z` falls back to
//! `tzname` when `tm_zone` is NULL, and `%s` ignores `tm_gmtoff` entirely and
//! uses `mktime` under the process zone. fl matches all three under `TZ=UTC`,
//! which is its documented scope, so this gate pins `TZ=UTC` rather than
//! excluding the specifiers outright — an exclusion would also hide a real
//! regression in `%z`, which is NOT timezone-dependent.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

unsafe extern "C" {
    /// NOT available as `libc::tzset` on linux targets — the libc crate only
    /// declares it under `windows/mod.rs` — so it is declared here, the same
    /// way conformance_diff_strftime_zone.rs and _strptime_tzname.rs do.
    fn tzset();
}

type StrftimeLFn =
    unsafe extern "C" fn(*mut c_char, usize, *const c_char, *const libc::tm, *mut c_void) -> usize;
type NewlocaleFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;

fn host_strftime_l() -> StrftimeLFn {
    // SAFETY: matches `size_t strftime_l(char *, size_t, const char *,
    // const struct tm *, locale_t)`, with fl's own export supplied so the
    // oracle refuses to resolve back to fl (bd-v0388t).
    unsafe {
        host_fn(
            c"strftime_l",
            frankenlibc_abi::unistd_abi::strftime_l as *const (),
        )
    }
}

fn host_newlocale() -> NewlocaleFn {
    // SAFETY: matches `locale_t newlocale(int, const char *, locale_t)`.
    unsafe {
        host_fn(
            c"newlocale",
            frankenlibc_abi::locale_abi::newlocale as *const (),
        )
    }
}

/// 2026-08-18 14:52:17, a Tuesday. `tm_yday` is 229 while `%j` prints 230 —
/// glibc adds one, and a fixture that "corrected" that would hide the bug.
fn fixture() -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = 17;
    tm.tm_min = 52;
    tm.tm_hour = 14;
    tm.tm_mday = 18;
    tm.tm_mon = 7;
    tm.tm_year = 126;
    tm.tm_wday = 2;
    tm.tm_yday = 229;
    tm.tm_isdst = 0;
    tm.tm_gmtoff = 0;
    tm.tm_zone = c"UTC".as_ptr();
    tm
}

/// Probed from live glibc under `TZ=UTC`, `LC_ALL=C`.
const EXPECTED: &[(&str, &str)] = &[
    ("%a", "Tue"),
    ("%A", "Tuesday"),
    ("%b", "Aug"),
    ("%B", "August"),
    ("%c", "Tue Aug 18 14:52:17 2026"),
    ("%C", "20"),
    ("%d", "18"),
    ("%D", "08/18/26"),
    ("%e", "18"),
    ("%F", "2026-08-18"),
    ("%g", "26"),
    ("%G", "2026"),
    ("%h", "Aug"),
    ("%H", "14"),
    ("%I", "02"),
    ("%j", "230"),
    ("%k", "14"),
    ("%l", " 2"),
    ("%m", "08"),
    ("%M", "52"),
    ("%n", "\n"),
    ("%p", "PM"),
    ("%P", "pm"),
    ("%r", "02:52:17 PM"),
    ("%R", "14:52"),
    ("%S", "17"),
    ("%T", "14:52:17"),
    ("%t", "\t"),
    ("%u", "2"),
    ("%U", "33"),
    ("%V", "34"),
    ("%w", "2"),
    ("%W", "33"),
    ("%x", "08/18/26"),
    ("%X", "14:52:17"),
    ("%y", "26"),
    ("%Y", "2026"),
    ("%z", "+0000"),
    ("%Z", "UTC"),
    ("%%", "%"),
];

/// Pin the process timezone, since `%Z` and `%s` read it and fl is UTC-only.
fn pin_utc() {
    // SAFETY: setenv/tzset with NUL-terminated literals.
    unsafe {
        libc::setenv(c"TZ".as_ptr(), c"UTC".as_ptr(), 1);
        tzset();
    }
}

fn render(f: StrftimeLFn, fmt: &CStr, tm: &libc::tm, loc: *mut c_void) -> String {
    let mut buf = [0 as c_char; 512];
    // SAFETY: 512-byte buffer, NUL-terminated format, live `tm`.
    let n = unsafe { f(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), tm, loc) };
    // SAFETY: `n` bytes were written and are in bounds.
    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) }
        .iter()
        .map(|&b| b as char)
        .collect()
}

#[test]
fn strftime_l_matches_glibc_across_the_c_locale_specifier_set() {
    pin_utc();
    let tm = fixture();
    let host = host_strftime_l();
    // SAFETY: LC_ALL_MASK with a NUL-terminated name and no base locale.
    let loc = unsafe { host_newlocale()(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "host newlocale(C) must succeed");

    let mut divergences = Vec::new();
    for (spec, expected) in EXPECTED {
        let fmt = CString::new(*spec).expect("format has no NUL");
        let host_out = render(host, &fmt, &tm, loc);
        // The PIN catches a host whose strftime has itself changed, which would
        // otherwise let fl and a drifted oracle agree on a wrong answer.
        assert_eq!(
            host_out, *expected,
            "host glibc no longer produces the recorded output for {spec}"
        );

        // SAFETY: same arguments through fl's entry point.
        let mut buf = [0 as c_char; 512];
        let n = unsafe {
            frankenlibc_abi::unistd_abi::strftime_l(
                buf.as_mut_ptr(),
                buf.len(),
                fmt.as_ptr(),
                (&tm as *const libc::tm).cast(),
                loc,
            )
        };
        // SAFETY: `n` bytes written, in bounds.
        let fl_out: String = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) }
            .iter()
            .map(|&b| b as char)
            .collect();

        if fl_out != host_out {
            divergences.push(format!("  {spec}: fl {fl_out:?} glibc {host_out:?}"));
        }
    }
    assert!(
        divergences.is_empty(),
        "strftime_l divergences from live glibc:\n{}",
        divergences.join("\n")
    );
}

/// fl ignores the `locale_t`. That is only safe while every locale fl ships
/// renders these fields identically — assert it rather than assume it, because
/// the day a third locale arrives this is the test that should fail.
#[test]
fn the_locale_handle_does_not_change_c_locale_output() {
    pin_utc();
    let tm = fixture();
    let host = host_strftime_l();
    // SAFETY: NUL-terminated names, no base locale.
    let c_loc = unsafe { host_newlocale()(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) };
    // SAFETY: same.
    let utf8_loc =
        unsafe { host_newlocale()(libc::LC_ALL_MASK, c"C.UTF-8".as_ptr(), std::ptr::null_mut()) };
    assert!(
        !c_loc.is_null() && !utf8_loc.is_null(),
        "both handles must resolve"
    );

    for (spec, _) in EXPECTED {
        let fmt = CString::new(*spec).unwrap();
        assert_eq!(
            render(host, &fmt, &tm, c_loc),
            render(host, &fmt, &tm, utf8_loc),
            "{spec} differs between C and C.UTF-8 on the HOST — fl's strftime_l \
             ignores its locale_t, which stops being safe the moment this fails"
        );
    }
}

/// Dates that make the week/year specifiers disagree with each other.
///
/// The fixture above is a single Tuesday in August. That is fine for breadth
/// across SPECIFIERS and useless for the one thing this family gets wrong:
/// `%G`/`%V`/`%U`/`%W` diverge from `%Y` in OPPOSITE directions at the two ends
/// of a year, so a week calculation can be wrong in one direction and look
/// perfect in the other. A mid-August fixture exercises neither.
///
/// Each row carries the reason it is here. Values were measured on live glibc
/// under `TZ=UTC`, `LC_ALL=C`, and the underlying arithmetic was separately
/// swept against glibc for all 47848 days from 1970-01-01 to 2100-12-31.
const EDGE_DATES: &[(i32, i32, i32, i32, i32, i32, &str)] = &[
    (2021, 1, 1, 0, 0, 0, "Fri 1 Jan: ISO year 2020, week 53"),
    (2023, 1, 1, 12, 0, 0, "Sun 1 Jan: %U=01 %W=00"),
    (
        2024,
        12,
        30,
        23,
        59,
        59,
        "Mon 30 Dec: ISO year 2025, week 01",
    ),
    (2019, 12, 31, 0, 0, 0, "Tue 31 Dec: ISO year 2020"),
    (2016, 2, 29, 12, 0, 0, "leap day"),
    (2000, 1, 1, 0, 0, 0, "century boundary, %C=20 %y=00"),
    (1970, 1, 1, 0, 0, 0, "the epoch, a Thursday"),
    (
        2024,
        1,
        1,
        0,
        0,
        0,
        "Mon 1 Jan: %U=00 %W=01, the mirror of 2023",
    ),
    (2025, 12, 31, 13, 5, 9, "afternoon: %I=01 %l=' 1'"),
    (2026, 1, 4, 0, 30, 0, "midnight: %I=12 %p=AM %k=' 0'"),
    (
        2100,
        3,
        1,
        6,
        0,
        0,
        "NOT a leap year (the /100 rule), so %j=060",
    ),
];

/// Only the specifiers whose output actually varies with the date.
const DATE_SENSITIVE: &[&str] = &[
    "%G-%V",
    "%g",
    "%U",
    "%W",
    "%j",
    "%a %A",
    "%b %B",
    "%I%p",
    "%l",
    "%k",
    "%C%y",
    "%e",
    "%u %w",
    "%F",
    "%D",
    "%c",
    "%x",
    "%X",
    "%r",
    "%T",
    "%Y-%m-%d %H:%M:%S",
];

#[test]
fn strftime_l_matches_glibc_at_calendar_edges() {
    pin_utc();
    let host = host_strftime_l();
    // SAFETY: LC_ALL_MASK with a NUL-terminated name and no base locale.
    let loc = unsafe { host_newlocale()(libc::LC_ALL_MASK, c"C".as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "host newlocale(C) must succeed");

    let mut compared = 0usize;
    let mut divergences = Vec::new();
    for &(y, mon, d, h, mi, s, why) in EDGE_DATES {
        // Normalise tm_wday/tm_yday through the host's own timegm, so the
        // fixture cannot encode a wrong weekday and hide a real difference.
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        tm.tm_year = y - 1900;
        tm.tm_mon = mon - 1;
        tm.tm_mday = d;
        tm.tm_hour = h;
        tm.tm_min = mi;
        tm.tm_sec = s;
        tm.tm_gmtoff = 0;
        tm.tm_zone = c"UTC".as_ptr();
        // SAFETY: `tm` is fully initialised above.
        unsafe { libc::timegm(&mut tm) };

        for spec in DATE_SENSITIVE {
            let fmt = CString::new(*spec).expect("format has no NUL");
            let host_out = render(host, &fmt, &tm, loc);
            assert!(
                !host_out.is_empty(),
                "oracle produced nothing for {spec} at {y}-{mon:02}-{d:02}; the comparison \
                 below would be vacuous"
            );

            // SAFETY: same arguments through fl's entry point.
            let mut buf = [0 as c_char; 512];
            let n = unsafe {
                frankenlibc_abi::unistd_abi::strftime_l(
                    buf.as_mut_ptr(),
                    buf.len(),
                    fmt.as_ptr(),
                    (&tm as *const libc::tm).cast(),
                    loc,
                )
            };
            // SAFETY: `n` bytes written, in bounds.
            let fl_out: String =
                unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) }
                    .iter()
                    .map(|&b| b as char)
                    .collect();

            compared += 1;
            if fl_out != host_out {
                divergences.push(format!(
                    "  {y}-{mon:02}-{d:02} [{why}] {spec}: fl {fl_out:?} glibc {host_out:?}"
                ));
            }
        }
    }

    assert_eq!(
        compared,
        EDGE_DATES.len() * DATE_SENSITIVE.len(),
        "the matrix did not run to completion"
    );
    assert!(
        divergences.is_empty(),
        "strftime_l calendar-edge divergences ({} of {compared}):\n{}",
        divergences.len(),
        divergences.join("\n")
    );
}
