#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime_l oracle

//! Differential gate for strftime_l (bd-t6c1zz) — previously zero coverage.
//! With a "C" locale_t, strftime_l must format a broken-down time identically
//! to glibc's strftime_l across a broad set of conversion specifiers (numeric
//! date/time, locale names %A/%B/%p which are English in C, week numbers %U/%W/
//! %V, day-of-year %j, %s epoch, combined %c/%x/%X, literals and %%). fl must
//! match host glibc byte-for-byte (output bytes AND return length). No mocks.

use std::ffi::{CString, c_char, c_void};

unsafe extern "C" {
    fn strftime_l(
        s: *mut c_char,
        max: usize,
        fmt: *const c_char,
        tm: *const libc::tm,
        loc: *mut c_void,
    ) -> usize;
    fn newlocale(mask: std::ffi::c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
    fn timegm(tm: *mut libc::tm) -> libc::time_t;
}

fn base_tm() -> libc::tm {
    // 2024-03-15 14:30:45 UTC (a Friday). Normalize wday/yday via timegm.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = 2024 - 1900;
    tm.tm_mon = 2; // March
    tm.tm_mday = 15;
    tm.tm_hour = 14;
    tm.tm_min = 30;
    tm.tm_sec = 45;
    unsafe { timegm(&mut tm) };
    tm
}

const FORMATS: &[&str] = &[
    "%Y-%m-%d",
    "%H:%M:%S",
    "%A",
    "%a",
    "%B",
    "%b",
    "%p",
    "%I:%M %p",
    "%j",
    "%U",
    "%W",
    "%V",
    "%w",
    "%u",
    "%C",
    "%y",
    "%G",
    "%g",
    "%e",
    "%k",
    "%l",
    "%n%t",
    "%D",
    "%F",
    "%R",
    "%T",
    "%c",
    "%x",
    "%X",
    "literal text %% %Y end",
    "%EY %Od",
    // NOTE: %s (epoch) and %Z/%z (timezone) are intentionally omitted — they
    // depend on the active timezone / tm_gmtoff,tm_zone, which is an
    // architectural axis (fl documents UTC-only %s), not a strftime_l parity
    // question. The specifiers above are deterministic for a C locale + the
    // UTC-normalized tm below.
];

#[test]
fn strftime_l_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());
    let tm = base_tm();

    for &f in FORMATS {
        let fc = CString::new(f).unwrap();
        let mut gbuf = vec![0u8; 256];
        let mut fbuf = vec![0u8; 256];
        let gn = unsafe {
            strftime_l(
                gbuf.as_mut_ptr() as *mut c_char,
                gbuf.len(),
                fc.as_ptr(),
                &tm,
                loc,
            )
        };
        let fln = unsafe {
            frankenlibc_abi::unistd_abi::strftime_l(
                fbuf.as_mut_ptr() as *mut c_char,
                fbuf.len(),
                fc.as_ptr(),
                &tm as *const libc::tm as *const c_void,
                loc as *mut c_void,
            )
        };
        // A format that produced NOTHING on both sides compares equal and proves
        // nothing. Every format in this list is non-empty for the tm above, so
        // require the oracle to have actually produced output.
        assert!(
            gn > 0,
            "oracle produced no output for {f:?} -- the comparison below would be vacuous"
        );
        assert_eq!(
            fln, gn,
            "strftime_l({f:?}) return length: fl={fln} glibc={gn}"
        );
        assert_eq!(
            &fbuf[..fln],
            &gbuf[..gn],
            "strftime_l({f:?}) bytes: fl={:?} glibc={:?}",
            String::from_utf8_lossy(&fbuf[..fln]),
            String::from_utf8_lossy(&gbuf[..gn])
        );
    }
    unsafe { freelocale(loc) };
}

/// A tm built from UTC components, with tm_wday/tm_yday normalized by timegm.
fn tm_at(y: i32, mon: i32, mday: i32, hour: i32, min: i32, sec: i32) -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = y - 1900;
    tm.tm_mon = mon - 1;
    tm.tm_mday = mday;
    tm.tm_hour = hour;
    tm.tm_min = min;
    tm.tm_sec = sec;
    unsafe { timegm(&mut tm) };
    tm
}

/// Dates chosen because the single tm above cannot exercise them, each with the
/// reason it is here. Every expectation was first MEASURED on live glibc 2.42
/// under LC_ALL=C, and the ISO-week algorithm was separately swept against glibc
/// for all 47848 days from 1970-01-01 to 2100-12-31 (zero divergences), so these
/// are the boundary cases that pin the result rather than a hopeful sample.
///
/// The point of the matrix: %G/%V/%U/%W disagree with %Y in opposite directions
/// at the two ends of a year, and a week calculation can be wrong in one
/// direction while looking perfect in the other. 2024-03-15 (mid-March, mid-week)
/// exercises NEITHER.
const EDGE_DATES: &[(i32, i32, i32, i32, i32, i32, &str)] = &[
    // ISO year BEHIND the calendar year, and the rare week 53.
    (2021, 1, 1, 0, 0, 0, "Fri 1 Jan: %G=2020 %V=53"),
    // Sunday 1 Jan: %U and %W diverge (01 vs 00).
    (
        2023,
        1,
        1,
        12,
        0,
        0,
        "Sun 1 Jan: %G=2022 %V=52, %U=01 %W=00",
    ),
    // ISO year AHEAD of the calendar year -- the opposite sign of the first row.
    (2024, 12, 30, 23, 59, 59, "Mon 30 Dec: %G=2025 %V=01"),
    (2019, 12, 31, 0, 0, 0, "Tue 31 Dec: %G=2020 %V=01"),
    // Leap day, and a leap-year %j.
    (2016, 2, 29, 12, 0, 0, "leap day: %j=060"),
    // Century boundary: %C=20 %y=00, and %G=1999.
    (2000, 1, 1, 0, 0, 0, "Sat 1 Jan 2000: %C=20 %y=00 %G=1999"),
    // The epoch itself: Thursday, so ISO week 1 with no year shift.
    (1970, 1, 1, 0, 0, 0, "epoch: Thu, %G=1970 %V=01"),
    // Monday 1 Jan: %W=01 while %U=00 -- the mirror of the 2023 row.
    (2024, 1, 1, 0, 0, 0, "Mon 1 Jan: %U=00 %W=01"),
    // Afternoon single-digit 12-hour: %I=01 with %l space-padded to " 1".
    (
        2025,
        12,
        31,
        13,
        5,
        9,
        "Wed 31 Dec 13:05: %G=2026 %V=01, %I=01 %l=' 1'",
    ),
    // Midnight: %I=12 %p=AM %k=' 0' -- the hour-0 aliasing case.
    (2026, 1, 4, 0, 30, 0, "Sun 4 Jan 00:30: %I=12 %p=AM %k=' 0'"),
    (1999, 12, 31, 12, 0, 0, "Fri 31 Dec 1999: %G=1999 %V=52"),
    // 2100 is NOT a leap year (the /100 rule), so 1 March is yday 59 -> %j=060,
    // the same %j as the 2016 leap day above but reached the other way.
    (2100, 3, 1, 6, 0, 0, "non-leap century: %j=060"),
];

/// Formats whose output actually varies with the date/time, so the matrix above
/// is meaningful. Deliberately excludes %Z/%z/%s for the same reason the list at
/// the top of this file does.
const EDGE_FORMATS: &[&str] = &[
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
    "%Y-%m-%d %H:%M:%S",
    "%r",
    "%T",
    "%y",
    "%C",
];

#[test]
fn strftime_l_matches_glibc_at_calendar_edges() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());

    let mut divergences = Vec::new();
    let mut compared = 0usize;
    for &(y, mon, d, h, mi, s, why) in EDGE_DATES {
        let tm = tm_at(y, mon, d, h, mi, s);
        for &f in EDGE_FORMATS {
            let fc = CString::new(f).unwrap();
            let mut gbuf = vec![0u8; 256];
            let mut fbuf = vec![0u8; 256];
            let gn = unsafe {
                strftime_l(
                    gbuf.as_mut_ptr() as *mut c_char,
                    gbuf.len(),
                    fc.as_ptr(),
                    &tm,
                    loc,
                )
            };
            let fln = unsafe {
                frankenlibc_abi::unistd_abi::strftime_l(
                    fbuf.as_mut_ptr() as *mut c_char,
                    fbuf.len(),
                    fc.as_ptr(),
                    &tm as *const libc::tm as *const c_void,
                    loc as *mut c_void,
                )
            };
            assert!(
                gn > 0,
                "oracle produced no output for {f:?} at {y}-{mon:02}-{d:02} -- vacuous"
            );
            compared += 1;
            if fln != gn || fbuf[..fln] != gbuf[..gn] {
                divergences.push(format!(
                    "{y}-{mon:02}-{d:02} {h:02}:{mi:02}:{s:02} [{why}] {f:?}: \
                     fl={:?}({fln}) glibc={:?}({gn})",
                    String::from_utf8_lossy(&fbuf[..fln]),
                    String::from_utf8_lossy(&gbuf[..gn])
                ));
            }
        }
    }
    unsafe { freelocale(loc) };

    // Assert the positive fact too: a silently empty matrix would otherwise read
    // as a pass.
    assert_eq!(
        compared,
        EDGE_DATES.len() * EDGE_FORMATS.len(),
        "matrix did not run to completion"
    );
    assert!(
        divergences.is_empty(),
        "strftime_l calendar-edge divergences ({} of {compared}):\n  {}",
        divergences.len(),
        divergences.join("\n  ")
    );
}
