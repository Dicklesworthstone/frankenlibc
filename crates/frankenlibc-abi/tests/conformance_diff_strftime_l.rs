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
        libc::tzset();
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
