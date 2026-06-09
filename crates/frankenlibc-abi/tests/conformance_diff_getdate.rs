#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getdate oracle

//! `getdate_r` POSIX default-fill parity vs host glibc (bd-2g7oyh.288).
//!
//! fl's getdate previously returned the raw `strptime` result (year=0, etc.)
//! for any partial spec; glibc seeds unspecified fields from the current local
//! time. This gate drives BOTH engines in the same process (so they observe the
//! same "now") over a DATEMSK template set and compares the full broken-down
//! result + error code.
//!
//! Run under TZ=UTC: glibc derives tm_isdst (and the time-only rollover) from
//! *local* mktime, while fl's mktime is UTC-only (documented TZ scope, see the
//! mktime≡timegm note). Under UTC the two agree on every field.
//!
//! The well-defined cases below are pinned. Degenerate single-field specs
//! (month-only, day-only, day-of-year-only) produce glibc-idiosyncratic output
//! (e.g. "March" -> mday 3 / next year, "15" -> tm_year -1885) that frankenlibc
//! deliberately does NOT mirror — they are intentionally excluded.

use std::ffi::CString;

use frankenlibc_abi::unistd_abi as flu;

unsafe extern "C" {
    fn getdate_r(string: *const i8, result: *mut libc::tm) -> i32;
    fn setlocale(c: i32, l: *const i8) -> *mut i8;
    fn tzset();
}

fn fields(tm: &libc::tm) -> (i32, i32, i32, i32, i32, i32, i32, i32) {
    (
        tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, tm.tm_wday, tm.tm_yday,
    )
}

#[test]
fn getdate_default_fill_matches_glibc() {
    // Force UTC so glibc's local-mktime-derived fields line up with fl's
    // UTC-only mktime.
    unsafe {
        std::env::set_var("TZ", "UTC");
        tzset();
        let loc = CString::new("C").unwrap();
        setlocale(6 /* LC_ALL */, loc.as_ptr());
    }

    let dmsk = format!("/tmp/fl_getdate_gate_{}.txt", std::process::id());
    std::fs::write(
        &dmsk,
        "%m/%d/%Y\n%H:%M\n%H:%M:%S\n%Y-%m-%d %H:%M:%S\n%B %d\n%A\n%m/%d\n%Y-%m-%d\n%m/%d/%Y %H:%M\n",
    )
    .unwrap();
    unsafe { std::env::set_var("DATEMSK", &dmsk) };

    // Well-defined specs (full date / date+time / time-only / weekday-only /
    // date-no-year), plus error cases.
    let inputs = [
        "12/25/2030",          // full date, time defaults to current
        "2030-06-15 08:00:00", // full datetime
        "23:59:58",            // time-only, future today
        "08:15",               // time-only (h:m), sec -> 0
        "January 05",          // month+day, year -> current
        "07/04",               // month+day, year -> current
        "Monday",              // weekday-only -> next occurrence
        "Tuesday",             // weekday-only
        "Wednesday",
        "Sunday",
        "1999-12-31",          // full date (2-digit-ish year path via %Y)
        "12/25/2030 06:30",    // full date + time
        "02/30/2024",          // impossible date -> error 8
        "13/45/2024",          // bad month -> no template matches -> error 7
        "garbage zzz",         // no match -> 7
        "",                    // empty -> error
    ];

    for inp in inputs {
        let c = CString::new(inp).unwrap();
        let mut fl_tm: libc::tm = unsafe { std::mem::zeroed() };
        let mut gl_tm: libc::tm = unsafe { std::mem::zeroed() };
        let fl_rc = unsafe { flu::getdate_r(c.as_ptr(), (&mut fl_tm as *mut libc::tm).cast()) };
        let gl_rc = unsafe { getdate_r(c.as_ptr(), &mut gl_tm) };
        assert_eq!(fl_rc, gl_rc, "getdate_r({inp:?}) return code: fl={fl_rc} glibc={gl_rc}");
        if gl_rc == 0 {
            assert_eq!(
                fields(&fl_tm),
                fields(&gl_tm),
                "getdate_r({inp:?}) broken-down fields diverged\n  fl   ={:?}\n  glibc={:?}",
                fields(&fl_tm),
                fields(&gl_tm),
            );
            // tm_isdst must agree too (UTC -> 0 for both).
            assert_eq!(fl_tm.tm_isdst, gl_tm.tm_isdst, "getdate_r({inp:?}) tm_isdst");
        }
    }

    let _ = std::fs::remove_file(&dmsk);
}
