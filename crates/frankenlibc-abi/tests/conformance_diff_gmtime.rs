#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc gmtime/ctime_r oracle

//! Differential gate for gmtime / ctime_r (bd-xdp5e7) — these fundamental
//! time-conversion functions had no differential gate. gmtime is fully
//! deterministic (UTC, no timezone), so the broken-down struct tm fields are
//! compared field-for-field across an epoch range (0, dotcom era, 2038 wrap,
//! pre-1970 negative, year-9999), and ctime_r's 26-byte "Day Mon DD HH:MM:SS
//! YYYY\n" string is compared too. Each impl's gmtime returns its own static tm,
//! copied immediately. No mocks.

use std::ffi::{c_char, CStr};

unsafe extern "C" {
    fn gmtime(t: *const i64) -> *mut libc::tm;
    fn ctime_r(t: *const i64, buf: *mut c_char) -> *mut c_char;
}

type TmFields = (i32, i32, i32, i32, i32, i32, i32, i32, i32);
fn fields(t: &libc::tm) -> TmFields {
    (t.tm_sec, t.tm_min, t.tm_hour, t.tm_mday, t.tm_mon, t.tm_year, t.tm_wday, t.tm_yday, t.tm_isdst)
}

#[test]
fn gmtime_matches_glibc() {
    let epochs: [i64; 7] = [
        0,            // 1970-01-01 00:00:00
        1_000_000_000, // 2001-09-09 01:46:40
        1_700_000_000, // 2023-11-14
        -86_400,      // 1969-12-31 (negative)
        2_147_483_647, // 2038-01-19 (32-bit wrap)
        951_782_400,  // 2000-02-29 (leap day)
        253_402_300_799, // 9999-12-31 23:59:59
    ];
    for t in epochs {
        let g = unsafe {
            let p = gmtime(&t);
            assert!(!p.is_null(), "glibc gmtime({t}) null");
            fields(&*p)
        };
        let f = unsafe {
            let p = frankenlibc_abi::time_abi::gmtime(&t);
            assert!(!p.is_null(), "fl gmtime({t}) null");
            fields(&*p)
        };
        assert_eq!(f, g, "gmtime({t}) tm fields: fl={f:?} glibc={g:?}");
    }
}

#[test]
fn ctime_r_matches_glibc() {
    for t in [0i64, 1_000_000_000, 1_700_000_000, 2_147_483_647] {
        let mut gb = [0u8; 64];
        let mut fb = [0u8; 64];
        let g = unsafe {
            let p = ctime_r(&t, gb.as_mut_ptr() as *mut c_char);
            assert!(!p.is_null());
            CStr::from_ptr(gb.as_ptr() as *const c_char).to_string_lossy().into_owned()
        };
        let f = unsafe {
            let p = frankenlibc_abi::time_abi::ctime_r(&t, fb.as_mut_ptr() as *mut c_char);
            assert!(!p.is_null());
            CStr::from_ptr(fb.as_ptr() as *const c_char).to_string_lossy().into_owned()
        };
        assert_eq!(f, g, "ctime_r({t}): fl={f:?} glibc={g:?}");
    }
}
