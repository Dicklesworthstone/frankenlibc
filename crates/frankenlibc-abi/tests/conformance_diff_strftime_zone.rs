#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime oracle

//! `strftime` `%Z` (timezone name) parity vs host glibc (bd-2g7oyh.303).
//!
//! glibc echoes the broken-down time's `tm_zone` when set, otherwise the
//! process timezone. fl previously hardcoded "GMT"; it now echoes `tm_zone`
//! and falls back to "UTC" (its only timezone). This gate runs under TZ=UTC —
//! where glibc's null-`tm_zone` fallback is "UTC" too, so the two agree — and
//! checks: (a) an explicitly set `tm_zone` is echoed; (b) a null `tm_zone`
//! falls back to "UTC"; (c) fl's own gmtime ("GMT") / localtime ("UTC") output
//! renders the same `%Z` as glibc's.
//!
//! The process-timezone fallback under a NON-UTC TZ is out of scope (fl is
//! UTC-only with no tz database).

use frankenlibc_abi::time_abi as fl;
use std::ffi::{CString, c_char};

unsafe extern "C" {
    fn strftime(s: *mut c_char, m: usize, f: *const c_char, tm: *const libc::tm) -> usize;
    fn gmtime_r(t: *const i64, tm: *mut libc::tm) -> *mut libc::tm;
    fn localtime_r(t: *const i64, tm: *mut libc::tm) -> *mut libc::tm;
    fn setlocale(c: i32, l: *const c_char) -> *mut c_char;
    fn tzset();
}

fn render(eng: u8, fmt: &str, tm: &libc::tm) -> String {
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0i8; 64];
    let n = if eng == 0 {
        unsafe { fl::strftime(buf.as_mut_ptr(), 64, cf.as_ptr(), tm) }
    } else {
        unsafe { strftime(buf.as_mut_ptr(), 64, cf.as_ptr(), tm) }
    };
    String::from_utf8_lossy(&buf[..n].iter().map(|&b| b as u8).collect::<Vec<_>>()).into_owned()
}

#[test]
fn strftime_zone_name_matches_glibc() {
    unsafe {
        std::env::set_var("TZ", "UTC");
        tzset();
        let loc = CString::new("C").unwrap();
        setlocale(6, loc.as_ptr());
    }

    let t = 1_718_450_000i64;
    let mut base: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { gmtime_r(&t, &mut base) };

    // (a) explicitly set tm_zone is echoed; (b) null falls back to "UTC".
    let zones = [c"GMT", c"UTC", c"PST", c"EST", c"CEST", c"AEST"];
    for z in zones {
        let mut tm = base;
        tm.tm_zone = z.as_ptr();
        for fmt in ["%Z", "%H:%M %Z", "%Z!"] {
            assert_eq!(
                render(0, fmt, &tm),
                render(1, fmt, &tm),
                "set zone {z:?} {fmt}"
            );
        }
    }
    let mut tm = base;
    tm.tm_zone = std::ptr::null();
    assert_eq!(
        render(0, "%Z", &tm),
        render(1, "%Z", &tm),
        "null zone -> UTC fallback"
    );

    // (c) fl's own gmtime / localtime output renders the same %Z as glibc's.
    let mut fl_g: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { fl::gmtime_r(&t, &mut fl_g) };
    let mut gl_g: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { gmtime_r(&t, &mut gl_g) };
    assert_eq!(render(0, "%Z", &fl_g), render(1, "%Z", &gl_g), "gmtime %Z");

    let mut fl_l: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { fl::localtime_r(&t, &mut fl_l) };
    let mut gl_l: libc::tm = unsafe { std::mem::zeroed() };
    unsafe { localtime_r(&t, &mut gl_l) };
    assert_eq!(
        render(0, "%Z", &fl_l),
        render(1, "%Z", &gl_l),
        "localtime %Z"
    );
}
