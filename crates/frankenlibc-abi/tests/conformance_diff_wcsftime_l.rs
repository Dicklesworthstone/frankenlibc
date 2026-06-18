#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsftime_l oracle

//! Differential gate for wcsftime_l (bd-jksmc2) — previously fl-internal only
//! (wcsftime has conformance_diff_wcsftime + a fuzz; the _l variant did not).
//! With a "C" locale_t and a UTC-normalized tm, fl's wide-string time format
//! must match glibc's wcsftime_l byte-for-byte (wchar_t array AND return
//! length) across numeric date/time, English locale names, week numbers, %j,
//! combined %c/%x/%X, and literals. %s/%Z/%z omitted (architectural timezone
//! axis). No mocks.

use std::ffi::{c_char, c_int, c_void, CString};
use libc::wchar_t;

unsafe extern "C" {
    fn wcsftime_l(s: *mut wchar_t, max: usize, fmt: *const wchar_t, tm: *const libc::tm, loc: *mut c_void) -> usize;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
    fn timegm(tm: *mut libc::tm) -> libc::time_t;
}

fn wide(s: &str) -> Vec<wchar_t> {
    s.chars().map(|c| c as wchar_t).chain(std::iter::once(0)).collect()
}

fn base_tm() -> libc::tm {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = 2024 - 1900;
    tm.tm_mon = 2;
    tm.tm_mday = 15;
    tm.tm_hour = 14;
    tm.tm_min = 30;
    tm.tm_sec = 45;
    unsafe { timegm(&mut tm) };
    tm
}

const FORMATS: &[&str] = &[
    "%Y-%m-%d", "%H:%M:%S", "%A", "%a", "%B", "%b", "%p", "%I:%M %p",
    "%j", "%U", "%W", "%V", "%w", "%u", "%C", "%y", "%e", "%D", "%F",
    "%R", "%T", "%c", "%x", "%X", "lit %% %Y end",
];

#[test]
fn wcsftime_l_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());
    let tm = base_tm();

    for &f in FORMATS {
        let wf = wide(f);
        let mut gbuf = vec![0 as wchar_t; 256];
        let mut fbuf = vec![0 as wchar_t; 256];
        let gn = unsafe { wcsftime_l(gbuf.as_mut_ptr(), gbuf.len(), wf.as_ptr(), &tm, loc) };
        let fln = unsafe {
            frankenlibc_abi::wchar_abi::wcsftime_l(
                fbuf.as_mut_ptr(),
                fbuf.len(),
                wf.as_ptr(),
                &tm as *const libc::tm as *const c_void,
                loc as *mut c_void,
            )
        };
        assert_eq!(fln, gn, "wcsftime_l({f:?}) return length: fl={fln} glibc={gn}");
        assert_eq!(&fbuf[..fln], &gbuf[..gn], "wcsftime_l({f:?}) wide bytes differ");
    }
    unsafe { freelocale(loc) };
}
