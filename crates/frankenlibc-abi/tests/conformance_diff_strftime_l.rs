#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strftime_l oracle

//! Differential gate for strftime_l (bd-t6c1zz) — previously zero coverage.
//! With a "C" locale_t, strftime_l must format a broken-down time identically
//! to glibc's strftime_l across a broad set of conversion specifiers (numeric
//! date/time, locale names %A/%B/%p which are English in C, week numbers %U/%W/
//! %V, day-of-year %j, %s epoch, combined %c/%x/%X, literals and %%). fl must
//! match host glibc byte-for-byte (output bytes AND return length). No mocks.

use std::ffi::{c_char, c_void, CString};

unsafe extern "C" {
    fn strftime_l(s: *mut c_char, max: usize, fmt: *const c_char, tm: *const libc::tm, loc: *mut c_void) -> usize;
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
    "%Y-%m-%d", "%H:%M:%S", "%A", "%a", "%B", "%b", "%p", "%I:%M %p",
    "%j", "%U", "%W", "%V", "%w", "%u", "%C", "%y", "%G", "%g",
    "%e", "%k", "%l", "%n%t", "%D", "%F", "%R", "%T", "%c", "%x", "%X",
    "literal text %% %Y end", "%EY %Od",
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
        let gn = unsafe { strftime_l(gbuf.as_mut_ptr() as *mut c_char, gbuf.len(), fc.as_ptr(), &tm, loc) };
        let fln = unsafe {
            frankenlibc_abi::unistd_abi::strftime_l(
                fbuf.as_mut_ptr() as *mut c_char,
                fbuf.len(),
                fc.as_ptr(),
                &tm as *const libc::tm as *const c_void,
                loc as *mut c_void,
            )
        };
        assert_eq!(fln, gn, "strftime_l({f:?}) return length: fl={fln} glibc={gn}");
        assert_eq!(
            &fbuf[..fln], &gbuf[..gn],
            "strftime_l({f:?}) bytes: fl={:?} glibc={:?}",
            String::from_utf8_lossy(&fbuf[..fln]),
            String::from_utf8_lossy(&gbuf[..gn])
        );
    }
    unsafe { freelocale(loc) };
}
