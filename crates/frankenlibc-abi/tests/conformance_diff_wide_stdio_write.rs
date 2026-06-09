#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-stdio oracle

//! Wide-stdio WRITE-side + ungetwc parity vs host glibc C.UTF-8
//! (bd-2g7oyh.287). `fputwc`/`fputws` byte-encoding (incl. obsolete 5/6-byte
//! RFC-2279 and the unconvertible-char '?' substitution glibc's gconv emits)
//! and `ungetwc` push-back are compared against the live glibc oracle by
//! writing/reading the SAME on-disk file with each engine.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::stdio_abi as flio;
use frankenlibc_abi::wchar_abi as flw;

unsafe extern "C" {
    fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
    fn fclose(s: *mut c_void) -> c_int;
    fn fputwc(wc: u32, s: *mut c_void) -> u32;
    fn fputws(ws: *const i32, s: *mut c_void) -> c_int;
    fn fgetwc(s: *mut c_void) -> u32;
    fn ungetwc(wc: u32, s: *mut c_void) -> u32;
    fn setlocale(c: c_int, l: *const c_char) -> *mut c_char;
}
const WEOF: u32 = 0xFFFF_FFFF;

fn open(path: &str, mode: &str, host: bool) -> *mut c_void {
    let cp = CString::new(path).unwrap();
    let m = CString::new(mode).unwrap();
    if host { unsafe { fopen(cp.as_ptr(), m.as_ptr()) } } else { unsafe { flio::fopen(cp.as_ptr(), m.as_ptr()) } }
}
fn close(s: *mut c_void, host: bool) {
    if host { unsafe { fclose(s) }; } else { unsafe { flio::fclose(s) }; }
}

/// (return-value-sequence, resulting-file-bytes) for writing `chars` via fputwc.
fn putwc_run(chars: &[u32], host: bool) -> (Vec<i64>, Vec<u8>) {
    let p = format!("/tmp/fl_wsw_{}_{}.bin", std::process::id(), host as u8);
    let s = open(&p, "w", host);
    assert!(!s.is_null());
    let mut rets = vec![];
    for &c in chars {
        let r = if host { unsafe { fputwc(c, s) } } else { unsafe { flw::fputwc(c, s) } };
        rets.push(r as i32 as i64);
    }
    close(s, host);
    let b = std::fs::read(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    (rets, b)
}

fn putws_bytes(ws: &[i32], host: bool) -> Vec<u8> {
    let p = format!("/tmp/fl_wsw2_{}_{}.bin", std::process::id(), host as u8);
    let s = open(&p, "w", host);
    assert!(!s.is_null());
    let mut v = ws.to_vec();
    v.push(0);
    if host { unsafe { fputws(v.as_ptr(), s) }; } else { unsafe { flw::fputws(v.as_ptr(), s) }; }
    close(s, host);
    let b = std::fs::read(&p).unwrap_or_default();
    let _ = std::fs::remove_file(&p);
    b
}

fn unget_script(content: &[u8], host: bool) -> Vec<i64> {
    let p = format!("/tmp/fl_wsu_{}_{}.bin", std::process::id(), host as u8);
    std::fs::write(&p, content).unwrap();
    let s = open(&p, "r", host);
    assert!(!s.is_null());
    let g = |s: *mut c_void| if host { unsafe { fgetwc(s) } } else { unsafe { flw::fgetwc(s) } };
    let u = |wc: u32, s: *mut c_void| if host { unsafe { ungetwc(wc, s) } } else { unsafe { flw::ungetwc(wc, s) } };
    let mut out = vec![];
    let c1 = g(s);
    out.push(c1 as i32 as i64);
    out.push(u(c1, s) as i32 as i64); // push back -> returns the char
    out.push(g(s) as i32 as i64); // re-read c1
    out.push(u(b'Z' as u32, s) as i32 as i64); // push a different char
    out.push(g(s) as i32 as i64); // read Z
    out.push(u(WEOF, s) as i32 as i64); // push WEOF -> WEOF (no-op)
    out.push(g(s) as i32 as i64); // continue normally
    close(s, host);
    let _ = std::fs::remove_file(&p);
    out
}

#[test]
fn wide_stdio_write_matches_glibc() {
    let loc = CString::new("C.UTF-8").unwrap();
    if unsafe { setlocale(0, loc.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }
    // fputwc byte encoding + return values, incl. obsolete 5/6-byte and the
    // unconvertible-char '?' substitution.
    let char_cases: &[&[u32]] = &[
        &[97, 98, 10],
        &[0xE9, 0x20AC, 0x10348],
        &[0x110000],          // > U+10FFFF, still a valid 4-byte RFC-2279 form
        &[0x200000],          // 5-byte
        &[0x4000000],         // 6-byte
        &[0x7FFF_FFFF],       // max 6-byte
        &[0xD800],            // surrogate -> '?'
        &[0x8000_0000],       // > U+7FFFFFFF -> '?'
        &[0x41, 0xD800, 0x42], // valid, '?', valid in one stream
    ];
    for chars in char_cases {
        assert_eq!(putwc_run(chars, false), putwc_run(chars, true), "fputwc {chars:x?}");
    }

    for ws in [&[104i32, 105][..], &[0x20AC, 0x10348][..], &[0x41, 0xD800, 0x42][..]] {
        assert_eq!(putws_bytes(ws, false), putws_bytes(ws, true), "fputws {ws:x?}");
    }

    for content in [&b"abc"[..], "\u{20ac}x".as_bytes(), &b"a\nb"[..]] {
        assert_eq!(unget_script(content, false), unget_script(content, true), "ungetwc {content:x?}");
    }
}
