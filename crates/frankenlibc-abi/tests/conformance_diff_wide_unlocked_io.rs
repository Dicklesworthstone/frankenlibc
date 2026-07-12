#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-unlocked-stdio oracle; real temp files

//! Differential gate for the WIDE unlocked stdio variants (bd-kigvyb):
//! fputwc_unlocked / fputws_unlocked (write path) and fgetwc_unlocked /
//! fgetws_unlocked (read path) — all had no differential gate. These convert
//! between wide chars and the stream's multibyte encoding (C.UTF-8 here). Each
//! impl writes a fixed wide payload to its own temp file (the resulting UTF-8
//! bytes compared), then reads a known UTF-8 file via the wide readers (decoded
//! wide values + return codes compared) vs glibc. No mocks.

use libc::wchar_t;
use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn setlocale(cat: c_int, loc: *const c_char) -> *mut c_char;
        pub fn fputwc_unlocked(wc: wchar_t, f: *mut c_void) -> u32;
        pub fn fputws_unlocked(ws: *const wchar_t, f: *mut c_void) -> c_int;
        pub fn fgetwc_unlocked(f: *mut c_void) -> u32;
        pub fn fgetws_unlocked(buf: *mut wchar_t, n: c_int, f: *mut c_void) -> *mut wchar_t;
    }
}
use frankenlibc_abi::{stdio_abi as fls, wchar_abi as flw};

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-wulio-{}-{}-{}", std::process::id(), tag, n));
    (
        p.clone(),
        CString::new(p.to_string_lossy().as_bytes()).unwrap(),
    )
}
fn wstr(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

macro_rules! write_path {
    ($fopen:path,$fclose:path,$fputwc:path,$fputws:path,$tag:literal) => {{
        let (path, c) = tmp($tag);
        let ws = wstr("wíde\n");
        unsafe {
            let f = $fopen(c.as_ptr().cast(), c"w".as_ptr().cast());
            assert!(!f.is_null());
            $fputwc('A' as wchar_t, f.cast());
            $fputwc('é' as wchar_t, f.cast()); // 2-byte UTF-8
            $fputwc('€' as wchar_t, f.cast()); // 3-byte UTF-8
            $fputwc('\n' as wchar_t, f.cast());
            $fputws(ws.as_ptr(), f.cast());
            $fclose(f.cast());
        }
        let b = std::fs::read(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        b
    }};
}

macro_rules! read_path {
    ($fopen:path,$fclose:path,$fgetwc:path,$fgetws:path,$cpath:expr) => {{
        unsafe {
            let f = $fopen($cpath.as_ptr().cast(), c"r".as_ptr().cast());
            assert!(!f.is_null());
            let c0 = $fgetwc(f.cast());
            let c1 = $fgetwc(f.cast());
            let c2 = $fgetwc(f.cast());
            let mut line = [0 as wchar_t; 32];
            let gp = $fgetws(line.as_mut_ptr(), 32, f.cast());
            let got = !gp.is_null();
            $fclose(f.cast());
            (c0, c1, c2, got, line.to_vec())
        }
    }};
}

#[test]
fn wide_unlocked_write_matches_glibc() {
    unsafe { g::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let gb = write_path!(
        g::fopen,
        g::fclose,
        g::fputwc_unlocked,
        g::fputws_unlocked,
        "g"
    );
    let fb = write_path!(
        fls::fopen,
        fls::fclose,
        flw::fputwc_unlocked,
        flw::fputws_unlocked,
        "fl"
    );
    assert_eq!(
        fb,
        gb,
        "wide unlocked write: fl={:?} glibc={:?}",
        String::from_utf8_lossy(&fb),
        String::from_utf8_lossy(&gb)
    );
    assert_eq!(gb, "Aé€\nwíde\n".as_bytes(), "glibc wrote expected UTF-8");
}

#[test]
fn wide_unlocked_read_matches_glibc() {
    unsafe { g::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let (path, c) = tmp("src");
    std::fs::write(&path, "Zé€\nαβγ\n".as_bytes()).unwrap();
    let gr = read_path!(
        g::fopen,
        g::fclose,
        g::fgetwc_unlocked,
        g::fgetws_unlocked,
        c
    );
    let fr = read_path!(
        fls::fopen,
        fls::fclose,
        flw::fgetwc_unlocked,
        flw::fgetws_unlocked,
        c
    );
    let _ = std::fs::remove_file(&path);
    assert_eq!(fr, gr, "wide unlocked read: fl={fr:?} glibc={gr:?}");
}
