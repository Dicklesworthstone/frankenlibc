#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fwprintf oracle; real temp files

//! Differential gate for fwprintf (bd-tliut7) — wide formatted output to a
//! stream had no differential gate. fwprintf formats a wide format string and
//! writes the multibyte encoding to the stream (per the C.UTF-8 locale here).
//! Each impl writes with its own fopen/fwprintf to a temp file; the produced
//! bytes AND the return value (count of wide chars, or -1) are compared with
//! glibc across %d/%x/%f/%ls/%lc conversions. No mocks.

use libc::wchar_t;
use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fwprintf(f: *mut c_void, fmt: *const wchar_t, ...) -> c_int;
        pub fn setlocale(cat: c_int, loc: *const c_char) -> *mut c_char;
    }
}
use frankenlibc_abi::{stdio_abi as fls, wchar_abi as flw};

static CNT: AtomicU64 = AtomicU64::new(0);

fn wfmt(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

fn tmp(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fwprintf-{}-{}-{}", std::process::id(), tag, n));
    (
        p.clone(),
        CString::new(p.to_string_lossy().as_bytes()).unwrap(),
    )
}

macro_rules! both {
    ($desc:literal, $fmt:expr $(, $arg:expr)*) => {{
        let wf = wfmt($fmt);
        // glibc
        let (gp, gc) = tmp("g");
        let gret = unsafe {
            let f = g::fopen(gc.as_ptr(), c"w".as_ptr());
            assert!(!f.is_null());
            let r = g::fwprintf(f, wf.as_ptr() $(, $arg)*);
            g::fclose(f);
            r
        };
        let gb = std::fs::read(&gp).unwrap_or_default();
        let _ = std::fs::remove_file(&gp);
        // fl
        let (fp, fc) = tmp("fl");
        let fret = unsafe {
            let f = fls::fopen(fc.as_ptr().cast(), c"w".as_ptr().cast());
            assert!(!f.is_null());
            let r = flw::fwprintf(f.cast::<c_void>(), wf.as_ptr() $(, $arg)*);
            fls::fclose(f);
            r
        };
        let fb = std::fs::read(&fp).unwrap_or_default();
        let _ = std::fs::remove_file(&fp);

        assert_eq!(fret, gret, "fwprintf({:?}) [{}] ret: fl={fret} glibc={gret}", $fmt, $desc);
        assert_eq!(
            fb, gb, "fwprintf({:?}) [{}] bytes: fl={:?} glibc={:?}",
            $fmt, $desc, String::from_utf8_lossy(&fb), String::from_utf8_lossy(&gb),
        );
    }};
}

#[test]
fn fwprintf_matches_glibc() {
    unsafe { g::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };

    let wide = wfmt("wide-arg");
    both!("decimal", "n=%d\n", 42 as c_int);
    both!("hex", "h=%x\n", 255 as c_int);
    both!("float", "f=%.3f\n", 3.14159f64);
    both!(
        "multi-int",
        "%d-%d-%d\n",
        1 as c_int,
        2 as c_int,
        3 as c_int
    );
    both!("wide string %ls", "s=[%ls]\n", wide.as_ptr());
    both!("wide char %lc", "c=%lc\n", ('Z' as wchar_t) as c_int);
    both!("percent + width", "[%5d]\n", 7 as c_int);
    both!("plain literal", "no conversions here\n");
}
