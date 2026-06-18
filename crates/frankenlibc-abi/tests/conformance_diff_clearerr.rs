#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc clearerr oracle; tmpfile + write-only stream

//! Differential gate for clearerr (bd-428r4i) — no differential gate existed
//! (feof/ferror are gated, but the flag-CLEARING path was not). Two scenarios
//! per impl: (1) read past end of a tmpfile to SET the EOF flag, clearerr, and
//! confirm it clears; (2) read from a write-only stream to SET the error flag,
//! clearerr, and confirm it clears. The packed (eof_set, err_after_eof,
//! eof_after_clear, err_set, eof_after_err, err_after_clear) state is compared
//! vs glibc. No mocks.

use std::ffi::{c_char, c_int, c_long, c_void, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn tmpfile() -> *mut c_void;
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fseek(f: *mut c_void, off: c_long, whence: c_int) -> c_int;
        pub fn feof(f: *mut c_void) -> c_int;
        pub fn ferror(f: *mut c_void) -> c_int;
        pub fn clearerr(f: *mut c_void);
        pub fn fclose(f: *mut c_void) -> c_int;
    }
}
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn wpath() -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-clearerr-{}-{}", std::process::id(), n));
    (p.clone(), CString::new(p.to_string_lossy().as_bytes()).unwrap())
}
fn norm(v: c_int) -> i32 { (v != 0) as i32 }

type S = (i32, i32, i32, i32, i32, i32);

fn glibc_scenario(wp: &CStr) -> S {
    let mut buf = [0u8; 16];
    unsafe {
        // (1) EOF flag via read-past-end of a tmpfile.
        let f = g::tmpfile();
        g::fwrite(b"data".as_ptr() as *const c_void, 1, 4, f);
        g::fseek(f, 0, 0);
        g::fread(buf.as_mut_ptr() as *mut c_void, 1, 16, f);
        let eof_set = norm(g::feof(f));
        let err_after_eof = norm(g::ferror(f));
        g::clearerr(f);
        let eof_after_clear = norm(g::feof(f));
        g::fclose(f);
        // (2) error flag via read on a write-only stream.
        let wf = g::fopen(wp.as_ptr(), c"w".as_ptr());
        g::fread(buf.as_mut_ptr() as *mut c_void, 1, 4, wf);
        let err_set = norm(g::ferror(wf));
        let eof_after_err = norm(g::feof(wf));
        g::clearerr(wf);
        let err_after_clear = norm(g::ferror(wf));
        g::fclose(wf);
        (eof_set, err_after_eof, eof_after_clear, err_set, eof_after_err, err_after_clear)
    }
}

fn fl_scenario(wp: &CStr) -> S {
    let mut buf = [0u8; 16];
    unsafe {
        let f = fl::tmpfile();
        fl::fwrite(b"data".as_ptr() as *const c_void, 1, 4, f);
        fl::fseek(f, 0, 0);
        fl::fread(buf.as_mut_ptr() as *mut c_void, 1, 16, f);
        let eof_set = norm(fl::feof(f));
        let err_after_eof = norm(fl::ferror(f));
        fl::clearerr(f);
        let eof_after_clear = norm(fl::feof(f));
        fl::fclose(f);
        let wf = fl::fopen(wp.as_ptr(), c"w".as_ptr());
        fl::fread(buf.as_mut_ptr() as *mut c_void, 1, 4, wf);
        let err_set = norm(fl::ferror(wf));
        let eof_after_err = norm(fl::feof(wf));
        fl::clearerr(wf);
        let err_after_clear = norm(fl::ferror(wf));
        fl::fclose(wf);
        (eof_set, err_after_eof, eof_after_clear, err_set, eof_after_err, err_after_clear)
    }
}

#[test]
fn clearerr_matches_glibc() {
    let (p1, w1) = wpath();
    let gr = glibc_scenario(&w1);
    let _ = std::fs::remove_file(&p1);
    let (p2, w2) = wpath();
    let fr = fl_scenario(&w2);
    let _ = std::fs::remove_file(&p2);
    assert_eq!(fr, gr, "clearerr scenarios: fl={fr:?} glibc={gr:?}");
    assert_eq!(gr.0, 1, "glibc: EOF set after read-past-end");
    assert_eq!(gr.2, 0, "glibc: EOF cleared by clearerr");
    assert_eq!(gr.3, 1, "glibc: error set after read on write-only stream");
    assert_eq!(gr.5, 0, "glibc: error cleared by clearerr");
}
