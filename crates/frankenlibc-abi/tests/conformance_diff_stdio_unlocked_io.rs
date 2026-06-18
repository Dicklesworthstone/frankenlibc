#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc unlocked-stdio oracle; real temp files

//! Differential gate for the stdio unlocked I/O variants (bd-211ow0):
//! fputc_unlocked / fputs_unlocked / fwrite_unlocked (write path) and
//! fgetc_unlocked / fgets_unlocked / fread_unlocked (read path) — all had no
//! differential gate. Single-threaded, they must behave exactly like their
//! locked counterparts. Each impl writes a fixed payload via all three writers
//! to its own temp file (bytes compared), then reads a known file via all three
//! readers (read values + return codes compared) vs glibc. No mocks.

use std::ffi::{c_char, c_int, c_void, CString};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fputc_unlocked(c: c_int, f: *mut c_void) -> c_int;
        pub fn fputs_unlocked(s: *const c_char, f: *mut c_void) -> c_int;
        pub fn fwrite_unlocked(p: *const c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fgetc_unlocked(f: *mut c_void) -> c_int;
        pub fn fgets_unlocked(buf: *mut c_char, n: c_int, f: *mut c_void) -> *mut c_char;
        pub fn fread_unlocked(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
    }
}
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-ulio-{}-{}-{}", std::process::id(), tag, n));
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

/// Write "Hi\n" + "line2\n" + "BLOCK" via the three unlocked writers; return the file bytes.
macro_rules! write_path {
    ($fopen:path, $fclose:path, $fputc:path, $fputs:path, $fwrite:path, $tag:literal) => {{
        let (path, c) = tmp($tag);
        unsafe {
            let f = $fopen(c.as_ptr().cast(), c"w".as_ptr().cast());
            assert!(!f.is_null());
            $fputc(b'H' as c_int, f.cast());
            $fputc(b'i' as c_int, f.cast());
            $fputc(b'\n' as c_int, f.cast());
            let s = c"line2\n";
            $fputs(s.as_ptr().cast(), f.cast());
            let blk = b"BLOCK";
            $fwrite(blk.as_ptr() as *const c_void, 1, blk.len(), f.cast());
            $fclose(f.cast());
        }
        let b = std::fs::read(&path).unwrap_or_default();
        let _ = std::fs::remove_file(&path);
        b
    }};
}

/// Read a known file via fgetc_unlocked (2 chars), fgets_unlocked (a line), fread_unlocked (rest).
macro_rules! read_path {
    ($fopen:path, $fclose:path, $fgetc:path, $fgets:path, $fread:path, $cpath:expr) => {{
        unsafe {
            let f = $fopen($cpath.as_ptr().cast(), c"r".as_ptr().cast());
            assert!(!f.is_null());
            let c0 = $fgetc(f.cast());
            let c1 = $fgetc(f.cast());
            let mut line = [0u8; 32];
            let gp = $fgets(line.as_mut_ptr() as *mut c_char, 32, f.cast());
            let got_line = !gp.is_null();
            let mut blk = [0u8; 32];
            let nread = $fread(blk.as_mut_ptr() as *mut c_void, 1, 32, f.cast());
            $fclose(f.cast());
            (c0, c1, got_line, line.to_vec(), nread, blk.to_vec())
        }
    }};
}

#[test]
fn unlocked_write_path_matches_glibc() {
    let gb = write_path!(g::fopen, g::fclose, g::fputc_unlocked, g::fputs_unlocked, g::fwrite_unlocked, "g");
    let fb = write_path!(fl::fopen, fl::fclose, fl::fputc_unlocked, fl::fputs_unlocked, fl::fwrite_unlocked, "fl");
    assert_eq!(fb, gb, "unlocked write path: fl={:?} glibc={:?}", String::from_utf8_lossy(&fb), String::from_utf8_lossy(&gb));
    assert_eq!(&gb, b"Hi\nline2\nBLOCK", "glibc wrote the expected payload");
}

#[test]
fn unlocked_read_path_matches_glibc() {
    // Prepare a known file.
    let (path, c) = tmp("src");
    std::fs::write(&path, b"abcdef\nXYZ\n0123456789").unwrap();
    let gr = read_path!(g::fopen, g::fclose, g::fgetc_unlocked, g::fgets_unlocked, g::fread_unlocked, c);
    let fr = read_path!(fl::fopen, fl::fclose, fl::fgetc_unlocked, fl::fgets_unlocked, fl::fread_unlocked, c);
    let _ = std::fs::remove_file(&path);
    assert_eq!(fr, gr, "unlocked read path: fl={fr:?} glibc={gr:?}");
}
