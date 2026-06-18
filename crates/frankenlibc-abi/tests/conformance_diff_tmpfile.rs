#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc tmpfile oracle

//! Differential gate for tmpfile / tmpfile64 (bd-xrf7qs) — no differential gate
//! existed. tmpfile() returns a FILE* for a new, unnamed, auto-deleted temp
//! file open in "w+b". This exercises the full contract for each impl on its
//! own stream: non-NULL result, write then rewind then read-back preserves the
//! bytes, ftell after writing equals the byte count, and EOF after reading all.
//! The observable (write/read round-trip outcome) is compared with glibc.
//! No mocks.

use std::ffi::{c_int, c_void};

const SEEK_SET: c_int = 0;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn tmpfile() -> *mut c_void;
        pub fn tmpfile64() -> *mut c_void;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fseek(f: *mut c_void, off: c_long, whence: c_int) -> c_int;
        pub fn ftell(f: *mut c_void) -> c_long;
        pub fn fclose(f: *mut c_void) -> c_int;
    }
}
use std::ffi::c_long;
use frankenlibc_abi::stdio_abi as fl;

const PAYLOAD: &[u8] = b"Hello tmpfile \x00\x01\xfe\xff round-trip";

/// (non_null, bytes_written, tell_after_write, bytes_read, read_back_matches)
type RT = (bool, usize, c_long, usize, bool);

fn round_trip(
    open: unsafe extern "C" fn() -> *mut c_void,
    fwrite: unsafe extern "C" fn(*const c_void, usize, usize, *mut c_void) -> usize,
    fread: unsafe extern "C" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    fseek: unsafe extern "C" fn(*mut c_void, c_long, c_int) -> c_int,
    ftell: unsafe extern "C" fn(*mut c_void) -> c_long,
    fclose: unsafe extern "C" fn(*mut c_void) -> c_int,
) -> RT {
    unsafe {
        let f = open();
        if f.is_null() {
            return (false, 0, -1, 0, false);
        }
        let w = fwrite(PAYLOAD.as_ptr() as *const c_void, 1, PAYLOAD.len(), f);
        let tell = ftell(f);
        fseek(f, 0, SEEK_SET);
        let mut buf = vec![0u8; PAYLOAD.len() + 8];
        let r = fread(buf.as_mut_ptr() as *mut c_void, 1, buf.len(), f);
        let matches = r == PAYLOAD.len() && &buf[..r] == PAYLOAD;
        fclose(f);
        (true, w, tell, r, matches)
    }
}

#[test]
fn tmpfile_round_trip_matches_glibc() {
    let gr = round_trip(g::tmpfile, g::fwrite, g::fread, g::fseek, g::ftell, g::fclose);
    let fr = round_trip(fl::tmpfile, fl::fwrite, fl::fread, fl::fseek, fl::ftell, fl::fclose);
    assert_eq!(fr, gr, "tmpfile round-trip: fl={fr:?} glibc={gr:?}");
    assert_eq!(gr, (true, PAYLOAD.len(), PAYLOAD.len() as c_long, PAYLOAD.len(), true), "glibc reference");
}

#[test]
fn tmpfile64_round_trip_matches_glibc() {
    let gr = round_trip(g::tmpfile64, g::fwrite, g::fread, g::fseek, g::ftell, g::fclose);
    let fr = round_trip(fl::tmpfile64, fl::fwrite, fl::fread, fl::fseek, fl::ftell, fl::fclose);
    assert_eq!(fr, gr, "tmpfile64 round-trip: fl={fr:?} glibc={gr:?}");
    assert!(gr.0 && gr.4, "glibc tmpfile64 should round-trip");
}
