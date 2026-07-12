#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // live host-glibc __freading/__fwriting oracle + real FILE*

//! Differential gate for __freading / __fwriting direction tracking
//! (bd-2x73ye). Both previously returned 0 unconditionally; glibc returns
//! nonzero when the stream is read-only/write-only respectively, or when the
//! last operation went in that direction. fl now tracks the last-I/O direction
//! in the stream and reports it. This gate opens the SAME mode with fl and host
//! glibc, performs the SAME operation, and asserts the introspection agrees.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type File = c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
        pub fn fclose(f: *mut File) -> c_int;
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut File) -> usize;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut File) -> usize;
        pub fn __freading(f: *mut File) -> c_int;
        pub fn __fwriting(f: *mut File) -> c_int;
    }
}
use frankenlibc_abi::glibc_internal_abi as fle;
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn temp_path(tag: &str) -> std::ffi::CString {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-rwdir-{}-{}-{}", std::process::id(), tag, n));
    std::fs::write(&p, b"seed-data-payload\n").unwrap();
    std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap()
}

/// (reading, writing) from glibc for a stream opened `mode`, after `op`.
fn glibc_dir(mode: &str, op: Op) -> (bool, bool) {
    let cm = std::ffi::CString::new(mode).unwrap();
    let path = temp_path(&format!("g{mode}"));
    let s = unsafe { g::fopen(path.as_ptr(), cm.as_ptr()) };
    assert!(!s.is_null());
    let mut buf = [0u8; 4];
    match op {
        Op::None => {}
        Op::Read => {
            unsafe { g::fread(buf.as_mut_ptr().cast(), 1, 1, s) };
        }
        Op::Write => {
            unsafe { g::fwrite(b"x".as_ptr().cast(), 1, 1, s) };
        }
    }
    let r = (
        unsafe { g::__freading(s) } != 0,
        unsafe { g::__fwriting(s) } != 0,
    );
    unsafe { g::fclose(s) };
    r
}

fn fl_dir(mode: &str, op: Op) -> (bool, bool) {
    let cm = std::ffi::CString::new(mode).unwrap();
    let path = temp_path(&format!("f{mode}"));
    let s = unsafe { fl::fopen(path.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
    assert!(!s.is_null());
    let mut buf = [0u8; 4];
    match op {
        Op::None => {}
        Op::Read => {
            unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 1, s) };
        }
        Op::Write => {
            unsafe { fl::fwrite(b"x".as_ptr().cast(), 1, 1, s) };
        }
    }
    let r = (
        unsafe { fle::__freading(s) } != 0,
        unsafe { fle::__fwriting(s) } != 0,
    );
    unsafe { fl::fclose(s) };
    r
}

#[derive(Clone, Copy)]
enum Op {
    None,
    Read,
    Write,
}

#[test]
fn freading_fwriting_match_glibc() {
    let cases: &[(&str, Op)] = &[
        ("r", Op::None),   // read-only -> reading
        ("w", Op::None),   // write-only -> writing
        ("a", Op::None),   // write-only -> writing
        ("r+", Op::None),  // neither yet
        ("w+", Op::None),  // neither yet
        ("r+", Op::Read),  // last op read
        ("r+", Op::Write), // last op write
        ("w+", Op::Read),  // (file truncated; read at EOF still counts as a read op)
        ("w+", Op::Write), // last op write
        ("a+", Op::Read),
        ("a+", Op::Write),
    ];
    for &(mode, op) in cases {
        let g = glibc_dir(mode, op);
        let f = fl_dir(mode, op);
        let opname = match op {
            Op::None => "none",
            Op::Read => "read",
            Op::Write => "write",
        };
        assert_eq!(
            f, g,
            "__freading/__fwriting mode={mode} op={opname}: fl={f:?} glibc={g:?}"
        );
    }

    // Spec invariants on the unambiguous cases.
    assert_eq!(fl_dir("r", Op::None), (true, false), "r is read-only");
    assert_eq!(fl_dir("w", Op::None), (false, true), "w is write-only");
    assert_eq!(
        fl_dir("r+", Op::Read),
        (true, false),
        "r+ after read -> reading"
    );
    assert_eq!(
        fl_dir("r+", Op::Write),
        (false, true),
        "r+ after write -> writing"
    );
}
