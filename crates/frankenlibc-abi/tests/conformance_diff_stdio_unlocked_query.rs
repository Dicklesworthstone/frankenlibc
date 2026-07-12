#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc stdio oracle; real temp files

//! Differential gate for the stdio _unlocked query variants feof_unlocked /
//! ferror_unlocked / fileno_unlocked / clearerr_unlocked (bd-exiib1) — all had
//! no differential gate (fl-internal only). Each must (a) agree with its locked
//! counterpart within the same implementation, and (b) reach the same EOF /
//! error state as glibc after identical operations. Each impl uses its own
//! fopen/read so the streams never cross. fd VALUES legitimately differ across
//! impls, so fileno is only checked for validity (>= 0). No mocks.

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fgetc(f: *mut c_void) -> c_int;
        pub fn feof_unlocked(f: *mut c_void) -> c_int;
        pub fn ferror_unlocked(f: *mut c_void) -> c_int;
        pub fn fileno_unlocked(f: *mut c_void) -> c_int;
        pub fn clearerr_unlocked(f: *mut c_void);
        pub fn feof(f: *mut c_void) -> c_int;
        pub fn ferror(f: *mut c_void) -> c_int;
    }
}
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);

fn make_temp(contents: &[u8]) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-unlocked-{}-{}", std::process::id(), n));
    std::fs::write(&p, contents).unwrap();
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

/// Returns (eof_norm, err_norm, fileno_valid) after reading every byte + 1 past EOF.
fn glibc_probe(path: &CString) -> (bool, bool, bool) {
    unsafe {
        let f = g::fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!f.is_null());
        let fno_valid = g::fileno_unlocked(f) >= 0;
        while g::fgetc(f) != -1 {}
        // After hitting EOF: feof_unlocked must agree with feof.
        let eof = g::feof_unlocked(f) != 0;
        assert_eq!(eof, g::feof(f) != 0, "glibc feof_unlocked != feof");
        let err = g::ferror_unlocked(f) != 0;
        assert_eq!(err, g::ferror(f) != 0, "glibc ferror_unlocked != ferror");
        g::clearerr_unlocked(f);
        assert!(
            g::feof_unlocked(f) == 0 && g::ferror_unlocked(f) == 0,
            "glibc clearerr_unlocked"
        );
        g::fclose(f);
        (eof, err, fno_valid)
    }
}

fn fl_probe(path: &CString) -> (bool, bool, bool) {
    unsafe {
        let f = fl::fopen(path.as_ptr().cast(), c"r".as_ptr().cast());
        assert!(!f.is_null());
        let fno_valid = fl::fileno_unlocked(f) >= 0;
        while fl::fgetc(f) != -1 {}
        let eof = fl::feof_unlocked(f) != 0;
        assert_eq!(eof, fl::feof(f) != 0, "fl feof_unlocked != feof");
        let err = fl::ferror_unlocked(f) != 0;
        assert_eq!(err, fl::ferror(f) != 0, "fl ferror_unlocked != ferror");
        fl::clearerr_unlocked(f);
        assert!(
            fl::feof_unlocked(f) == 0 && fl::ferror_unlocked(f) == 0,
            "fl clearerr_unlocked"
        );
        fl::fclose(f);
        (eof, err, fno_valid)
    }
}

#[test]
fn stdio_unlocked_query_matches_glibc() {
    for contents in [&b"hello world"[..], &b""[..], &b"x"[..]] {
        let (path, c) = make_temp(contents);
        let gp = glibc_probe(&c);
        let fp = fl_probe(&c);
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            fp, gp,
            "unlocked query state for {contents:?}: fl={fp:?} glibc={gp:?}"
        );
        assert!(gp.0, "reading past end should set EOF");
        assert!(gp.2 && fp.2, "fileno_unlocked should be valid");
    }
}
