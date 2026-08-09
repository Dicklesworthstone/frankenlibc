#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc freopen oracle + real temp files

//! Differential gate for `freopen(NULL, mode, stream)` — the mode-change form
//! (bd-mpp7kt).
//!
//! POSIX leaves it implementation-defined; glibc implements it by reopening the
//! stream's OWN descriptor through `/proc/self/fd/N` and dup2-ing the result
//! back, so the caller keeps both its `FILE*` and its descriptor number.
//!
//! fl returned NULL with EINVAL — and did so *after* closing the descriptor,
//! so the stream was destroyed and the call still reported failure. A caller
//! that handles the NULL by retrying or by falling back to the original stream
//! was operating on a closed fd.
//!
//! Measured on live glibc 2.42 before being asserted:
//!
//! ```text
//!   f = fopen(p,"w"); fputs("line-one\n",f); fflush(f);
//!   freopen(NULL,"r",f) -> same FILE*, same fd (3), errno untouched
//!   fgets(f)            -> "line-one\n"
//!   freopen(NULL,"r+") on an "r" handle -> success, file NOT truncated
//! ```
//!
//! Each implementation drives its own temp file with its own stdio functions;
//! the two are never mixed.

use std::ffi::{CString, c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut c_void;
        pub fn freopen(
            path: *const c_char,
            mode: *const c_char,
            stream: *mut c_void,
        ) -> *mut c_void;
        pub fn fputs(s: *const c_char, f: *mut c_void) -> c_int;
        pub fn fgets(buf: *mut c_char, n: c_int, f: *mut c_void) -> *mut c_char;
        pub fn fflush(f: *mut c_void) -> c_int;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn fileno(f: *mut c_void) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::stdio_abi as fl;

const SENTINEL_ERRNO: c_int = 0x5EED;

fn plant_errno() {
    unsafe { *g::__errno_location() = SENTINEL_ERRNO };
}
fn read_errno() -> c_int {
    unsafe { *g::__errno_location() }
}

static CNT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

fn tmp_path(tag: &str) -> (std::path::PathBuf, CString) {
    let n = CNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-freopen-{}-{}-{}", std::process::id(), tag, n));
    let _ = std::fs::remove_file(&p);
    let c = CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

/// What one implementation reports for the write-then-reopen-for-read script.
/// `(reopen returned non-null, fd preserved, errno after reopen, bytes read back)`
type Obs = (bool, bool, c_int, Vec<u8>);

macro_rules! write_then_reopen_read {
    ($m:ident, $tag:expr) => {{
        let (path, cpath) = tmp_path($tag);
        let payload = CString::new("line-one\n").unwrap();
        let mode_w = CString::new("w").unwrap();
        let mode_r = CString::new("r").unwrap();
        unsafe {
            let f = $m::fopen(cpath.as_ptr(), mode_w.as_ptr());
            assert!(!f.is_null(), "fopen(w) should succeed");
            $m::fputs(payload.as_ptr(), f);
            $m::fflush(f);
            let fd_before = $m::fileno(f);

            plant_errno();
            let r = $m::freopen(std::ptr::null(), mode_r.as_ptr(), f);
            let e = read_errno();

            let mut got = Vec::new();
            let fd_same = if r.is_null() {
                false
            } else {
                let same = $m::fileno(r) == fd_before;
                let mut buf = [0i8; 64];
                if !$m::fgets(buf.as_mut_ptr(), 64, r).is_null() {
                    for &b in buf.iter() {
                        if b == 0 {
                            break;
                        }
                        got.push(b as u8);
                    }
                }
                same
            };
            if !r.is_null() {
                $m::fclose(r);
            }
            let _ = std::fs::remove_file(&path);
            (!r.is_null(), fd_same, e, got)
        }
    }};
}

/// The headline contract: the mode change succeeds, the descriptor number is
/// preserved, errno is untouched, and the file's contents are readable through
/// the reopened stream.
#[test]
fn freopen_null_mode_change_matches_glibc() {
    let gg: Obs = write_then_reopen_read!(g, "g");
    let ff: Obs = write_then_reopen_read!(fl, "f");
    assert_eq!(
        ff, gg,
        "freopen(NULL,\"r\") after writing: fl={ff:?} glibc={gg:?} \
         (non_null, fd_preserved, errno, bytes_read)"
    );
    // Reference half, so the pair cannot drift together into both-broken.
    assert_eq!(
        (gg.0, gg.1, gg.2),
        (true, true, SENTINEL_ERRNO),
        "glibc: reopen succeeds, keeps the fd number, and leaves errno alone"
    );
    assert_eq!(
        gg.3, b"line-one\n",
        "glibc: the reopened stream reads the bytes written before the reopen"
    );
}

/// `r` -> `r+` must widen the mode without truncating. A NULL-pathname reopen
/// that went through the `w`-style path would silently empty the file, which
/// is the damaging way to get this wrong.
#[test]
fn freopen_null_does_not_truncate_matches_glibc() {
    fn run<F>(open: F, tag: &str) -> (bool, u64)
    where
        F: FnOnce(*const c_char, *const c_char, *const c_char) -> (bool, std::path::PathBuf),
    {
        let (path, cpath) = tmp_path(tag);
        std::fs::write(&path, b"0123456789").expect("seed file");
        let mode_r = CString::new("r").unwrap();
        let mode_rp = CString::new("r+").unwrap();
        let (ok, p) = open(cpath.as_ptr(), mode_r.as_ptr(), mode_rp.as_ptr());
        let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(u64::MAX);
        let _ = std::fs::remove_file(&p);
        let _ = path;
        (ok, size)
    }

    let gg = run(
        |cpath, mr, mrp| unsafe {
            let f = g::fopen(cpath, mr);
            assert!(!f.is_null());
            let r = g::freopen(std::ptr::null(), mrp, f);
            let ok = !r.is_null();
            if ok {
                g::fclose(r);
            } else {
                g::fclose(f);
            }
            let p = std::ffi::CStr::from_ptr(cpath).to_string_lossy().into_owned();
            (ok, std::path::PathBuf::from(p))
        },
        "gt",
    );
    let ff = run(
        |cpath, mr, mrp| unsafe {
            let f = fl::fopen(cpath, mr);
            assert!(!f.is_null());
            let r = fl::freopen(std::ptr::null(), mrp, f);
            let ok = !r.is_null();
            if ok {
                fl::fclose(r);
            } else {
                fl::fclose(f);
            }
            let p = std::ffi::CStr::from_ptr(cpath).to_string_lossy().into_owned();
            (ok, std::path::PathBuf::from(p))
        },
        "ft",
    );

    assert_eq!(
        ff, gg,
        "freopen(NULL,\"r+\") on an \"r\" handle: fl={ff:?} glibc={gg:?} (ok, file_size)"
    );
    assert_eq!(
        gg,
        (true, 10),
        "glibc: the mode widens and the 10 seeded bytes survive"
    );
}
