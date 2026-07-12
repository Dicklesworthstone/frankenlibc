#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getw/putw oracle + real temp files

//! Differential gate for getw/putw (bd-j7gsni) — previously uncovered. putw
//! writes a native-endian int (4 bytes) to a stream; getw reads one back. fl's
//! on-disk bytes must match host glibc's, and a write/read roundtrip must
//! recover the exact values. No mocks.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn getw(f: *mut c_void) -> c_int;
        pub fn putw(w: c_int, f: *mut c_void) -> c_int;
    }
}
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp(tag: &str) -> (std::path::PathBuf, std::ffi::CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-getw-{}-{}-{}", std::process::id(), tag, n));
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

const VALS: [c_int; 5] = [0x1122_3344, -1, 0, i32::MIN, i32::MAX];

#[test]
fn putw_writes_same_bytes_as_glibc() {
    let (fp, fc) = tmp("flw");
    let f = unsafe { fl::fopen(fc.as_ptr().cast::<c_char>(), c"w".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());
    for v in VALS {
        assert_eq!(unsafe { fl::putw(v, f) }, 0, "fl putw should return 0");
    }
    unsafe { fl::fclose(f) };
    let fb = std::fs::read(&fp).unwrap();
    let _ = std::fs::remove_file(&fp);

    let (gp, gc) = tmp("gw");
    let gf = unsafe { g::fopen(gc.as_ptr(), c"w".as_ptr()) };
    assert!(!gf.is_null());
    for v in VALS {
        assert_eq!(unsafe { g::putw(v, gf) }, 0, "glibc putw should return 0");
    }
    unsafe { g::fclose(gf) };
    let gb = std::fs::read(&gp).unwrap();
    let _ = std::fs::remove_file(&gp);

    assert_eq!(fb, gb, "putw byte stream: fl != glibc");
    assert_eq!(
        fb.len(),
        VALS.len() * 4,
        "putw should write 4 bytes per int"
    );
}

#[test]
fn getw_roundtrips_putw() {
    // Write with fl, read back with fl.
    let (fp, fc) = tmp("rt");
    let f = unsafe {
        fl::fopen(
            fc.as_ptr().cast::<c_char>(),
            c"w+".as_ptr().cast::<c_char>(),
        )
    };
    assert!(!f.is_null());
    for v in VALS {
        unsafe { fl::putw(v, f) };
    }
    // Reopen for reading (avoids relying on in-place rewind semantics).
    unsafe { fl::fclose(f) };
    let rf = unsafe { fl::fopen(fc.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!rf.is_null());
    for expect in VALS {
        let got = unsafe { fl::getw(rf) };
        assert_eq!(got, expect, "getw roundtrip");
    }
    unsafe { fl::fclose(rf) };
    let _ = std::fs::remove_file(&fp);
}
