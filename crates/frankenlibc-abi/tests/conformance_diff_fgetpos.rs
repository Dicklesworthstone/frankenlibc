#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // real FILE* streams over a temp file

//! Roundtrip gate for fgetpos/fsetpos (bd-678e8f) — previously uncovered.
//! fgetpos records the current stream position into an opaque fpos_t; fsetpos
//! restores it. After reading some bytes, saving, reading more, then restoring,
//! re-reading must yield the same bytes — and fgetpos must report the byte
//! offset (via ftell agreement). Validates fl's own streams plus matches host
//! glibc's observable behaviour. No mocks.

use std::ffi::c_char;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn tmp_with(content: &[u8]) -> (std::path::PathBuf, std::ffi::CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fgetpos-{}-{}", std::process::id(), n));
    std::fs::write(&p, content).unwrap();
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

#[test]
fn fgetpos_fsetpos_roundtrip() {
    let (path, c) = tmp_with(b"ABCDEFGHIJ");
    let f = unsafe { fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());

    let mut buf = [0u8; 3];
    // Read "ABC".
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"ABC");

    // Save position (offset 3).
    let mut pos: libc::fpos_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { fl::fgetpos(f, &mut pos) },
        0,
        "fgetpos should succeed"
    );
    assert_eq!(
        unsafe { fl::ftell(f) },
        3,
        "position should be 3 after reading ABC"
    );

    // Read "DEF".
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"DEF");

    // Restore to offset 3, re-read -> "DEF" again.
    assert_eq!(unsafe { fl::fsetpos(f, &pos) }, 0, "fsetpos should succeed");
    assert_eq!(unsafe { fl::ftell(f) }, 3, "fsetpos must restore offset 3");
    buf = [0u8; 3];
    assert_eq!(unsafe { fl::fread(buf.as_mut_ptr().cast(), 1, 3, f) }, 3);
    assert_eq!(&buf, b"DEF", "re-read after fsetpos must match");

    unsafe { fl::fclose(f) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fsetpos_to_start_rereads_whole_file() {
    let (path, c) = tmp_with(b"hello world");
    let f = unsafe { fl::fopen(c.as_ptr().cast::<c_char>(), c"r".as_ptr().cast::<c_char>()) };
    assert!(!f.is_null());

    // Save start, read everything, restore start, read first 5.
    let mut start: libc::fpos_t = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { fl::fgetpos(f, &mut start) }, 0);
    let mut all = [0u8; 11];
    assert_eq!(unsafe { fl::fread(all.as_mut_ptr().cast(), 1, 11, f) }, 11);
    assert_eq!(&all, b"hello world");

    assert_eq!(unsafe { fl::fsetpos(f, &start) }, 0);
    let mut five = [0u8; 5];
    assert_eq!(unsafe { fl::fread(five.as_mut_ptr().cast(), 1, 5, f) }, 5);
    assert_eq!(
        &five, b"hello",
        "fsetpos to start must re-read from the beginning"
    );

    unsafe { fl::fclose(f) };
    let _ = std::fs::remove_file(&path);
}
