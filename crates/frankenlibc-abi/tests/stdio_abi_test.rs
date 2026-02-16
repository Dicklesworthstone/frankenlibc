#![cfg(target_os = "linux")]

//! Integration tests for `<stdio.h>` ABI entrypoints.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi::{
    fclose, fflush, fgetc, fgets, fileno, fopen, fputc, fputs, fread, fseek, fwrite, setbuf,
    setvbuf, ungetc,
};

const IOFBF: i32 = 0;
const IONBF: i32 = 2;

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(0);

fn temp_path(tag: &str) -> PathBuf {
    let id = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut path = std::env::temp_dir();
    path.push(format!(
        "frankenlibc_stdio_{}_{}_{}.tmp",
        tag,
        std::process::id(),
        id
    ));
    path
}

fn path_cstring(path: &PathBuf) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("temp path must not contain interior NUL")
}

#[test]
fn fopen_fputs_fflush_fclose_round_trip() {
    let path = temp_path("puts");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: `stream` is an open FILE* sentinel managed by stdio_abi.
    assert_eq!(unsafe { fputs(c"hello from stdio\n".as_ptr(), stream) }, 0);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);

    let bytes = fs::read(&path).expect("round-trip file read should succeed");
    assert_eq!(bytes, b"hello from stdio\n");

    let _ = fs::remove_file(path);
}

#[test]
fn fputc_fgetc_and_ungetc_behave_consistently() {
    let path = temp_path("chars");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: `stream` is valid and writable.
    assert_eq!(unsafe { fputc(b'A' as i32, stream) }, b'A' as i32);
    // SAFETY: `stream` is valid and writable.
    assert_eq!(unsafe { fputc(b'B' as i32, stream) }, b'B' as i32);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    // SAFETY: `stream` is valid and readable.
    assert_eq!(unsafe { fgetc(stream) }, b'A' as i32);
    // SAFETY: `stream` is valid and readable.
    assert_eq!(unsafe { ungetc(b'Z' as i32, stream) }, b'Z' as i32);
    // SAFETY: `stream` is valid and readable.
    assert_eq!(unsafe { fgetc(stream) }, b'Z' as i32);
    // SAFETY: `stream` is valid and readable.
    assert_eq!(unsafe { fgetc(stream) }, b'B' as i32);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);

    let _ = fs::remove_file(path);
}

#[test]
fn fwrite_then_fread_round_trip_matches_bytes() {
    let path = temp_path("rw");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let expected = b"frankenlibc-stdio";
    // SAFETY: source pointer is valid for `expected.len()` bytes and stream is open.
    let wrote = unsafe { fwrite(expected.as_ptr().cast(), 1, expected.len(), stream) };
    assert_eq!(wrote, expected.len());
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut actual = vec![0u8; expected.len()];
    // SAFETY: destination pointer is valid and stream is open.
    let read = unsafe { fread(actual.as_mut_ptr().cast(), 1, actual.len(), stream) };
    assert_eq!(read, expected.len());
    assert_eq!(actual, expected);

    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn fgets_reads_a_line_and_nul_terminates() {
    let path = temp_path("fgets");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: `stream` is valid and writable.
    assert_eq!(unsafe { fputs(c"alpha\nbeta\n".as_ptr(), stream) }, 0);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0_i8; 16];
    // SAFETY: destination buffer is writable and stream is valid.
    let out = unsafe { fgets(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert_eq!(out, buf.as_mut_ptr());

    // SAFETY: `fgets` guarantees NUL-termination on success.
    let line = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(line.to_bytes(), b"alpha\n");

    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn fileno_and_setvbuf_contracts_hold() {
    let path = temp_path("buf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: `stream` is valid and open.
    let fd = unsafe { fileno(stream) };
    assert!(fd >= 0);

    // SAFETY: setvbuf before any I/O is valid.
    assert_eq!(
        unsafe { setvbuf(stream, std::ptr::null_mut(), IONBF, 0) },
        0
    );
    // SAFETY: `stream` remains valid after setvbuf.
    assert_eq!(unsafe { fputc(b'X' as i32, stream) }, b'X' as i32);

    // After I/O, setvbuf should reject mode changes.
    // SAFETY: call is valid even when expected to fail.
    assert_eq!(
        unsafe { setvbuf(stream, std::ptr::null_mut(), IOFBF, 1024) },
        -1
    );

    // setbuf should remain callable without crashing.
    // SAFETY: wrapper over setvbuf for this valid stream.
    unsafe { setbuf(stream, std::ptr::null_mut()) };

    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}
