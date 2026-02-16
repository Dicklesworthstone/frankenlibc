#![cfg(target_os = "linux")]

//! Integration tests for `<stdio.h>` ABI entrypoints.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi::{
    fclose, fflush, fgetc, fgets, fileno, fopen, fprintf, fputc, fputs, fread, fseek, fwrite,
    printf, setbuf, setvbuf, snprintf, sprintf, ungetc,
};

const IOFBF: i32 = 0;
const IONBF: i32 = 2;

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(0);
static STDOUT_REDIRECT_LOCK: Mutex<()> = Mutex::new(());

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

fn path_cstring(path: &Path) -> CString {
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

#[test]
fn rejects_invalid_open_mode_and_null_stream_handles() {
    let path = temp_path("invalid_mode");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let invalid = unsafe { fopen(path_c.as_ptr(), c"z".as_ptr()) };
    assert!(invalid.is_null());

    // SAFETY: null stream is explicitly rejected by ABI functions.
    assert_eq!(unsafe { fclose(std::ptr::null_mut()) }, libc::EOF);
    // SAFETY: null stream is explicitly rejected by ABI functions.
    assert_eq!(unsafe { fileno(std::ptr::null_mut()) }, -1);
}

#[test]
fn null_and_zero_length_io_paths_are_safe_defaults() {
    let path = temp_path("null_io");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let mut read_buf = [0_u8; 8];

    // SAFETY: zero-sized operations are valid and return zero items.
    assert_eq!(
        unsafe { fread(read_buf.as_mut_ptr().cast(), 0, 8, stream) },
        0
    );
    // SAFETY: zero-sized operations are valid and return zero items.
    assert_eq!(
        unsafe { fread(read_buf.as_mut_ptr().cast(), 1, 0, stream) },
        0
    );
    // SAFETY: null pointer is rejected by ABI implementation.
    assert_eq!(unsafe { fread(std::ptr::null_mut(), 1, 8, stream) }, 0);

    // SAFETY: zero-sized operations are valid and return zero items.
    assert_eq!(
        unsafe { fwrite(read_buf.as_ptr().cast(), 0, read_buf.len(), stream) },
        0
    );
    // SAFETY: zero-sized operations are valid and return zero items.
    assert_eq!(unsafe { fwrite(read_buf.as_ptr().cast(), 1, 0, stream) }, 0);
    // SAFETY: null pointer is rejected by ABI implementation.
    assert_eq!(
        unsafe { fwrite(std::ptr::null(), 1, read_buf.len(), stream) },
        0
    );

    // SAFETY: null string pointer is rejected by ABI implementation.
    assert_eq!(unsafe { fputs(std::ptr::null(), stream) }, libc::EOF);
    // SAFETY: EOF cannot be pushed back by contract.
    assert_eq!(unsafe { ungetc(libc::EOF, stream) }, libc::EOF);

    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn fgets_rejects_invalid_destination_or_size() {
    let path = temp_path("fgets_invalid");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: destination buffer null is rejected.
    assert!(unsafe { fgets(std::ptr::null_mut(), 8, stream) }.is_null());

    let mut buf = [0_i8; 8];
    // SAFETY: non-positive size is rejected.
    assert!(unsafe { fgets(buf.as_mut_ptr(), 0, stream) }.is_null());
    // SAFETY: non-positive size is rejected.
    assert!(unsafe { fgets(buf.as_mut_ptr(), -1, stream) }.is_null());

    // SAFETY: `stream` is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn snprintf_truncates_and_reports_full_length() {
    let mut buf = [0_i8; 5];

    // SAFETY: destination is writable; format string is valid C string.
    let written = unsafe { snprintf(buf.as_mut_ptr(), buf.len(), c"abcdef".as_ptr()) };
    assert_eq!(written, 6);

    // SAFETY: snprintf guarantees NUL-termination when size > 0.
    let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(out.to_bytes(), b"abcd");
}

#[test]
fn sprintf_formats_integer_and_string_arguments() {
    let mut buf = [0_i8; 64];

    // SAFETY: destination is writable; variadic args match format specifiers.
    let written = unsafe {
        sprintf(
            buf.as_mut_ptr(),
            c"x=%d %s".as_ptr(),
            17_i32,
            c"ok".as_ptr(),
        )
    };
    assert_eq!(written, 7);

    // SAFETY: sprintf writes a trailing NUL on success.
    let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(out.to_bytes(), b"x=17 ok");
}

#[test]
fn fprintf_formats_and_persists_to_stream() {
    let path = temp_path("fprintf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: path/mode pointers are valid C strings.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: stream is valid; variadic args match format specifiers.
    let written = unsafe { fprintf(stream, c"v=%u:%c".as_ptr(), 42_u32, b'Z' as i32) };
    assert_eq!(written, 6);
    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);

    let bytes = fs::read(&path).expect("fprintf output file should exist");
    assert_eq!(bytes, b"v=42:Z");
    let _ = fs::remove_file(path);
}

#[test]
fn printf_writes_to_redirected_stdout() {
    let _guard = STDOUT_REDIRECT_LOCK
        .lock()
        .expect("stdout redirect lock should not be poisoned");

    let path = temp_path("printf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: path pointer is valid and open mode bits are valid.
    let out_fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
            0o600,
        )
    };
    assert!(out_fd >= 0);

    // SAFETY: dup/dup2/close operate on valid fds.
    let saved_stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
    assert!(saved_stdout >= 0);
    // SAFETY: redirect stdout to the temp file.
    assert_eq!(
        unsafe { libc::dup2(out_fd, libc::STDOUT_FILENO) },
        libc::STDOUT_FILENO
    );

    // SAFETY: variadic args match the format string.
    let written = unsafe { printf(c"printf-%d\n".as_ptr(), 9_i32) };
    assert_eq!(written, 9);

    // SAFETY: restore stdout and close descriptors.
    unsafe {
        libc::dup2(saved_stdout, libc::STDOUT_FILENO);
        libc::close(saved_stdout);
        libc::close(out_fd);
    }

    let bytes = fs::read(&path).expect("redirected printf output file should exist");
    assert_eq!(bytes, b"printf-9\n");
    let _ = fs::remove_file(path);
}
