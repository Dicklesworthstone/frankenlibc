#![cfg(target_os = "linux")]

//! Integration tests for `<stdio.h>` ABI entrypoints.

use std::ffi::{CStr, CString};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi::{
    asprintf, dprintf, fclose, fdopen, fflush, fgetc, fgetc_unlocked, fgetpos, fgetpos64, fgets,
    fileno, flockfile, fopen, fopen64, fprintf, fputc, fputc_unlocked, fputs, fread, freopen,
    fseek, fseeko64, fsetpos, fsetpos64, ftello64, ftrylockfile, funlockfile, fwrite, getc,
    getc_unlocked, getdelim, getline, printf, putc, putc_unlocked, remove as stdio_remove, setbuf,
    setlinebuf, setvbuf, snprintf, sprintf, tmpfile, tmpnam, ungetc,
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
    assert!(
        bytes
            .windows(b"printf-9\n".len())
            .any(|window| window == b"printf-9\n"),
        "redirected stdout should contain printf payload; got bytes={bytes:?}"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn dprintf_writes_to_fd() {
    let path = temp_path("dprintf");
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

    // SAFETY: file descriptor is valid and variadic args match format string.
    let written = unsafe { dprintf(out_fd, c"dprintf-%u".as_ptr(), 77_u32) };
    assert_eq!(written, 10);

    // SAFETY: file descriptor was returned by open and is still owned here.
    unsafe {
        libc::close(out_fd);
    }

    let bytes = fs::read(&path).expect("dprintf output file should exist");
    assert_eq!(bytes, b"dprintf-77");
    let _ = fs::remove_file(path);
}

#[test]
fn asprintf_allocates_and_formats_output() {
    let mut out: *mut i8 = std::ptr::null_mut();
    // SAFETY: out-pointer and format are valid; variadic args match specifiers.
    let written = unsafe { asprintf(&mut out, c"asprintf-%d:%s".as_ptr(), 55_i32, c"ok".as_ptr()) };
    assert_eq!(written, 14);
    assert!(!out.is_null());

    // SAFETY: asprintf returns a NUL-terminated allocated string on success.
    let rendered = unsafe { CStr::from_ptr(out) };
    assert_eq!(rendered.to_bytes(), b"asprintf-55:ok");

    // SAFETY: pointer was allocated by asprintf and is released once here.
    unsafe { libc::free(out.cast()) };
}

#[test]
fn asprintf_rejects_null_arguments() {
    let mut out: *mut i8 = std::ptr::null_mut();
    // SAFETY: null out-pointer is rejected by contract.
    assert_eq!(unsafe { asprintf(std::ptr::null_mut(), c"x".as_ptr()) }, -1);
    // SAFETY: null format pointer is rejected by contract.
    assert_eq!(unsafe { asprintf(&mut out, std::ptr::null()) }, -1);
}

#[test]
fn getc_and_putc_behave_like_fgetc_fputc() {
    let path = temp_path("getc_putc");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: stream is valid and writable.
    assert_eq!(unsafe { putc(b'X' as i32, stream) }, b'X' as i32);
    assert_eq!(unsafe { putc(b'Y' as i32, stream) }, b'Y' as i32);
    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    // SAFETY: stream is valid and readable.
    assert_eq!(unsafe { getc(stream) }, b'X' as i32);
    assert_eq!(unsafe { getc(stream) }, b'Y' as i32);
    // At EOF.
    assert_eq!(unsafe { getc(stream) }, libc::EOF);

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn unlocked_stdio_variants_follow_locked_semantics() {
    let path = temp_path("unlocked");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: lock helpers are valid on an open stream in this phase contract.
    unsafe { flockfile(stream) };
    assert_eq!(unsafe { ftrylockfile(stream) }, 0);

    // SAFETY: stream is valid and writable.
    assert_eq!(unsafe { fputc_unlocked(b'Q' as i32, stream) }, b'Q' as i32);
    assert_eq!(unsafe { putc_unlocked(b'R' as i32, stream) }, b'R' as i32);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    // SAFETY: stream is valid and readable.
    assert_eq!(unsafe { fgetc_unlocked(stream) }, b'Q' as i32);
    assert_eq!(unsafe { getc_unlocked(stream) }, b'R' as i32);
    assert_eq!(unsafe { getc_unlocked(stream) }, libc::EOF);
    unsafe { funlockfile(stream) };

    assert_eq!(unsafe { fclose(stream) }, 0);

    // SAFETY: null stream is rejected in this phase contract.
    assert_eq!(unsafe { ftrylockfile(std::ptr::null_mut()) }, -1);
    let _ = fs::remove_file(path);
}

#[test]
fn setlinebuf_is_callable_for_valid_streams() {
    let path = temp_path("setlinebuf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: setlinebuf is a valid pre-I/O operation for this stream.
    unsafe { setlinebuf(stream) };
    assert_eq!(unsafe { fputc(b'X' as i32, stream) }, b'X' as i32);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fclose(stream) }, 0);

    let bytes = fs::read(&path).expect("setlinebuf file should exist");
    assert_eq!(bytes, b"X");
    let _ = fs::remove_file(path);
}

#[test]
fn stdio_64bit_aliases_match_base_contracts() {
    let path = temp_path("stdio64");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen64(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // SAFETY: stream is valid and writable.
    assert_eq!(unsafe { fputs(c"ABCDE".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseeko64(stream, 0, libc::SEEK_SET) }, 0);
    assert_eq!(unsafe { ftello64(stream) }, 0);

    // Advance by reading two characters.
    assert_eq!(unsafe { fgetc(stream) }, b'A' as i32);
    assert_eq!(unsafe { fgetc(stream) }, b'B' as i32);

    // Save 64-bit position.
    let mut pos = unsafe { std::mem::zeroed::<libc::fpos_t>() };
    let pos_ptr = (&mut pos as *mut libc::fpos_t).cast();
    assert_eq!(unsafe { fgetpos64(stream, pos_ptr) }, 0);

    // Consume two more bytes, then restore.
    assert_eq!(unsafe { fgetc(stream) }, b'C' as i32);
    assert_eq!(unsafe { fgetc(stream) }, b'D' as i32);
    let pos_const_ptr = (&pos as *const libc::fpos_t).cast();
    assert_eq!(unsafe { fsetpos64(stream, pos_const_ptr) }, 0);
    assert_eq!(unsafe { fgetc(stream) }, b'C' as i32);

    // SAFETY: null position pointers are rejected.
    assert_eq!(unsafe { fgetpos64(stream, std::ptr::null_mut()) }, -1);
    assert_eq!(unsafe { fsetpos64(stream, std::ptr::null()) }, -1);

    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn fgetpos_fsetpos_save_and_restore_position() {
    let path = temp_path("fpos");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // Write some data.
    // SAFETY: stream is valid and writable.
    assert_eq!(unsafe { fputs(c"ABCDE".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    // Read 2 chars to advance position.
    assert_eq!(unsafe { fgetc(stream) }, b'A' as i32);
    assert_eq!(unsafe { fgetc(stream) }, b'B' as i32);

    // Save position (should be at offset 2).
    let mut pos = unsafe { std::mem::zeroed::<libc::fpos_t>() };
    // SAFETY: stream is valid and pos is a valid fpos_t.
    assert_eq!(unsafe { fgetpos(stream, &mut pos) }, 0);

    // Read 2 more chars.
    assert_eq!(unsafe { fgetc(stream) }, b'C' as i32);
    assert_eq!(unsafe { fgetc(stream) }, b'D' as i32);

    // Restore saved position (back to offset 2).
    // SAFETY: pos was saved by fgetpos.
    assert_eq!(unsafe { fsetpos(stream, &pos) }, 0);

    // Should read 'C' again.
    assert_eq!(unsafe { fgetc(stream) }, b'C' as i32);

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn fgetpos_rejects_null_arguments() {
    let path = temp_path("fpos_null");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let mut pos = unsafe { std::mem::zeroed::<libc::fpos_t>() };
    // SAFETY: null stream is rejected.
    assert_eq!(unsafe { fgetpos(std::ptr::null_mut(), &mut pos) }, -1);
    // SAFETY: null pos is rejected.
    assert_eq!(unsafe { fgetpos(stream, std::ptr::null_mut()) }, -1);
    // SAFETY: null stream is rejected.
    assert_eq!(unsafe { fsetpos(std::ptr::null_mut(), &pos) }, -1);
    // SAFETY: null pos is rejected.
    assert_eq!(unsafe { fsetpos(stream, std::ptr::null()) }, -1);

    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn fdopen_wraps_existing_fd() {
    let path = temp_path("fdopen");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // Open a raw fd via libc.
    // SAFETY: path and flags are valid.
    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(fd >= 0);

    // Wrap fd as a FILE stream.
    // SAFETY: fd is valid and mode is a valid C string.
    let stream = unsafe { fdopen(fd, c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // Write through the stream.
    // SAFETY: stream is valid and writable.
    assert_eq!(unsafe { fputs(c"fdopen-test".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fclose(stream) }, 0);

    let bytes = fs::read(&path).expect("fdopen output should exist");
    assert_eq!(bytes, b"fdopen-test");

    let _ = fs::remove_file(path);
}

#[test]
fn fdopen_rejects_invalid_fd_and_null_mode() {
    // SAFETY: invalid fd is rejected.
    assert!(unsafe { fdopen(-1, c"r".as_ptr()) }.is_null());
    // SAFETY: null mode is rejected.
    assert!(unsafe { fdopen(0, std::ptr::null()) }.is_null());
}

#[test]
fn freopen_reopens_stream_with_new_file() {
    let path1 = temp_path("freopen1");
    let path2 = temp_path("freopen2");
    let _ = fs::remove_file(&path1);
    let _ = fs::remove_file(&path2);
    let path1_c = path_cstring(&path1);
    let path2_c = path_cstring(&path2);

    // Open first file.
    // SAFETY: pointers are valid C strings.
    let stream = unsafe { fopen(path1_c.as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null());
    assert_eq!(unsafe { fputs(c"file1".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);

    // Reopen the same stream onto a different file.
    // SAFETY: all pointers are valid C strings, stream is open.
    let reopened = unsafe { freopen(path2_c.as_ptr(), c"w".as_ptr(), stream) };
    assert!(!reopened.is_null());
    // Stream pointer identity is preserved.
    assert_eq!(reopened, stream);

    assert_eq!(unsafe { fputs(c"file2".as_ptr(), reopened) }, 0);
    assert_eq!(unsafe { fflush(reopened) }, 0);
    assert_eq!(unsafe { fclose(reopened) }, 0);

    let bytes1 = fs::read(&path1).expect("first file should exist");
    assert_eq!(bytes1, b"file1");
    let bytes2 = fs::read(&path2).expect("second file should exist");
    assert_eq!(bytes2, b"file2");

    let _ = fs::remove_file(path1);
    let _ = fs::remove_file(path2);
}

#[test]
fn remove_deletes_a_file() {
    let path = temp_path("remove");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"to_delete").expect("should write test file");
    assert!(path.exists());

    let path_c = path_cstring(&path);
    // SAFETY: pathname is a valid C string pointing to an existing file.
    assert_eq!(unsafe { stdio_remove(path_c.as_ptr()) }, 0);
    assert!(!path.exists());
}

#[test]
fn remove_rejects_null_and_nonexistent() {
    // SAFETY: null pathname is rejected.
    assert_eq!(unsafe { stdio_remove(std::ptr::null()) }, -1);

    // Non-existent file should fail.
    assert_eq!(
        unsafe { stdio_remove(c"/tmp/frankenlibc_no_such_file_ever".as_ptr()) },
        -1
    );
}

#[test]
fn getline_reads_complete_lines() {
    let path = temp_path("getline");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(unsafe { fputs(c"hello\nworld\n".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut lineptr: *mut i8 = std::ptr::null_mut();
    let mut n: usize = 0;

    // Read first line.
    // SAFETY: lineptr and n are valid pointers, stream is open.
    let len = unsafe { getline(&mut lineptr, &mut n, stream) };
    assert_eq!(len, 6); // "hello\n"
    assert!(!lineptr.is_null());
    let line1 = unsafe { CStr::from_ptr(lineptr) };
    assert_eq!(line1.to_bytes(), b"hello\n");

    // Read second line.
    let len = unsafe { getline(&mut lineptr, &mut n, stream) };
    assert_eq!(len, 6); // "world\n"
    let line2 = unsafe { CStr::from_ptr(lineptr) };
    assert_eq!(line2.to_bytes(), b"world\n");

    // At EOF.
    let len = unsafe { getline(&mut lineptr, &mut n, stream) };
    assert_eq!(len, -1);

    // SAFETY: lineptr was allocated by getline via malloc.
    unsafe { libc::free(lineptr.cast()) };
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn getdelim_reads_until_custom_delimiter() {
    let path = temp_path("getdelim");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // Write data with ';' as delimiter.
    assert_eq!(unsafe { fputs(c"alpha;beta;gamma".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut lineptr: *mut i8 = std::ptr::null_mut();
    let mut n: usize = 0;

    // Read until first ';'.
    let len = unsafe { getdelim(&mut lineptr, &mut n, b';' as i32, stream) };
    assert_eq!(len, 6); // "alpha;"
    let seg1 = unsafe { CStr::from_ptr(lineptr) };
    assert_eq!(seg1.to_bytes(), b"alpha;");

    // Read until next ';'.
    let len = unsafe { getdelim(&mut lineptr, &mut n, b';' as i32, stream) };
    assert_eq!(len, 5); // "beta;"
    let seg2 = unsafe { CStr::from_ptr(lineptr) };
    assert_eq!(seg2.to_bytes(), b"beta;");

    // Read remaining (no trailing ';', hits EOF).
    let len = unsafe { getdelim(&mut lineptr, &mut n, b';' as i32, stream) };
    assert_eq!(len, 5); // "gamma"
    let seg3 = unsafe { CStr::from_ptr(lineptr) };
    assert_eq!(seg3.to_bytes(), b"gamma");

    unsafe { libc::free(lineptr.cast()) };
    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn getdelim_rejects_null_arguments() {
    let path = temp_path("getdelim_null");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let mut lineptr: *mut i8 = std::ptr::null_mut();
    let mut n: usize = 0;

    // SAFETY: null lineptr is rejected.
    assert_eq!(
        unsafe { getdelim(std::ptr::null_mut(), &mut n, b'\n' as i32, stream) },
        -1
    );
    // SAFETY: null n is rejected.
    assert_eq!(
        unsafe { getdelim(&mut lineptr, std::ptr::null_mut(), b'\n' as i32, stream) },
        -1
    );
    // SAFETY: null stream is rejected.
    assert_eq!(
        unsafe { getdelim(&mut lineptr, &mut n, b'\n' as i32, std::ptr::null_mut()) },
        -1
    );

    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn tmpfile_creates_writable_anonymous_stream() {
    // SAFETY: tmpfile creates an anonymous temp file.
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    // Write and read back.
    assert_eq!(unsafe { fputs(c"tmpfile-test".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0_i8; 32];
    let out = unsafe { fgets(buf.as_mut_ptr(), buf.len() as i32, stream) };
    assert_eq!(out, buf.as_mut_ptr());
    let content = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(content.to_bytes(), b"tmpfile-test");

    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn tmpnam_generates_unique_names() {
    let mut buf1 = [0_i8; 64];
    let mut buf2 = [0_i8; 64];

    // SAFETY: buffers are 64 bytes, sufficient for tmpnam output.
    let p1 = unsafe { tmpnam(buf1.as_mut_ptr()) };
    let p2 = unsafe { tmpnam(buf2.as_mut_ptr()) };

    assert!(!p1.is_null());
    assert!(!p2.is_null());

    let name1 = unsafe { CStr::from_ptr(p1) };
    let name2 = unsafe { CStr::from_ptr(p2) };

    // Names should start with /tmp/.
    assert!(name1.to_bytes().starts_with(b"/tmp/"));
    assert!(name2.to_bytes().starts_with(b"/tmp/"));

    // Consecutive calls must produce different names.
    assert_ne!(name1, name2);
}

#[test]
fn tmpnam_null_uses_static_buffer() {
    // SAFETY: NULL s uses internal static buffer.
    let p1 = unsafe { tmpnam(std::ptr::null_mut()) };
    assert!(!p1.is_null());
    let name = unsafe { CStr::from_ptr(p1) };
    assert!(name.to_bytes().starts_with(b"/tmp/"));
}
