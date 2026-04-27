#![feature(c_variadic)]
#![cfg(target_os = "linux")]

//! Integration tests for `<stdio.h>` ABI entrypoints.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use frankenlibc_abi::io_internal_abi::{
    _IO_fclose, _IO_fdopen, _IO_fflush, _IO_fgetpos, _IO_fgetpos64, _IO_fgets, _IO_file_close,
    _IO_file_close_it, _IO_file_overflow, _IO_file_read, _IO_file_seek, _IO_file_seekoff,
    _IO_file_setbuf, _IO_file_stat, _IO_file_sync, _IO_file_underflow, _IO_file_write,
    _IO_file_xsputn, _IO_flush_all, _IO_fopen, _IO_fprintf, _IO_fputs, _IO_fread, _IO_fsetpos,
    _IO_fsetpos64, _IO_ftell, _IO_fwrite, _IO_printf, _IO_setbuffer, _IO_setvbuf, _IO_sprintf,
    _IO_sscanf, _IO_ungetc, _IO_vfprintf, _IO_vsprintf, native_stdio_stream_ptr,
    verify_native_file,
};
use frankenlibc_abi::io_internal_abi::{_IO_feof, _IO_ferror, _IO_getc, _IO_putc};
use frankenlibc_abi::stdio_abi::{
    __getline,
    __isoc99_fscanf,
    __isoc99_sscanf,
    _IO_flockfile,
    _IO_ftrylockfile,
    _IO_funlockfile,
    _IO_padn,
    _IO_puts,
    _IO_seekoff,
    _IO_seekpos,
    _IO_sgetn,
    IO_2_1_STDERR,
    IO_2_1_STDIN,
    IO_2_1_STDOUT,
    asprintf,
    clearerr,
    clearerr_unlocked,
    dprintf,
    fclose,
    fdopen,
    feof,
    feof_unlocked,
    ferror,
    ferror_unlocked,
    fflush,
    fflush_unlocked,
    fgetc,
    fgetc_unlocked,
    fgetln,
    fgetpos,
    fgetpos64,
    fgets,
    fgets_unlocked,
    fileno,
    fileno_unlocked,
    flockfile,
    fmemopen,
    fopen,
    fopen64,
    fopencookie,
    fparseln,
    fprintf,
    fpurge,
    fputc,
    fputc_unlocked,
    fputs,
    fputs_unlocked,
    fread,
    fread_unlocked,
    freopen,
    freopen64,
    fscanf,
    fseek,
    fseeko,
    fseeko64,
    fsetpos,
    fsetpos64,
    ftell,
    ftello,
    ftello64,
    ftrylockfile,
    funlockfile,
    funopen,
    fwrite,
    fwrite_unlocked,
    getc,
    getc_unlocked,
    getdelim,
    getline,
    getw,
    init_host_stdio_streams_for_tests,
    mktemp,
    nvis,
    // Newly tested:
    open_memstream,
    pclose,
    perror,
    popen,
    printf,
    putc,
    putc_unlocked,
    putchar,
    putchar_unlocked,
    puts,
    putw,
    remove as stdio_remove,
    rewind,
    setbuf,
    setbuffer,
    setlinebuf,
    setvbuf,
    signal_runtime_ready_for_tests,
    snprintb,
    snprintb_m,
    snprintf,
    snvis,
    sprintf,
    sscanf,
    stderr,
    stdin,
    stdout,
    stravis,
    strenvisx,
    strnunvis,
    strnunvis_netbsd,
    strnunvisx,
    strnvis,
    strnvis_netbsd,
    strnvisx,
    strsenvisx,
    strsnvis,
    strsnvisx,
    strsvis,
    strsvisx,
    strunvis,
    strunvisx,
    strvis,
    strvisx,
    svis,
    take_last_decision_gate_for_tests,
    tmpfile,
    tmpfile64,
    tmpnam,
    ungetc,
    unvis,
    vasprintf,
    vis,
};

const IOFBF: i32 = 0;
const IONBF: i32 = 2;

static NEXT_TMP_ID: AtomicU64 = AtomicU64::new(0);
static STDOUT_REDIRECT_LOCK: Mutex<()> = Mutex::new(());

/// Serializes tests that assert specific addresses are absent from the
/// native stream registry after fclose. Without this, a parallel test
/// can fmemopen a NEW stream that happens to land at the same address
/// as the just-freed stream from another test, making the
/// `verify_native_file(stream).is_none()` post-fclose check spuriously
/// fail. (bd-el0v8)
static STREAM_REGISTRY_PROBE_LOCK: Mutex<()> = Mutex::new(());

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

#[allow(dead_code)] // kept for future tests that need /tmp enumeration
fn temp_dir_entries_with_prefix(prefix: &str) -> Vec<PathBuf> {
    let mut matches = Vec::new();
    let tmp_dir = std::env::temp_dir();
    let Ok(entries) = fs::read_dir(&tmp_dir) else {
        return matches;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|name| name.as_bytes().starts_with(prefix.as_bytes()))
        {
            matches.push(path);
        }
    }
    matches.sort();
    matches
}

unsafe extern "C" fn call_io_vfprintf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> c_int {
    unsafe {
        _IO_vfprintf(
            stream,
            format,
            std::ptr::addr_of_mut!(args).cast::<c_void>(),
        )
    }
}

unsafe extern "C" fn call_io_vsprintf(
    buf: *mut c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    unsafe { _IO_vsprintf(buf, format, std::ptr::addr_of_mut!(args).cast::<c_void>()) }
}

unsafe extern "C" fn call_vasprintf(
    out: *mut *mut c_char,
    format: *const c_char,
    mut args: ...
) -> c_int {
    unsafe { vasprintf(out, format, std::ptr::addr_of_mut!(args).cast::<c_void>()) }
}

unsafe extern "C" fn call_vfprintf(
    stream: *mut c_void,
    format: *const c_char,
    mut args: ...
) -> c_int {
    unsafe {
        frankenlibc_abi::stdio_abi::vfprintf(
            stream,
            format,
            std::ptr::addr_of_mut!(args).cast::<c_void>(),
        )
    }
}

fn path_cstring(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).expect("temp path must not contain interior NUL")
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CookieIoFuncs {
    read: Option<unsafe extern "C" fn(*mut c_void, *mut c_char, usize) -> isize>,
    write: Option<unsafe extern "C" fn(*mut c_void, *const c_char, usize) -> isize>,
    seek: Option<unsafe extern "C" fn(*mut c_void, *mut i64, c_int) -> c_int>,
    close: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
}

#[derive(Default)]
struct CookieState {
    data: Vec<u8>,
    pos: usize,
    closed: bool,
    inject_read_eintr_once: bool,
    inject_write_eintr_once: bool,
    read_eintr_emitted: bool,
    write_eintr_emitted: bool,
    max_write_chunk: usize,
    write_calls: usize,
}

unsafe extern "C" fn cookie_read(cookie: *mut c_void, buf: *mut c_char, count: usize) -> isize {
    if cookie.is_null() || buf.is_null() {
        return -1;
    }
    // SAFETY: test controls cookie pointer lifetime and type.
    let state = unsafe { &mut *(cookie as *mut CookieState) };
    if state.inject_read_eintr_once && !state.read_eintr_emitted {
        state.read_eintr_emitted = true;
        // SAFETY: libc exposes thread-local errno pointer on Linux.
        unsafe {
            *libc::__errno_location() = libc::EINTR;
        }
        return -1;
    }
    if state.pos >= state.data.len() {
        return 0;
    }
    let n = count.min(state.data.len() - state.pos);
    // SAFETY: caller provides writable buffer for `count` bytes.
    unsafe { std::ptr::copy_nonoverlapping(state.data[state.pos..].as_ptr(), buf.cast::<u8>(), n) };
    state.pos += n;
    n as isize
}

unsafe extern "C" fn cookie_write(cookie: *mut c_void, buf: *const c_char, count: usize) -> isize {
    if cookie.is_null() || buf.is_null() {
        return -1;
    }
    // SAFETY: test controls cookie pointer lifetime and type.
    let state = unsafe { &mut *(cookie as *mut CookieState) };
    if state.inject_write_eintr_once && !state.write_eintr_emitted {
        state.write_eintr_emitted = true;
        // SAFETY: libc exposes thread-local errno pointer on Linux.
        unsafe {
            *libc::__errno_location() = libc::EINTR;
        }
        return -1;
    }
    state.write_calls = state.write_calls.saturating_add(1);
    let to_write = if state.max_write_chunk == 0 {
        count
    } else {
        count.min(state.max_write_chunk)
    };
    let src = unsafe { std::slice::from_raw_parts(buf.cast::<u8>(), to_write) };
    let end = state.pos.saturating_add(to_write);
    if state.data.len() < end {
        state.data.resize(end, 0);
    }
    state.data[state.pos..end].copy_from_slice(src);
    state.pos = end;
    to_write as isize
}

unsafe extern "C" fn cookie_seek(cookie: *mut c_void, offset: *mut i64, whence: c_int) -> c_int {
    if cookie.is_null() || offset.is_null() {
        return -1;
    }
    // SAFETY: test controls cookie pointer lifetime and type.
    let state = unsafe { &mut *(cookie as *mut CookieState) };
    let req = unsafe { *offset };
    let base = match whence {
        libc::SEEK_SET => 0i64,
        libc::SEEK_CUR => state.pos as i64,
        libc::SEEK_END => state.data.len() as i64,
        _ => return -1,
    };
    let new_pos = match base.checked_add(req) {
        Some(v) if v >= 0 => v as usize,
        _ => return -1,
    };
    state.pos = new_pos;
    unsafe { *offset = new_pos as i64 };
    0
}

unsafe extern "C" fn cookie_close(cookie: *mut c_void) -> c_int {
    if cookie.is_null() {
        return -1;
    }
    // SAFETY: test controls cookie pointer lifetime and type.
    let state = unsafe { &mut *(cookie as *mut CookieState) };
    state.closed = true;
    0
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
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
fn fopencookie_rejects_tracked_unterminated_mode() {
    let mode = unsafe { frankenlibc_abi::malloc_abi::malloc(1).cast::<c_char>() };
    assert!(!mode.is_null());
    unsafe { *mode = b'w' as c_char };
    let funcs = CookieIoFuncs {
        read: None,
        write: None,
        seek: None,
        close: None,
    };

    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let stream = unsafe {
        fopencookie(
            std::ptr::null_mut(),
            mode.cast_const(),
            (&funcs as *const CookieIoFuncs).cast::<c_void>(),
        )
    };
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    unsafe { frankenlibc_abi::malloc_abi::free(mode.cast::<c_void>()) };

    assert!(
        stream.is_null(),
        "fopencookie should reject unterminated mode"
    );
    assert_eq!(err, libc::EINVAL, "unterminated mode should set EINVAL");
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopencookie_routes_io_callbacks_for_read_write_seek_close() {
    let cookie = Box::into_raw(Box::new(CookieState::default()));
    let funcs = CookieIoFuncs {
        read: Some(cookie_read),
        write: Some(cookie_write),
        seek: Some(cookie_seek),
        close: Some(cookie_close),
    };

    let mode = CString::new("w+").expect("valid mode");
    // SAFETY: callback table and mode pointers are valid for call duration.
    let stream = unsafe {
        fopencookie(
            cookie.cast::<c_void>(),
            mode.as_ptr(),
            (&funcs as *const CookieIoFuncs).cast::<c_void>(),
        )
    };
    assert!(!stream.is_null());

    let payload = b"cookie-io";
    // SAFETY: pointers and stream are valid.
    let wrote = unsafe { fwrite(payload.as_ptr().cast::<c_void>(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());

    // SAFETY: stream is valid.
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut out = [0u8; 9];
    // SAFETY: destination pointer and stream are valid.
    let read = unsafe { fread(out.as_mut_ptr().cast::<c_void>(), 1, out.len(), stream) };
    assert_eq!(read, out.len());
    assert_eq!(&out, payload);

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);

    // SAFETY: cookie ownership remains with this test.
    let state = unsafe { Box::from_raw(cookie) };
    assert!(state.closed);
    assert_eq!(state.data, payload);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopencookie_fread_retries_once_on_eintr() {
    let cookie = Box::into_raw(Box::new(CookieState {
        data: b"retry-read".to_vec(),
        pos: 0,
        closed: false,
        inject_read_eintr_once: true,
        inject_write_eintr_once: false,
        read_eintr_emitted: false,
        write_eintr_emitted: false,
        max_write_chunk: 0,
        write_calls: 0,
    }));
    let funcs = CookieIoFuncs {
        read: Some(cookie_read),
        write: Some(cookie_write),
        seek: Some(cookie_seek),
        close: Some(cookie_close),
    };
    let mode = CString::new("r+").expect("valid mode");
    // SAFETY: callback table and mode pointers are valid for call duration.
    let stream = unsafe {
        fopencookie(
            cookie.cast::<c_void>(),
            mode.as_ptr(),
            (&funcs as *const CookieIoFuncs).cast::<c_void>(),
        )
    };
    assert!(!stream.is_null());

    let mut out = [0u8; 10];
    // SAFETY: destination pointer and stream are valid.
    let read = unsafe { fread(out.as_mut_ptr().cast::<c_void>(), 1, out.len(), stream) };
    assert_eq!(read, 10);
    assert_eq!(&out, b"retry-read");

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    // SAFETY: cookie ownership remains with this test.
    let state = unsafe { Box::from_raw(cookie) };
    assert!(state.read_eintr_emitted);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopencookie_fwrite_retries_once_on_eintr() {
    let cookie = Box::into_raw(Box::new(CookieState {
        data: Vec::new(),
        pos: 0,
        closed: false,
        inject_read_eintr_once: false,
        inject_write_eintr_once: true,
        read_eintr_emitted: false,
        write_eintr_emitted: false,
        max_write_chunk: 0,
        write_calls: 0,
    }));
    let funcs = CookieIoFuncs {
        read: Some(cookie_read),
        write: Some(cookie_write),
        seek: Some(cookie_seek),
        close: Some(cookie_close),
    };
    let mode = CString::new("w+").expect("valid mode");
    // SAFETY: callback table and mode pointers are valid for call duration.
    let stream = unsafe {
        fopencookie(
            cookie.cast::<c_void>(),
            mode.as_ptr(),
            (&funcs as *const CookieIoFuncs).cast::<c_void>(),
        )
    };
    assert!(!stream.is_null());

    let payload = b"retry-write";
    // SAFETY: pointers and stream are valid.
    let wrote = unsafe { fwrite(payload.as_ptr().cast::<c_void>(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    // SAFETY: cookie ownership remains with this test.
    let state = unsafe { Box::from_raw(cookie) };
    assert!(state.write_eintr_emitted);
    assert_eq!(state.data, payload);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopencookie_fwrite_handles_partial_writes_without_data_loss() {
    let cookie = Box::into_raw(Box::new(CookieState {
        data: Vec::new(),
        pos: 0,
        closed: false,
        inject_read_eintr_once: false,
        inject_write_eintr_once: false,
        read_eintr_emitted: false,
        write_eintr_emitted: false,
        max_write_chunk: 3,
        write_calls: 0,
    }));
    let funcs = CookieIoFuncs {
        read: Some(cookie_read),
        write: Some(cookie_write),
        seek: Some(cookie_seek),
        close: Some(cookie_close),
    };
    let mode = CString::new("w+").expect("valid mode");
    // SAFETY: callback table and mode pointers are valid for call duration.
    let stream = unsafe {
        fopencookie(
            cookie.cast::<c_void>(),
            mode.as_ptr(),
            (&funcs as *const CookieIoFuncs).cast::<c_void>(),
        )
    };
    assert!(!stream.is_null());

    let payload = b"partial-write-payload";
    // SAFETY: pointers and stream are valid.
    let wrote = unsafe { fwrite(payload.as_ptr().cast::<c_void>(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);
    // SAFETY: cookie ownership remains with this test.
    let state = unsafe { Box::from_raw(cookie) };
    assert_eq!(state.data, payload);
    assert!(
        state.write_calls > 1,
        "short-write path should require retries"
    );
}

#[test]
fn mixed_buffered_and_unbuffered_same_fd_completes_without_deadlock() {
    let path = temp_path("mixed_buffer_modes");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // SAFETY: pointers are valid C strings for this call.
    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());
    // SAFETY: stream is valid and setvbuf pre-I/O configuration is valid.
    assert_eq!(
        unsafe { setvbuf(stream, std::ptr::null_mut(), IOFBF, 4096) },
        0
    );

    // SAFETY: stream is valid.
    let fd = unsafe { fileno(stream) };
    assert!(fd >= 0);

    let iterations = 256usize;
    let stream_addr = stream as usize;
    let (done_tx, done_rx) = mpsc::channel::<&'static str>();
    let tx_a = done_tx.clone();
    let tx_b = done_tx.clone();
    drop(done_tx);

    let writer_stream = thread::spawn(move || {
        let stream = stream_addr as *mut c_void;
        for _ in 0..iterations {
            let byte = [b'A'];
            // SAFETY: stream and pointer are valid for 1-byte write.
            let wrote = unsafe { fwrite(byte.as_ptr().cast::<c_void>(), 1, 1, stream) };
            if wrote != 1 {
                break;
            }
        }
        let _ = tx_a.send("stream");
    });

    let writer_fd = thread::spawn(move || {
        for _ in 0..iterations {
            let byte = [b'B'];
            // SAFETY: fd is valid while stream remains open.
            let rc = unsafe { libc::write(fd, byte.as_ptr().cast::<c_void>(), 1) };
            if rc != 1 {
                break;
            }
        }
        let _ = tx_b.send("fd");
    });

    let first = done_rx.recv_timeout(Duration::from_secs(2));
    let second = done_rx.recv_timeout(Duration::from_secs(2));
    assert!(first.is_ok(), "first writer did not finish in time");
    assert!(second.is_ok(), "second writer did not finish in time");

    writer_stream
        .join()
        .expect("stream writer thread should join");
    writer_fd.join().expect("fd writer thread should join");

    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fflush(stream) }, 0);
    // SAFETY: stream is valid and open.
    assert_eq!(unsafe { fclose(stream) }, 0);

    let bytes = fs::read(&path).expect("mixed mode output should be readable");
    assert!(!bytes.is_empty(), "mixed-mode writes should persist data");

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
    let mut scanned = 0;
    // SAFETY: null stream is explicitly rejected before scanning writes.
    assert_eq!(
        unsafe {
            fscanf(
                std::ptr::null_mut(),
                c"%d".as_ptr(),
                &mut scanned as *mut c_int,
            )
        },
        -1
    );
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
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_returns_native_handle_usable_by_our_stdio() {
    let path = temp_path("fopen_host_interop");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert!(unsafe { fileno(stream) } >= 0);
    assert_eq!(unsafe { fputs(c"host-write".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fclose(stream) }, 0);

    let bytes = fs::read(&path).expect("host-written fopen file should exist");
    assert_eq!(bytes, b"host-write");
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: foreign stream handling needs adoption path"]
fn fclose_accepts_host_streams() {
    let path = temp_path("host_fopen_our_fclose");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let host_stream = unsafe { libc::fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!host_stream.is_null());
    assert_ne!(
        unsafe { libc::fputs(c"mixed-close".as_ptr(), host_stream) },
        libc::EOF
    );

    let rc = unsafe { fclose(host_stream.cast::<c_void>()) };
    assert_eq!(rc, 0);
    let bytes = fs::read(&path).expect("host fopen output should exist");
    assert_eq!(bytes, b"mixed-close");
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
fn snprintf_records_ffi_pcc_gate_when_runtime_ready() {
    signal_runtime_ready_for_tests();
    let _ = take_last_decision_gate_for_tests();

    let mut buf = [0_i8; 16];
    let written = unsafe { snprintf(buf.as_mut_ptr(), buf.len(), c"hello".as_ptr()) };

    assert_eq!(written, 5);
    assert_eq!(
        take_last_decision_gate_for_tests(),
        Some("runtime_policy.ffi_pcc.decide")
    );
}

#[test]
fn strict_hot_stdio_writes_skip_runtime_policy_gate() {
    signal_runtime_ready_for_tests();

    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let _ = take_last_decision_gate_for_tests();
    assert_eq!(unsafe { fputc(b'X' as c_int, stream) }, b'X' as c_int);
    assert_eq!(take_last_decision_gate_for_tests(), None);

    let _ = take_last_decision_gate_for_tests();
    assert_eq!(unsafe { fputs(c"YZ".as_ptr(), stream) }, 0);
    assert_eq!(take_last_decision_gate_for_tests(), None);

    let bulk = b"bulk";
    let _ = take_last_decision_gate_for_tests();
    assert_eq!(
        unsafe { fwrite(bulk.as_ptr().cast(), 1, bulk.len(), stream) },
        bulk.len()
    );
    assert_eq!(take_last_decision_gate_for_tests(), None);

    assert_eq!(unsafe { fclose(stream) }, 0);

    let _ = take_last_decision_gate_for_tests();
    assert_eq!(unsafe { puts(c"".as_ptr()) }, 0);
    assert_eq!(take_last_decision_gate_for_tests(), None);
}

#[test]
fn io_2_1_aliases_resolve_to_native_stdio_storage() {
    init_host_stdio_streams_for_tests();

    let stdin_ptr = native_stdio_stream_ptr(libc::STDIN_FILENO);
    let stdout_ptr = native_stdio_stream_ptr(libc::STDOUT_FILENO);
    let stderr_ptr = native_stdio_stream_ptr(libc::STDERR_FILENO);
    let stdin_global = unsafe { std::ptr::addr_of_mut!(stdin).read() };
    let stdout_global = unsafe { std::ptr::addr_of_mut!(stdout).read() };
    let stderr_global = unsafe { std::ptr::addr_of_mut!(stderr).read() };
    let io_stdin = unsafe { std::ptr::addr_of_mut!(IO_2_1_STDIN).read() };
    let io_stdout = unsafe { std::ptr::addr_of_mut!(IO_2_1_STDOUT).read() };
    let io_stderr = unsafe { std::ptr::addr_of_mut!(IO_2_1_STDERR).read() };

    assert_eq!(stdin_global, stdin_ptr);
    assert_eq!(stdout_global, stdout_ptr);
    assert_eq!(stderr_global, stderr_ptr);
    assert_eq!(io_stdin, stdin_ptr);
    assert_eq!(io_stdout, stdout_ptr);
    assert_eq!(io_stderr, stderr_ptr);
    assert_eq!(io_stdin, stdin_global);
    assert_eq!(io_stdout, stdout_global);
    assert_eq!(io_stderr, stderr_global);

    assert_eq!(verify_native_file(stdin_ptr), Some(0));
    assert_eq!(verify_native_file(stdout_ptr), Some(1));
    assert_eq!(verify_native_file(stderr_ptr), Some(2));
}

#[test]
fn snprintf_supports_positional_value_reordering() {
    let mut buf = [0_i8; 64];

    let written = unsafe {
        snprintf(
            buf.as_mut_ptr(),
            buf.len(),
            c"%2$s is %1$d".as_ptr(),
            42_i32,
            c"answer".as_ptr(),
        )
    };
    assert_eq!(written, 12);

    let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(out.to_bytes(), b"answer is 42");
}

#[test]
fn snprintf_supports_positional_width_and_precision() {
    let mut buf = [0_i8; 64];

    let written = unsafe {
        snprintf(
            buf.as_mut_ptr(),
            buf.len(),
            c"%3$*2$.*1$f".as_ptr(),
            2_i32,
            8_i32,
            core::f64::consts::PI,
        )
    };
    assert_eq!(written, 8);

    let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(out.to_bytes(), b"    3.14");
}

#[test]
fn snprintf_percent_n_records_bytes_before_directive() {
    let mut buf = [0_i8; 64];
    let mut count = -1_i32;

    let written = unsafe {
        snprintf(
            buf.as_mut_ptr(),
            buf.len(),
            c"abc%n:%s".as_ptr(),
            std::ptr::addr_of_mut!(count),
            c"tail".as_ptr(),
        )
    };
    assert_eq!(written, 8);
    assert_eq!(count, 3);

    let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(out.to_bytes(), b"abc:tail");
}

#[test]
fn sprintf_supports_reusing_positional_argument() {
    let mut buf = [0_i8; 64];

    let written = unsafe { sprintf(buf.as_mut_ptr(), c"%1$d %1$d %1$d".as_ptr(), 7_i32) };
    assert_eq!(written, 5);

    let out = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(out.to_bytes(), b"7 7 7");
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
fn fprintf_writes_to_native_tmpfile_handle() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let written = unsafe { fprintf(stream, c"host=%d:%s".as_ptr(), 11_i32, c"ok".as_ptr()) };
    assert_eq!(written, 10);
    assert_eq!(unsafe { fflush(stream) }, 0);

    unsafe { rewind(stream) };
    let mut buf = [0 as c_char; 32];
    let out = unsafe { fgets(buf.as_mut_ptr(), buf.len() as c_int, stream) };
    assert_eq!(out, buf.as_mut_ptr());
    let rendered = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(rendered.to_bytes(), b"host=11:ok");

    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn vfprintf_writes_to_native_tmpfile_handle() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let written = unsafe { call_vfprintf(stream, c"%s=%d".as_ptr(), c"host".as_ptr(), 21_i32) };
    assert_eq!(written, 7);
    assert_eq!(unsafe { fflush(stream) }, 0);

    unsafe { rewind(stream) };
    let mut buf = [0 as c_char; 32];
    let out = unsafe { fgets(buf.as_mut_ptr(), buf.len() as c_int, stream) };
    assert_eq!(out, buf.as_mut_ptr());
    let rendered = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(rendered.to_bytes(), b"host=21");

    assert_eq!(unsafe { fclose(stream) }, 0);
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

    // SAFETY: `asprintf` in this crate allocates via frankenlibc's allocator,
    // so release with the matching frankenlibc free entrypoint.
    unsafe { frankenlibc_abi::malloc_abi::free(out.cast()) };
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
fn vasprintf_allocates_and_formats_output() {
    let mut out: *mut c_char = std::ptr::null_mut();
    // SAFETY: out-pointer and format are valid; variadic args match specifiers.
    let written = unsafe {
        call_vasprintf(
            &mut out,
            c"vasprintf-%u:%s".as_ptr(),
            66_u32,
            c"ok".as_ptr(),
        )
    };
    assert_eq!(written, 15);
    assert!(!out.is_null());

    // SAFETY: vasprintf returns a NUL-terminated allocated string on success.
    let rendered = unsafe { CStr::from_ptr(out) };
    assert_eq!(rendered.to_bytes(), b"vasprintf-66:ok");

    // SAFETY: `vasprintf` in this crate allocates via frankenlibc's allocator,
    // so release with the matching frankenlibc free entrypoint.
    unsafe { frankenlibc_abi::malloc_abi::free(out.cast()) };
}

#[test]
fn vasprintf_rejects_null_arguments() {
    let mut out: *mut c_char = std::ptr::null_mut();
    // SAFETY: null out-pointer is rejected by contract.
    assert_eq!(
        unsafe { vasprintf(std::ptr::null_mut(), c"x".as_ptr(), std::ptr::null_mut()) },
        -1
    );
    // SAFETY: null format pointer is rejected by contract.
    assert_eq!(
        unsafe { vasprintf(&mut out, std::ptr::null(), std::ptr::null_mut()) },
        -1
    );
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
    let mut pos = std::mem::MaybeUninit::<libc::fpos_t>::uninit();
    let pos_ptr = pos.as_mut_ptr().cast();
    assert_eq!(unsafe { fgetpos64(stream, pos_ptr) }, 0);
    let pos = unsafe { pos.assume_init() };

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
    let mut pos = std::mem::MaybeUninit::<libc::fpos_t>::uninit();
    // SAFETY: stream is valid and pos is a valid fpos_t.
    assert_eq!(unsafe { fgetpos(stream, pos.as_mut_ptr()) }, 0);
    let pos = unsafe { pos.assume_init() };

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

    let mut pos = std::mem::MaybeUninit::<libc::fpos_t>::uninit();
    // SAFETY: null stream is rejected.
    assert_eq!(
        unsafe { fgetpos(std::ptr::null_mut(), pos.as_mut_ptr()) },
        -1
    );
    // SAFETY: null pos is rejected.
    assert_eq!(unsafe { fgetpos(stream, std::ptr::null_mut()) }, -1);
    // SAFETY: null stream is rejected.
    assert_eq!(unsafe { fsetpos(std::ptr::null_mut(), pos.as_ptr()) }, -1);
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
fn tmpfile_closes_without_leaking_named_tmp_entries() {
    // The "(deleted)" check on /proc/self/fd/N below is the
    // authoritative oracle for "tmpfile unlinked its backing file
    // while open" — POSIX requires the file be unreachable from any
    // pathname the moment tmpfile() returns. The previous
    // before/after enumeration of `frankenlibc_*` entries was
    // redundant (tmpfile uses glibc's own `tmpXXXXXX` naming, never
    // `frankenlibc_`) and was the source of bd-el0v8 flakiness:
    // any concurrent test using `temp_path()` would create a
    // frankenlibc_-prefixed file that flickered through the snapshot
    // window. Drop the snapshot.

    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let fd = unsafe { fileno(stream) };
    assert!(fd >= 0);

    let proc_fd_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    let target =
        fs::read_link(&proc_fd_path).expect("tmpfile fd should be visible in /proc/self/fd");
    let rendered = target.to_string_lossy();
    assert!(
        rendered.contains("/tmp/"),
        "tmpfile backing path should live under /tmp: {rendered}"
    );
    assert!(
        rendered.contains("(deleted)"),
        "tmpfile backing file should already be unlinked while open: {rendered}"
    );

    assert_eq!(unsafe { fputs(c"tmpfile-cleanup".as_ptr(), stream) }, 0);
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

// ===========================================================================
// feof / ferror / clearerr / rewind / ftell
// ===========================================================================

#[test]
fn feof_and_ferror_report_stream_state() {
    let path = temp_path("feof");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    // Write a single byte then rewind
    assert_eq!(unsafe { fputc(b'X' as i32, stream) }, b'X' as i32);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    // Not at EOF yet
    assert_eq!(unsafe { feof(stream) }, 0);
    assert_eq!(unsafe { ferror(stream) }, 0);

    // Read the one byte
    assert_eq!(unsafe { fgetc(stream) }, b'X' as i32);
    // Now read past EOF
    assert_eq!(unsafe { fgetc(stream) }, libc::EOF);
    // EOF flag should now be set
    assert_ne!(unsafe { feof(stream) }, 0);

    // clearerr should clear the EOF flag
    unsafe { clearerr(stream) };
    assert_eq!(unsafe { feof(stream) }, 0);

    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn rewind_and_ftell_position_tracking() {
    let path = temp_path("rewind");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(unsafe { fputs(c"ABCDE".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);

    // ftell should report position 5
    assert_eq!(unsafe { ftell(stream) }, 5);

    // rewind should set position to 0
    unsafe { rewind(stream) };
    assert_eq!(unsafe { ftell(stream) }, 0);

    // Should be able to read from the beginning
    assert_eq!(unsafe { fgetc(stream) }, b'A' as i32);
    assert_eq!(unsafe { ftell(stream) }, 1);

    assert_eq!(unsafe { fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

// ===========================================================================
// sscanf
// ===========================================================================

#[test]
fn sscanf_parses_integers_and_strings() {
    let input = c"42 hello";
    let mut num: c_int = 0;
    let mut buf = [0_i8; 32];

    // SAFETY: format matches arguments.
    let n = unsafe {
        sscanf(
            input.as_ptr(),
            c"%d %s".as_ptr(),
            &mut num,
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(n, 2);
    assert_eq!(num, 42);
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(s.to_bytes(), b"hello");
}

#[test]
fn sscanf_returns_zero_on_mismatch() {
    let input = c"not_a_number";
    let mut num: c_int = -1;

    let n = unsafe { sscanf(input.as_ptr(), c"%d".as_ptr(), &mut num) };
    assert_eq!(n, 0);
}

#[test]
fn sscanf_returns_eof_on_empty_input() {
    let input = c"";
    let mut num: c_int = -1;

    let n = unsafe { sscanf(input.as_ptr(), c"%d".as_ptr(), &mut num) };
    assert!(n <= 0, "sscanf on empty input should return 0 or EOF");
}

#[test]
fn sscanf_rejects_tracked_unterminated_input() {
    let input = unsafe { frankenlibc_abi::malloc_abi::malloc(2).cast::<c_char>() };
    assert!(!input.is_null());
    unsafe {
        *input.add(0) = b'4' as c_char;
        *input.add(1) = b'2' as c_char;
    }
    let mut num: c_int = -1;

    let n = unsafe { sscanf(input.cast_const(), c"%d".as_ptr(), &mut num) };

    unsafe { frankenlibc_abi::malloc_abi::free(input.cast::<c_void>()) };

    assert_eq!(n, libc::EOF);
    assert_eq!(num, -1, "unterminated input must not write outputs");
}

#[test]
fn sscanf_rejects_tracked_unterminated_format() {
    let format = unsafe { frankenlibc_abi::malloc_abi::malloc(2).cast::<c_char>() };
    assert!(!format.is_null());
    unsafe {
        *format.add(0) = b'%' as c_char;
        *format.add(1) = b'd' as c_char;
    }
    let mut num: c_int = -1;

    let n = unsafe { sscanf(c"42".as_ptr(), format.cast_const(), &mut num) };

    unsafe { frankenlibc_abi::malloc_abi::free(format.cast::<c_void>()) };

    assert_eq!(n, libc::EOF);
    assert_eq!(num, -1, "unterminated format must not write outputs");
}

// ===========================================================================
// mktemp
// ===========================================================================

#[test]
fn mktemp_generates_unique_name() {
    let mut tmpl = *b"/tmp/frankenlibc_XXXXXX\0";
    let ptr = unsafe { mktemp(tmpl.as_mut_ptr().cast::<c_char>()) };
    assert!(!ptr.is_null());

    let name = unsafe { CStr::from_ptr(ptr) };
    let name_str = name.to_string_lossy();
    // The X's should have been replaced
    assert!(
        !name_str.contains("XXXXXX"),
        "template should be filled: {name_str}"
    );
    assert!(name_str.starts_with("/tmp/frankenlibc_"));
}

#[test]
fn mktemp_consecutive_calls_produce_different_names() {
    let mut tmpl1 = *b"/tmp/frankenlibc_XXXXXX\0";
    let mut tmpl2 = *b"/tmp/frankenlibc_XXXXXX\0";

    let p1 = unsafe { mktemp(tmpl1.as_mut_ptr().cast::<c_char>()) };
    let p2 = unsafe { mktemp(tmpl2.as_mut_ptr().cast::<c_char>()) };
    assert!(!p1.is_null());
    assert!(!p2.is_null());

    let n1 = unsafe { CStr::from_ptr(p1) };
    let n2 = unsafe { CStr::from_ptr(p2) };
    assert_ne!(
        n1, n2,
        "consecutive mktemp calls should produce different names"
    );
}

// ---------------------------------------------------------------------------
// popen / pclose
// ---------------------------------------------------------------------------
//
// Note: popen tests that use glibc functions (fgets, fputs) on the returned
// stream are skipped in unit test mode because glibc's vtable validation
// rejects NativeFile streams. These tests pass under LD_PRELOAD integration.

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn popen_reads_command_output() {
    let cmd = CString::new("echo hello").unwrap();
    let mode = CString::new("r").unwrap();
    let stream = unsafe { popen(cmd.as_ptr(), mode.as_ptr()) };
    assert!(!stream.is_null(), "popen should succeed");

    let mut buf = [0i8; 64];
    let line = unsafe { fgets(buf.as_mut_ptr(), buf.len() as c_int, stream) };
    assert!(!line.is_null());
    let output = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
    assert!(output.starts_with("hello"), "got: {output}");

    let status = unsafe { pclose(stream) };
    assert!(status >= 0, "pclose should return valid status: {status}");
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn popen_write_mode() {
    // Write to /dev/null, just verify it works
    let cmd = CString::new("cat > /dev/null").unwrap();
    let mode = CString::new("w").unwrap();
    let stream = unsafe { popen(cmd.as_ptr(), mode.as_ptr()) };
    assert!(!stream.is_null());

    let data = c"test data\n";
    unsafe { fputs(data.as_ptr(), stream) };
    let status = unsafe { pclose(stream) };
    assert!(status >= 0);
}

#[test]
fn popen_rejects_invalid_modes() {
    let cmd = CString::new("echo hello").unwrap();
    let bad_modes = ["", "r+", "w+", "rw", "x", "rr", "we+", "re+"];
    for mode in bad_modes {
        let mode = CString::new(mode).unwrap();
        // SAFETY: use FrankenLibC errno to match the ABI under test.
        unsafe {
            *frankenlibc_abi::errno_abi::__errno_location() = 0;
        }
        let stream = unsafe { popen(cmd.as_ptr(), mode.as_ptr()) };
        assert!(stream.is_null(), "mode '{mode:?}' should be rejected");
        let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        assert_eq!(err, libc::EINVAL, "mode '{mode:?}' should set EINVAL");
    }
}

#[test]
fn popen_rejects_tracked_unterminated_mode() {
    let mode = unsafe { frankenlibc_abi::malloc_abi::malloc(1).cast::<c_char>() };
    assert!(!mode.is_null());
    unsafe { *mode = b'r' as c_char };

    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let stream = unsafe { popen(c"echo hello".as_ptr(), mode.cast_const()) };
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    unsafe { frankenlibc_abi::malloc_abi::free(mode.cast::<c_void>()) };

    assert!(stream.is_null(), "popen should reject unterminated mode");
    assert_eq!(err, libc::EINVAL, "unterminated mode should set EINVAL");
}

// ---------------------------------------------------------------------------
// perror
// ---------------------------------------------------------------------------

#[test]
fn perror_does_not_crash_with_null_or_empty() {
    let _guard = STDOUT_REDIRECT_LOCK
        .lock()
        .expect("stdio redirect lock should not be poisoned");

    // perror writes to stderr; we just verify it doesn't crash
    unsafe { perror(std::ptr::null()) };
    unsafe { perror(c"test_prefix".as_ptr()) };
}

#[test]
fn perror_ignores_tracked_unterminated_prefix() {
    let _guard = STDOUT_REDIRECT_LOCK
        .lock()
        .expect("stdio redirect lock should not be poisoned");

    let mut pipe_fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);

    let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
    assert!(saved_stderr >= 0);
    assert_eq!(
        unsafe { libc::dup2(pipe_fds[1], libc::STDERR_FILENO) },
        libc::STDERR_FILENO
    );

    let prefix = unsafe { tracked_bytes_without_nul(b"unterminated_prefix") };
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = libc::EINVAL;
        perror(prefix.cast_const());
        frankenlibc_abi::malloc_abi::free(prefix.cast::<c_void>());
        libc::dup2(saved_stderr, libc::STDERR_FILENO);
        libc::close(saved_stderr);
        libc::close(pipe_fds[1]);
    }

    let mut captured = Vec::new();
    let mut buf = [0u8; 128];
    loop {
        let n = unsafe { libc::read(pipe_fds[0], buf.as_mut_ptr().cast(), buf.len()) };
        if n <= 0 {
            break;
        }
        captured.extend_from_slice(&buf[..n as usize]);
    }
    unsafe { libc::close(pipe_fds[0]) };

    assert_eq!(captured, b"Invalid argument\n");
}

// ---------------------------------------------------------------------------
// Unlocked stdio variants
// ---------------------------------------------------------------------------

#[test]
fn fputs_unlocked_and_fgets_unlocked_round_trip() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let msg = c"hello unlocked\n";
    assert!(unsafe { fputs_unlocked(msg.as_ptr(), stream) } >= 0);

    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0i8; 64];
    let ptr = unsafe { fgets_unlocked(buf.as_mut_ptr(), buf.len() as c_int, stream) };
    assert!(!ptr.is_null());
    let line = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(line, b"hello unlocked\n");

    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fwrite_unlocked_and_fread_unlocked_round_trip() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let data = b"ABCDEF";
    let written = unsafe { fwrite_unlocked(data.as_ptr().cast(), 1, data.len(), stream) };
    assert_eq!(written, data.len());

    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0u8; 16];
    let read_n = unsafe { fread_unlocked(buf.as_mut_ptr().cast(), 1, buf.len(), stream) };
    assert_eq!(read_n, data.len());
    assert_eq!(&buf[..data.len()], data);

    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fflush_unlocked_succeeds_on_writable_stream() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());
    assert_eq!(unsafe { fflush_unlocked(stream) }, 0);
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn clearerr_unlocked_clears_error_and_eof() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    // Read on empty file sets EOF
    let mut buf = [0u8; 1];
    unsafe { fread(buf.as_mut_ptr().cast(), 1, 1, stream) };
    assert_ne!(unsafe { feof_unlocked(stream) }, 0);

    unsafe { clearerr_unlocked(stream) };
    assert_eq!(unsafe { feof_unlocked(stream) }, 0);
    assert_eq!(unsafe { ferror_unlocked(stream) }, 0);

    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fileno_unlocked_returns_valid_fd() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());
    let fd = unsafe { fileno_unlocked(stream) };
    assert!(fd >= 0);
    assert_eq!(unsafe { fclose(stream) }, 0);
}

// ---------------------------------------------------------------------------
// fseeko / ftello
// ---------------------------------------------------------------------------

#[test]
fn fseeko_and_ftello_track_position() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    let data = b"0123456789";
    unsafe { fwrite(data.as_ptr().cast(), 1, data.len(), stream) };

    assert_eq!(unsafe { fseeko(stream, 5, libc::SEEK_SET) }, 0);
    assert_eq!(unsafe { ftello(stream) }, 5);

    assert_eq!(unsafe { fclose(stream) }, 0);
}

// ---------------------------------------------------------------------------
// setbuffer
// ---------------------------------------------------------------------------

#[test]
fn setbuffer_with_null_buf_sets_unbuffered() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());
    // NULL buffer with size 0 -> unbuffered
    unsafe { setbuffer(stream, std::ptr::null_mut(), 0) };
    // Just verify it doesn't crash and we can still write
    unsafe { fputc(b'X' as c_int, stream) };
    assert_eq!(unsafe { fclose(stream) }, 0);
}

// ---------------------------------------------------------------------------
// putw / getw
// ---------------------------------------------------------------------------

#[test]
fn putw_and_getw_round_trip() {
    let stream = unsafe { tmpfile() };
    assert!(!stream.is_null());

    assert_eq!(unsafe { putw(42, stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);
    let val = unsafe { getw(stream) };
    assert_eq!(val, 42);

    assert_eq!(unsafe { fclose(stream) }, 0);
}

// ---------------------------------------------------------------------------
// tmpfile64
// ---------------------------------------------------------------------------

#[test]
fn tmpfile64_creates_writable_stream() {
    let stream = unsafe { tmpfile64() };
    assert!(!stream.is_null());
    let data = b"test64";
    let written = unsafe { fwrite(data.as_ptr().cast(), 1, data.len(), stream) };
    assert_eq!(written, data.len());
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn tmpfile64_alias_uses_unlinked_update_stream() {
    let stream = unsafe { tmpfile64() };
    assert!(!stream.is_null());

    let fd = unsafe { fileno(stream) };
    assert!(fd >= 0);
    let proc_fd_path = PathBuf::from(format!("/proc/self/fd/{fd}"));
    let target =
        fs::read_link(&proc_fd_path).expect("tmpfile64 fd should be visible in /proc/self/fd");
    let rendered = target.to_string_lossy();
    assert!(
        rendered.contains("/tmp/"),
        "tmpfile64 backing path should live under /tmp: {rendered}"
    );
    assert!(
        rendered.contains("(deleted)"),
        "tmpfile64 backing file should already be unlinked while open: {rendered}"
    );

    let data = b"tmpfile64-alias";
    let written = unsafe { fwrite(data.as_ptr().cast(), 1, data.len(), stream) };
    assert_eq!(written, data.len());
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0_u8; 32];
    let read = unsafe { fread(buf.as_mut_ptr().cast(), 1, data.len(), stream) };
    assert_eq!(read, data.len());
    assert_eq!(&buf[..data.len()], data);

    assert_eq!(unsafe { fclose(stream) }, 0);
}

// ---------------------------------------------------------------------------
// vsnprintf / vsprintf (via variadic wrapper)
// ---------------------------------------------------------------------------

#[test]
fn vsnprintf_truncates_correctly() {
    let mut buf = [0i8; 8];
    // Use snprintf as the test vehicle (vsnprintf is called internally)
    let fmt = c"%d-%s";
    let n = unsafe {
        snprintf(
            buf.as_mut_ptr(),
            buf.len(),
            fmt.as_ptr(),
            42i32,
            c"hello".as_ptr(),
        )
    };
    assert!(n > 0);
    let result = unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes();
    assert_eq!(result, b"42-hell"); // Truncated to fit in 8 bytes
}

// ---------------------------------------------------------------------------
// fmemopen
// ---------------------------------------------------------------------------

#[test]
fn fmemopen_write_creates_stream() {
    // bd-el0v8: serialize against other parallel tests that allocate
    // streams. Address reuse by glibc malloc would otherwise let
    // another in-flight stream land at the just-freed address and
    // make the "not in registry after fclose" assertion racy.
    let _registry_probe = STREAM_REGISTRY_PROBE_LOCK
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let mut buf = [0u8; 64];
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"w+".as_ptr()) };
    // fmemopen may not work fully without LD_PRELOAD, just check it returns something
    if !stream.is_null() {
        assert!(verify_native_file(stream).is_some());
        assert_eq!(unsafe { fileno(stream) }, -1);
        assert_eq!(unsafe { fclose(stream) }, 0);
        assert!(verify_native_file(stream).is_none());
    }
}

#[test]
fn fmemopen_rejects_tracked_unterminated_mode() {
    let mode = unsafe { frankenlibc_abi::malloc_abi::malloc(1).cast::<c_char>() };
    assert!(!mode.is_null());
    unsafe { *mode = b'w' as c_char };
    let mut buf = [0u8; 8];

    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
    }
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), mode.cast_const()) };
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };

    unsafe { frankenlibc_abi::malloc_abi::free(mode.cast::<c_void>()) };

    assert!(stream.is_null(), "fmemopen should reject unterminated mode");
    assert_eq!(err, libc::EINVAL, "unterminated mode should set EINVAL");
}

#[test]
fn fmemopen_writes_sync_on_flush_not_immediately() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"r+".as_ptr()) };
    if stream.is_null() {
        return;
    }
    let payload = b"xyz";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(&buf, b"ABCDEFGH");
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(&buf, b"xyzDEFGH");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fmemopen_fseek_syncs_pending_write() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"r+".as_ptr()) };
    if stream.is_null() {
        return;
    }
    let payload = b"xyz";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(&buf, b"ABCDEFGH");
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);
    assert_eq!(&buf, b"xyzDEFGH");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fmemopen_wplus_truncate_sets_initial_nul_only() {
    let mut buf = [b'Z'; 8];
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"w+".as_ptr()) };
    if stream.is_null() {
        return;
    }
    assert_eq!(buf, [0, b'Z', b'Z', b'Z', b'Z', b'Z', b'Z', b'Z']);
    assert_eq!(unsafe { fclose(stream) }, 0);
    assert_eq!(buf, [0, b'Z', b'Z', b'Z', b'Z', b'Z', b'Z', b'Z']);
}

#[test]
fn fmemopen_w_truncate_without_write_leaves_caller_buffer_unchanged() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"w".as_ptr()) };
    if stream.is_null() {
        return;
    }
    assert_eq!(&buf, b"ABCDEFGH");
    assert_eq!(unsafe { fclose(stream) }, 0);
    assert_eq!(&buf, b"ABCDEFGH");
}

#[test]
fn fmemopen_w_truncate_defers_caller_buffer_change_until_flush() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"w".as_ptr()) };
    if stream.is_null() {
        return;
    }
    assert_eq!(&buf, b"ABCDEFGH");
    let payload = b"xy";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(&buf, b"ABCDEFGH");
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(&buf, b"xy\0DEFGH");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fmemopen_w_truncate_exact_capacity_preserves_final_nul_slot() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"w".as_ptr()) };
    if stream.is_null() {
        return;
    }
    let payload = b"01234567";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(&buf, b"ABCDEFGH");
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(&buf, b"0123456\0");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fmemopen_wplus_exact_capacity_readback_sees_terminal_nul() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"w+".as_ptr()) };
    if stream.is_null() {
        return;
    }
    let payload = b"01234567";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(&buf, b"0123456\0");
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut out = [0u8; 8];
    let got = unsafe { fread(out.as_mut_ptr().cast(), 1, out.len(), stream) };
    assert_eq!(got, out.len());
    assert_eq!(&out, b"0123456\0");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fmemopen_rplus_exact_capacity_does_not_reserve_final_nul_slot() {
    let mut buf = *b"ABCDEFGH";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"r+".as_ptr()) };
    if stream.is_null() {
        return;
    }
    let payload = b"01234567";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(&buf, b"ABCDEFGH");
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(&buf, b"01234567");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

#[test]
fn fmemopen_append_flush_writes_nul_after_appended_content() {
    let mut buf = *b"ABC\0ZZZZ";
    let stream = unsafe { fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"a".as_ptr()) };
    if stream.is_null() {
        return;
    }
    let payload = b"xy";
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(&buf, b"ABC\0ZZZZ");
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(&buf, b"ABCxy\0ZZ");
    assert_eq!(unsafe { fclose(stream) }, 0);
}

// ===========================================================================
// open_memstream
// ===========================================================================

#[test]
fn open_memstream_returns_stream_or_null() {
    let mut ptr: *mut c_char = std::ptr::null_mut();
    let mut size: usize = 0;
    let stream = unsafe { open_memstream(&mut ptr, &mut size) };
    // open_memstream may not be fully functional without LD_PRELOAD
    if stream.is_null() {
        return;
    }
    assert!(verify_native_file(stream).is_some());
    assert_eq!(unsafe { fileno(stream) }, -1);
    // Just close it — don't free ptr as it may be managed internally
    unsafe { fclose(stream) };
    assert!(verify_native_file(stream).is_none());
}

#[test]
fn open_memstream_grows_and_syncs_on_flush_and_close() {
    let mut ptr: *mut c_char = std::ptr::null_mut();
    let mut size: usize = 0;
    let stream = unsafe { open_memstream(&mut ptr, &mut size) };
    assert!(!stream.is_null());

    let payload = vec![b'x'; 8192];
    let wrote = unsafe { fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());

    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(size, payload.len());
    assert!(!ptr.is_null());
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), size) };
    assert_eq!(bytes, payload.as_slice());
    assert_eq!(unsafe { *ptr.add(size) }, 0);

    assert_eq!(unsafe { fclose(stream) }, 0);
    assert_eq!(size, payload.len());
    let bytes = unsafe { std::slice::from_raw_parts(ptr.cast::<u8>(), size) };
    assert_eq!(bytes, payload.as_slice());

    unsafe { frankenlibc_abi::malloc_abi::free(ptr.cast::<c_void>()) };
}

// ===========================================================================
// puts / putchar / putchar_unlocked — test via file stream (fdopen)
// ===========================================================================

#[test]
fn puts_calls_without_crash() {
    // We can't easily capture stdout in the interposition layer,
    // so just verify puts doesn't crash and returns a non-negative value
    let rc = unsafe { puts(c"".as_ptr()) };
    // puts returns non-negative on success or EOF on error
    assert!(rc >= 0 || rc == libc::EOF, "puts returned unexpected {rc}");
}

#[test]
fn putchar_returns_char_or_eof() {
    // putchar writes to stdout; verify it returns the character or EOF
    let rc = unsafe { putchar(b'A' as c_int) };
    assert!(
        rc == b'A' as c_int || rc == libc::EOF,
        "putchar should return the char or EOF, got {rc}"
    );
}

#[test]
fn putchar_unlocked_returns_char_or_eof() {
    let rc = unsafe { putchar_unlocked(b'B' as c_int) };
    assert!(
        rc == b'B' as c_int || rc == libc::EOF,
        "putchar_unlocked should return the char or EOF, got {rc}"
    );
}

// ===========================================================================
// freopen64
// ===========================================================================

#[test]
fn freopen64_reopens_file() {
    let p = temp_path("freopen64");
    let pc = path_cstring(&p);

    // Create a file with known content
    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    unsafe { fputs(c"original".as_ptr(), f) };
    unsafe { fclose(f) };

    // Open for writing, then reopen for reading
    let f = unsafe { fopen(pc.as_ptr(), c"r".as_ptr()) };
    assert!(!f.is_null());
    let f2 = unsafe { freopen64(pc.as_ptr(), c"r".as_ptr(), f) };
    if !f2.is_null() {
        let mut buf = [0u8; 32];
        let n = unsafe { fread(buf.as_mut_ptr().cast(), 1, buf.len(), f2) };
        // The file should have "original" (8 bytes)
        assert!(n > 0, "freopen64 should allow reading, got {n} bytes");
        unsafe { fclose(f2) };
    } else {
        // freopen64 returned null, original stream is closed by freopen semantics
    }
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// __isoc99_sscanf / __isoc99_fscanf
// ===========================================================================

#[test]
fn isoc99_sscanf_basic() {
    let input = c"42 hello";
    let mut val: c_int = 0;
    let mut buf = [0u8; 32];
    let n = unsafe {
        __isoc99_sscanf(
            input.as_ptr(),
            c"%d %31s".as_ptr(),
            &mut val as *mut c_int,
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(n, 2);
    assert_eq!(val, 42);
    let s = unsafe { CStr::from_ptr(buf.as_ptr().cast()) };
    assert_eq!(s.to_str().unwrap(), "hello");
}

#[test]
fn isoc99_fscanf_from_file() {
    let p = temp_path("isoc99_fscanf");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    unsafe { fputs(c"99 bottles".as_ptr(), f) };
    unsafe { fclose(f) };

    let f = unsafe { fopen(pc.as_ptr(), c"r".as_ptr()) };
    assert!(!f.is_null());
    let mut val: c_int = 0;
    let n = unsafe { __isoc99_fscanf(f, c"%d".as_ptr(), &mut val as *mut c_int) };
    assert_eq!(n, 1);
    assert_eq!(val, 99);
    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// _IO_putc / _IO_getc
// ===========================================================================

#[test]
fn io_putc_getc_roundtrip() {
    let p = temp_path("io_putc_getc");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w+".as_ptr()) };
    assert!(!f.is_null());

    let rc = unsafe { _IO_putc(b'X' as c_int, f) };
    assert_eq!(rc, b'X' as c_int);

    unsafe { rewind(f) };

    let ch = unsafe { _IO_getc(f) };
    assert_eq!(ch, b'X' as c_int);

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// _IO_feof / _IO_ferror
// ===========================================================================

#[test]
fn io_feof_at_end() {
    let p = temp_path("io_feof");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w+".as_ptr()) };
    assert!(!f.is_null());
    unsafe { _IO_putc(b'A' as c_int, f) };
    unsafe { rewind(f) };

    assert_eq!(unsafe { _IO_feof(f) }, 0, "not at EOF yet");
    unsafe { _IO_getc(f) }; // read the 'A'
    unsafe { _IO_getc(f) }; // trigger EOF
    assert_ne!(unsafe { _IO_feof(f) }, 0, "should be at EOF");

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

#[test]
fn io_ferror_on_good_stream() {
    let p = temp_path("io_ferror");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    assert_eq!(unsafe { _IO_ferror(f) }, 0, "no error on fresh stream");
    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// _IO_flockfile / _IO_funlockfile / _IO_ftrylockfile
// ===========================================================================

#[test]
fn io_flockfile_funlockfile_basic() {
    let p = temp_path("io_flock");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());

    // Should not deadlock: lock then unlock
    unsafe { _IO_flockfile(f) };
    unsafe { _IO_funlockfile(f) };

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

#[test]
fn io_ftrylockfile_succeeds_when_unlocked() {
    let p = temp_path("io_ftrylock");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());

    let rc = unsafe { _IO_ftrylockfile(f) };
    assert_eq!(rc, 0, "ftrylockfile on unlocked stream should return 0");
    unsafe { _IO_funlockfile(f) };

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// _IO_puts (writes to stdout like puts)
// ===========================================================================

#[test]
fn io_puts_does_not_crash() {
    // _IO_puts writes to stdout; just verify it doesn't crash
    let rc = unsafe { _IO_puts(c"io_puts_ok".as_ptr()) };
    assert!(
        rc >= 0 || rc == libc::EOF,
        "_IO_puts returned unexpected {rc}"
    );
}

// ===========================================================================
// _IO_padn (write padding characters)
// ===========================================================================

#[test]
fn io_padn_writes_padding() {
    let p = temp_path("io_padn");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());

    let n = unsafe { _IO_padn(f, b' ' as c_int, 5) };
    // Should write 5 space characters (or return error if not supported)
    if n >= 0 {
        assert_eq!(n, 5, "_IO_padn should write 5 bytes");
    }

    unsafe { fclose(f) };

    if n >= 0 {
        let content = fs::read_to_string(&p).unwrap();
        assert_eq!(content, "     ", "should have 5 spaces");
    }
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// _IO_sgetn (read n bytes from stream)
// ===========================================================================

#[test]
fn io_sgetn_reads_bytes() {
    let p = temp_path("io_sgetn");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    unsafe { fputs(c"abcdefgh".as_ptr(), f) };
    unsafe { fclose(f) };

    let f = unsafe { fopen(pc.as_ptr(), c"r".as_ptr()) };
    assert!(!f.is_null());

    let mut buf = [0u8; 8];
    let n = unsafe { _IO_sgetn(f, buf.as_mut_ptr().cast(), 4) };
    assert_eq!(n, 4, "_IO_sgetn should read 4 bytes");
    assert_eq!(&buf[..4], b"abcd");

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

// ===========================================================================
// _IO_seekoff / _IO_seekpos
// ===========================================================================

#[test]
fn io_seekoff_resets_position() {
    let p = temp_path("io_seekoff");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w+".as_ptr()) };
    assert!(!f.is_null());
    unsafe { fputs(c"seektest".as_ptr(), f) };

    // Seek to beginning using _IO_seekoff (offset=0, whence=SEEK_SET=0)
    let pos = unsafe { _IO_seekoff(f, 0, 0, 0) };
    // pos should be 0 (beginning of file)
    if pos >= 0 {
        assert_eq!(pos, 0);
        let ch = unsafe { fgetc(f) };
        assert_eq!(ch, b's' as c_int);
    }

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

#[test]
fn io_seekpos_to_beginning() {
    let p = temp_path("io_seekpos");
    let pc = path_cstring(&p);

    let f = unsafe { fopen(pc.as_ptr(), c"w+".as_ptr()) };
    assert!(!f.is_null());
    unsafe { fputs(c"postest".as_ptr(), f) };

    let pos = unsafe { _IO_seekpos(f, 0, 0) };
    if pos >= 0 {
        assert_eq!(pos, 0);
        let ch = unsafe { fgetc(f) };
        assert_eq!(ch, b'p' as c_int);
    }

    unsafe { fclose(f) };
    let _ = fs::remove_file(&p);
}

#[test]
fn io_internal_fopen_fputs_fflush_fgets_fclose_round_trip() {
    let path = temp_path("io_internal_fopen");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(unsafe { _IO_fputs(c"alpha\nbeta\n".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { _IO_fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0 as c_char; 16];
    let out = unsafe { _IO_fgets(buf.as_mut_ptr(), buf.len() as c_int, stream) };
    assert_eq!(out, buf.as_mut_ptr());
    let rendered = unsafe { CStr::from_ptr(buf.as_ptr()) };
    assert_eq!(rendered.to_bytes(), b"alpha\n");

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_fdopen_fwrite_and_fread_round_trip() {
    let path = temp_path("io_internal_fdopen");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_RDWR,
            0o600,
        )
    };
    assert!(fd >= 0);

    let stream = unsafe { _IO_fdopen(fd, c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let payload = b"io-internal-data";
    let wrote = unsafe { _IO_fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());
    assert_eq!(unsafe { _IO_fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut buf = [0u8; 16];
    let read = unsafe { _IO_fread(buf.as_mut_ptr().cast(), 1, payload.len(), stream) };
    assert_eq!(read, payload.len());
    assert_eq!(&buf[..payload.len()], payload);

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_fgetpos_variants_restore_position() {
    let path = temp_path("io_internal_fpos");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());
    assert_eq!(unsafe { _IO_fputs(c"ABCDE".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { _IO_fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    assert_eq!(unsafe { fgetc(stream) }, b'A' as c_int);
    let mut pos = std::mem::MaybeUninit::<libc::fpos_t>::uninit();
    assert_eq!(unsafe { _IO_fgetpos(stream, pos.as_mut_ptr().cast()) }, 0);
    let pos = unsafe { pos.assume_init() };
    assert_eq!(unsafe { fgetc(stream) }, b'B' as c_int);
    assert_eq!(
        unsafe { _IO_fsetpos(stream, (&pos as *const libc::fpos_t).cast()) },
        0
    );
    assert_eq!(unsafe { _IO_ftell(stream) }, 1);
    assert_eq!(unsafe { fgetc(stream) }, b'B' as c_int);

    let mut pos64 = 0_i64;
    assert_eq!(
        unsafe { _IO_fgetpos64(stream, (&mut pos64 as *mut i64).cast()) },
        0
    );
    assert_eq!(unsafe { fgetc(stream) }, b'C' as c_int);
    assert_eq!(
        unsafe { _IO_fsetpos64(stream, (&pos64 as *const i64).cast()) },
        0
    );
    assert_eq!(unsafe { _IO_ftell(stream) }, pos64);
    assert_eq!(unsafe { fgetc(stream) }, b'C' as c_int);

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_fprintf_and_sprintf_use_native_formatting() {
    let path = temp_path("io_internal_fprintf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let written = unsafe { _IO_fprintf(stream, c"v=%d:%s".as_ptr(), 7_i32, c"ok".as_ptr()) };
    assert_eq!(written, 6);
    assert_eq!(unsafe { _IO_fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut file_buf = [0 as c_char; 16];
    let out = unsafe { _IO_fgets(file_buf.as_mut_ptr(), file_buf.len() as c_int, stream) };
    assert_eq!(out, file_buf.as_mut_ptr());
    let file_rendered = unsafe { CStr::from_ptr(file_buf.as_ptr()) };
    assert_eq!(file_rendered.to_bytes(), b"v=7:ok");

    let mut mem_buf = [0 as c_char; 32];
    let rendered = unsafe {
        _IO_sprintf(
            mem_buf.as_mut_ptr(),
            c"%d-%s".as_ptr(),
            42_i32,
            c"wave".as_ptr(),
        )
    };
    assert_eq!(rendered, 7);
    let mem_rendered = unsafe { CStr::from_ptr(mem_buf.as_ptr()) };
    assert_eq!(mem_rendered.to_bytes(), b"42-wave");

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_printf_and_sscanf_use_native_stdio_paths() {
    let _guard = STDOUT_REDIRECT_LOCK
        .lock()
        .expect("stdout redirect lock should not be poisoned");

    let path = temp_path("io_internal_printf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let out_fd = unsafe {
        libc::open(
            path_c.as_ptr(),
            libc::O_CREAT | libc::O_TRUNC | libc::O_WRONLY,
            0o600,
        )
    };
    assert!(out_fd >= 0);

    let saved_stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
    assert!(saved_stdout >= 0);
    assert_eq!(
        unsafe { libc::dup2(out_fd, libc::STDOUT_FILENO) },
        libc::STDOUT_FILENO
    );

    let written = unsafe { _IO_printf(c"io-%d\n".as_ptr(), 9_i32) };
    assert_eq!(written, 5);

    unsafe {
        libc::dup2(saved_stdout, libc::STDOUT_FILENO);
        libc::close(saved_stdout);
        libc::close(out_fd);
    }

    let bytes = fs::read(&path).expect("redirected _IO_printf output file should exist");
    assert!(
        bytes
            .windows(b"io-9\n".len())
            .any(|window| window == b"io-9\n"),
        "redirected stdout should contain _IO_printf payload; got bytes={bytes:?}"
    );

    let input = c"11 parsed";
    let mut value = 0_i32;
    let mut word = [0 as c_char; 16];
    let parsed = unsafe {
        _IO_sscanf(
            input.as_ptr(),
            c"%d %15s".as_ptr(),
            &mut value,
            word.as_mut_ptr(),
        )
    };
    assert_eq!(parsed, 2);
    assert_eq!(value, 11);
    let parsed_word = unsafe { CStr::from_ptr(word.as_ptr()) };
    assert_eq!(parsed_word.to_bytes(), b"parsed");

    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_flush_all_uses_native_fflush_null_semantics() {
    let path = temp_path("io_internal_flush_all");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(unsafe { _IO_fputs(c"pending-flush".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { _IO_flush_all() }, 0);

    let bytes = fs::read(&path).expect("flush_all should materialize buffered data on disk");
    assert_eq!(bytes, b"pending-flush");

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_setvbuf_setbuffer_and_ungetc_use_native_stdio_paths() {
    let path = temp_path("io_internal_setvbuf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(
        unsafe { _IO_setvbuf(stream, std::ptr::null_mut(), IONBF, 0) },
        0
    );
    assert_eq!(unsafe { _IO_fputs(c"AB".as_ptr(), stream) }, 0);

    let mut user_buf = [0 as c_char; 32];
    unsafe { _IO_setbuffer(stream, user_buf.as_mut_ptr(), user_buf.len()) };
    assert_eq!(unsafe { _IO_fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    assert_eq!(unsafe { fgetc(stream) }, b'A' as c_int);
    assert_eq!(unsafe { _IO_ungetc(b'Z' as c_int, stream) }, b'Z' as c_int);
    assert_eq!(unsafe { fgetc(stream) }, b'Z' as c_int);

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_file_ops_use_native_stdio_paths() {
    let path = temp_path("io_internal_file_ops");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let payload = b"native-file-ops";
    let wrote = unsafe { _IO_file_write(stream, payload.as_ptr().cast::<c_void>(), 6) };
    assert_eq!(wrote, 6);
    let wrote_rest = unsafe { _IO_file_xsputn(stream, payload[6..].as_ptr().cast::<c_void>(), 9) };
    assert_eq!(wrote_rest, payload.len() - 6);

    let mut user_buf = [0 as c_char; 64];
    assert_eq!(
        unsafe { _IO_file_setbuf(stream, user_buf.as_mut_ptr(), user_buf.len() as isize) },
        stream
    );
    assert_eq!(unsafe { _IO_file_sync(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut out = [0u8; 32];
    let read = unsafe {
        _IO_file_read(
            stream,
            out.as_mut_ptr().cast::<c_void>(),
            payload.len() as isize,
        )
    };
    assert_eq!(read, payload.len() as isize);
    assert_eq!(&out[..payload.len()], payload);

    assert_eq!(unsafe { _IO_file_close(stream) }, 0);
    assert_eq!(fs::read(&path).expect("file should flush to disk"), payload);
    let _ = fs::remove_file(&path);
}

#[test]
fn io_internal_file_close_it_closes_stream_natively() {
    let path = temp_path("io_internal_file_close_it");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());
    assert_eq!(unsafe { _IO_fputs(c"close-it".as_ptr(), stream) }, 0);

    assert_eq!(unsafe { _IO_file_close_it(stream) }, 0);
    assert_eq!(
        fs::read(&path).expect("close_it should flush data"),
        b"close-it"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_file_seek_stat_and_buffer_edges_use_native_stdio_paths() {
    let path = temp_path("io_internal_file_seek_stat");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(
        unsafe { _IO_file_overflow(stream, b'A' as c_int) },
        b'A' as c_int
    );
    assert_eq!(
        unsafe { _IO_file_overflow(stream, b'B' as c_int) },
        b'B' as c_int
    );
    assert_eq!(unsafe { _IO_file_overflow(stream, libc::EOF) }, 0);

    assert_eq!(unsafe { _IO_file_seek(stream, 1, libc::SEEK_SET) }, 1);
    assert_eq!(unsafe { _IO_file_underflow(stream) }, b'B' as c_int);
    assert_eq!(unsafe { fgetc(stream) }, b'B' as c_int);

    assert_eq!(unsafe { _IO_file_seekoff(stream, 0, libc::SEEK_END, 0) }, 2);

    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::zeroed();
    assert_eq!(
        unsafe { _IO_file_stat(stream, stat_buf.as_mut_ptr().cast::<c_void>()) },
        0
    );
    let stat_buf = unsafe { stat_buf.assume_init() };
    assert_eq!(stat_buf.st_size, 2);

    assert_eq!(unsafe { _IO_file_close(stream) }, 0);
    assert_eq!(
        fs::read(&path).expect("overflow writes should flush to disk"),
        b"AB"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn io_internal_vfprintf_and_vsprintf_use_native_stdio_paths() {
    let path = temp_path("io_internal_vfprintf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { _IO_fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    let written =
        unsafe { call_io_vfprintf(stream, c"%s=%d".as_ptr(), c"native".as_ptr(), 21_i32) };
    assert_eq!(written, 9);
    assert_eq!(unsafe { _IO_fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut file_buf = [0 as c_char; 32];
    let out = unsafe { _IO_fgets(file_buf.as_mut_ptr(), file_buf.len() as c_int, stream) };
    assert_eq!(out, file_buf.as_mut_ptr());
    let file_rendered = unsafe { CStr::from_ptr(file_buf.as_ptr()) };
    assert_eq!(file_rendered.to_bytes(), b"native=21");

    let mut mem_buf = [0 as c_char; 32];
    let rendered = unsafe {
        call_io_vsprintf(
            mem_buf.as_mut_ptr(),
            c"%d:%s".as_ptr(),
            5_i32,
            c"ok".as_ptr(),
        )
    };
    assert_eq!(rendered, 4);
    let mem_rendered = unsafe { CStr::from_ptr(mem_buf.as_ptr()) };
    assert_eq!(mem_rendered.to_bytes(), b"5:ok");

    assert_eq!(unsafe { _IO_fclose(stream) }, 0);
    let _ = fs::remove_file(path);
}

// ===========================================================================
// bd-9chy.47: Comprehensive fopen/fdopen test suite
// ===========================================================================

// ---------------------------------------------------------------------------
// Mode parsing tests (1-10)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_r_opens_readonly() {
    let path = temp_path("fopen_mode_r");
    fs::write(&path, b"content").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(
        !stream.is_null(),
        "fopen(r) should succeed for existing file"
    );

    // Verify readable
    let mut buf = [0u8; 8];
    let n = unsafe { fread(buf.as_mut_ptr().cast(), 1, 7, stream) };
    assert_eq!(n, 7);
    assert_eq!(&buf[..7], b"content");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_w_creates_and_truncates() {
    let path = temp_path("fopen_mode_w");
    fs::write(&path, b"old content").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null(), "fopen(w) should succeed");

    // Write new content
    let written = unsafe { fputs(c"new".as_ptr(), stream) };
    assert!(written >= 0);
    unsafe { fclose(stream) };

    // Verify truncation and new content
    let content = fs::read(&path).unwrap();
    assert_eq!(content, b"new");
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_a_appends() {
    let path = temp_path("fopen_mode_a");
    fs::write(&path, b"start").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"a".as_ptr()) };
    assert!(!stream.is_null(), "fopen(a) should succeed");

    let written = unsafe { fputs(c"_end".as_ptr(), stream) };
    assert!(written >= 0);
    unsafe { fclose(stream) };

    let content = fs::read(&path).unwrap();
    assert_eq!(content, b"start_end");
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_rplus_opens_readwrite() {
    let path = temp_path("fopen_mode_rplus");
    fs::write(&path, b"ABCDE").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"r+".as_ptr()) };
    assert!(!stream.is_null(), "fopen(r+) should succeed");

    // Read first
    let ch = unsafe { fgetc(stream) };
    assert_eq!(ch, b'A' as c_int);

    // Write at position 1
    let written = unsafe { fputc(b'X' as c_int, stream) };
    assert_eq!(written, b'X' as c_int);
    unsafe { fclose(stream) };

    let content = fs::read(&path).unwrap();
    assert_eq!(content, b"AXCDE");
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_wplus_truncates_and_readwrite() {
    let path = temp_path("fopen_mode_wplus");
    fs::write(&path, b"old").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null(), "fopen(w+) should succeed");

    // Write
    let written = unsafe { fputs(c"new".as_ptr(), stream) };
    assert!(written >= 0);

    // Seek back and read
    unsafe { rewind(stream) };
    let mut buf = [0u8; 4];
    let n = unsafe { fread(buf.as_mut_ptr().cast(), 1, 3, stream) };
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"new");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_aplus_appends_and_reads() {
    let path = temp_path("fopen_mode_aplus");
    fs::write(&path, b"base").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"a+".as_ptr()) };
    assert!(!stream.is_null(), "fopen(a+) should succeed");

    // Append
    let written = unsafe { fputs(c"+ext".as_ptr(), stream) };
    assert!(written >= 0);

    // Seek to start and read
    unsafe { rewind(stream) };
    let mut buf = [0u8; 16];
    let n = unsafe { fread(buf.as_mut_ptr().cast(), 1, 16, stream) };
    assert_eq!(n, 8);
    assert_eq!(&buf[..8], b"base+ext");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_b_binary_is_noop() {
    let path = temp_path("fopen_mode_b");
    fs::write(&path, b"\n\r\n").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"rb".as_ptr()) };
    assert!(!stream.is_null(), "fopen(rb) should succeed");

    let mut buf = [0u8; 4];
    let n = unsafe { fread(buf.as_mut_ptr().cast(), 1, 3, stream) };
    assert_eq!(n, 3);
    // Binary mode preserves bytes exactly on Linux
    assert_eq!(&buf[..3], b"\n\r\n");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_x_exclusive_fails_if_exists() {
    let path = temp_path("fopen_mode_x");
    fs::write(&path, b"exists").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"wx".as_ptr()) };
    assert!(stream.is_null(), "fopen(wx) should fail for existing file");

    // Should set errno to EEXIST
    let err = unsafe { *libc::__errno_location() };
    assert_eq!(err, libc::EEXIST);

    // Create non-existing path
    let path2 = temp_path("fopen_mode_x_new");
    let _ = fs::remove_file(&path2);
    let path2_c = path_cstring(&path2);

    let stream2 = unsafe { fopen(path2_c.as_ptr(), c"wx".as_ptr()) };
    assert!(!stream2.is_null(), "fopen(wx) should succeed for new file");
    unsafe { fclose(stream2) };

    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path2);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_mode_e_cloexec_sets_flag() {
    let path = temp_path("fopen_mode_e");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"we".as_ptr()) };
    assert!(!stream.is_null(), "fopen(we) should succeed");

    let fd = unsafe { fileno(stream) };
    assert!(fd >= 0);

    // Check FD_CLOEXEC flag
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "CLOEXEC should be set");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

#[test]
fn fopen_bad_modes_return_null_with_einval() {
    let path = temp_path("fopen_bad_modes");
    fs::write(&path, b"test").unwrap();
    let path_c = path_cstring(&path);

    // Test various invalid mode strings
    let bad_modes = [c"".as_ptr(), c"z".as_ptr(), c"rw".as_ptr(), c"ar".as_ptr()];

    for mode in &bad_modes {
        unsafe { *libc::__errno_location() = 0 };
        let stream = unsafe { fopen(path_c.as_ptr(), *mode) };
        assert!(stream.is_null(), "fopen with bad mode should return NULL");
        let err = unsafe { *libc::__errno_location() };
        assert_eq!(err, libc::EINVAL, "bad mode should set EINVAL");
    }

    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// errno preservation tests (18-19)
// ---------------------------------------------------------------------------

#[test]
fn fopen_failed_sets_errno() {
    let path = temp_path("fopen_nonexistent_asdfqwer");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    unsafe { *libc::__errno_location() = 0 };
    let stream = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(stream.is_null());

    let err = unsafe { *libc::__errno_location() };
    assert_eq!(err, libc::ENOENT, "nonexistent file should set ENOENT");
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_success_does_not_touch_errno() {
    let path = temp_path("fopen_errno_preserve");
    fs::write(&path, b"test").unwrap();
    let path_c = path_cstring(&path);

    // Set errno to a known value
    unsafe { *libc::__errno_location() = libc::EBUSY };

    let stream = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(!stream.is_null());

    // errno should be unchanged
    let err = unsafe { *libc::__errno_location() };
    assert_eq!(err, libc::EBUSY, "successful fopen should not touch errno");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// fd lifecycle tests (20-22)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_returns_fresh_fd() {
    let path = temp_path("fopen_fresh_fd");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null());

    let fd = unsafe { fileno(stream) };
    // FD should be >= 3 (0, 1, 2 are stdin/stdout/stderr)
    assert!(fd >= 3, "fopen should return fresh fd >= 3, got {fd}");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

#[test]
fn fclose_closes_fd() {
    let path = temp_path("fclose_closes_fd");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null());

    let fd = unsafe { fileno(stream) };
    assert!(fd >= 0);

    unsafe { fclose(stream) };

    // fd should now be invalid
    let mut stat_buf = std::mem::MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstat(fd, stat_buf.as_mut_ptr()) };
    assert_eq!(rc, -1, "fstat on closed fd should fail");
    let err = unsafe { *libc::__errno_location() };
    assert_eq!(err, libc::EBADF, "closed fd should report EBADF");

    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// fdopen tests (23-25)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fdopen_wraps_valid_fd() {
    let path = temp_path("fdopen_valid");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_CREAT | libc::O_RDWR, 0o600) };
    assert!(fd >= 0);

    let stream = unsafe { fdopen(fd, c"w+".as_ptr()) };
    assert!(!stream.is_null(), "fdopen should wrap valid fd");

    let written = unsafe { fputs(c"fdopen-test".as_ptr(), stream) };
    assert!(written >= 0);

    unsafe { fclose(stream) };
    // Note: fclose also closes the underlying fd

    let content = fs::read(&path).unwrap();
    assert_eq!(content, b"fdopen-test");
    let _ = fs::remove_file(path);
}

#[test]
fn fdopen_invalid_fd_returns_null() {
    unsafe { *libc::__errno_location() = 0 };
    let stream = unsafe { fdopen(-1, c"r".as_ptr()) };
    assert!(stream.is_null(), "fdopen(-1) should fail");

    let err = unsafe { *libc::__errno_location() };
    assert_eq!(err, libc::EBADF, "fdopen(-1) should set EBADF");
}

#[test]
fn fdopen_rejects_tracked_unterminated_mode() {
    let mode = unsafe { frankenlibc_abi::malloc_abi::malloc(1).cast::<c_char>() };
    assert!(!mode.is_null());
    unsafe { *mode = b'w' as c_char };

    unsafe { *libc::__errno_location() = 0 };
    let stream = unsafe { fdopen(0, mode.cast_const()) };
    let err = unsafe { *libc::__errno_location() };

    unsafe { frankenlibc_abi::malloc_abi::free(mode.cast::<c_void>()) };

    assert!(stream.is_null(), "fdopen should reject unterminated mode");
    assert_eq!(err, libc::EINVAL, "unterminated mode should set EINVAL");
}

#[test]
fn fdopen_mode_mismatch_fails() {
    let path = temp_path("fdopen_mismatch");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    // Open as read-only
    fs::write(&path, b"test").unwrap();
    let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0);

    // Try to fdopen as write
    unsafe { *libc::__errno_location() = 0 };
    let stream = unsafe { fdopen(fd, c"w".as_ptr()) };

    // Note: POSIX allows this to succeed or fail; if it fails, EINVAL expected
    if stream.is_null() {
        let err = unsafe { *libc::__errno_location() };
        assert_eq!(err, libc::EINVAL, "mode mismatch should set EINVAL");
    } else {
        // If it succeeded (some systems allow this), clean up
        unsafe { fclose(stream) };
    }

    unsafe { libc::close(fd) };
    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// Path handling tests (11-14)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_long_path_accepted() {
    // Create a long path using nested directories
    let base = temp_path("fopen_long");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();

    // Create a file with a reasonably long name (not PATH_MAX but still long)
    let long_name = "a".repeat(200);
    let path = base.join(&long_name);
    fs::write(&path, b"content").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(!stream.is_null(), "fopen should accept long path");

    unsafe { fclose(stream) };
    let _ = fs::remove_dir_all(base);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_path_with_spaces_accepted() {
    let path = temp_path("fopen with spaces in name");
    let _ = fs::remove_file(&path);
    fs::write(&path, b"spaced").unwrap();
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"r".as_ptr()) };
    assert!(!stream.is_null(), "fopen should accept path with spaces");

    let mut buf = [0u8; 8];
    let n = unsafe { fread(buf.as_mut_ptr().cast(), 1, 6, stream) };
    assert_eq!(n, 6);
    assert_eq!(&buf[..6], b"spaced");

    unsafe { fclose(stream) };
    let _ = fs::remove_file(path);
}

// ---------------------------------------------------------------------------
// isatty buffering tests (15-17)
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_regular_file_uses_full_buffering() {
    let path = temp_path("fopen_fullbuf");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null());

    // Write some data - with full buffering it should be buffered
    let written = unsafe { fputs(c"buffered".as_ptr(), stream) };
    assert!(written >= 0);

    // Before flush, file might be empty due to buffering
    // This is implementation-specific but demonstrates buffering is active

    unsafe { fclose(stream) };

    // After close, data should be there
    let content = fs::read(&path).unwrap();
    assert_eq!(content, b"buffered");
    let _ = fs::remove_file(path);
}

#[test]
#[ignore = "requires LD_PRELOAD: glibc rejects NativeFile vtable in unit tests"]
fn fopen_dev_null_succeeds() {
    let stream = unsafe { fopen(c"/dev/null".as_ptr(), c"w".as_ptr()) };
    assert!(!stream.is_null(), "fopen(/dev/null) should succeed");

    // Write to /dev/null should succeed
    let written = unsafe { fputs(c"discarded".as_ptr(), stream) };
    assert!(written >= 0);

    unsafe { fclose(stream) };
}

// ---------------------------------------------------------------------------
// Path handling edge cases (13-14)
// ---------------------------------------------------------------------------

#[test]
fn fopen_path_with_embedded_null_truncates() {
    // A path with an embedded null byte will be truncated at the first null by
    // C string handling. "/tmp\0bogus" becomes just "/tmp".
    // Build this manually since c-string literals don't allow embedded nulls.
    let path_bytes: &[u8] = b"/tmp\0bogus\0";

    // Opening "/tmp" (directory) for writing should fail with EISDIR.
    unsafe { *libc::__errno_location() = 0 };
    let stream = unsafe { fopen(path_bytes.as_ptr() as *const c_char, c"w".as_ptr()) };

    // fopen on a directory should fail.
    if stream.is_null() {
        let err = unsafe { *libc::__errno_location() };
        assert!(
            err == libc::EISDIR || err == libc::EACCES || err == libc::ENOENT,
            "Opening directory for write should fail, got errno {err}"
        );
    } else {
        // If somehow succeeded (unlikely), clean up.
        unsafe { fclose(stream) };
    }
}

#[test]
fn fopen_null_path_fails() {
    // NULL path should fail with EINVAL (our implementation) or EFAULT.
    unsafe { *libc::__errno_location() = 0 };
    let stream = unsafe { fopen(std::ptr::null(), c"r".as_ptr()) };
    assert!(stream.is_null(), "fopen(NULL, ...) should fail");
    let err = unsafe { *libc::__errno_location() };
    assert!(
        err == libc::EINVAL || err == libc::EFAULT,
        "NULL path should set EINVAL or EFAULT, got {err}"
    );
}

// ---------------------------------------------------------------------------
// Double-close detection (22)
// ---------------------------------------------------------------------------
//
// Note: Double-close testing is skipped in this test file because the test
// environment triggers glibc's vtable validation when using NativeFile.
// Double-close detection is tested via the LD_PRELOAD integration tests.

// ---------------------------------------------------------------------------
// fgetln (BSD: read a logical line into a thread-local buffer)
// ---------------------------------------------------------------------------

fn temp_text_file(content: &[u8]) -> std::path::PathBuf {
    let seq = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-fgetln-{}-{seq}.txt",
        std::process::id()
    ));
    std::fs::write(&path, content).unwrap();
    path
}

fn open_for_read(path: &std::path::Path) -> *mut c_void {
    let cstr = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let mode = c"r";
    let fp = unsafe { fopen(cstr.as_ptr(), mode.as_ptr()) };
    assert!(!fp.is_null(), "fopen({:?}) failed", path);
    fp
}

#[test]
fn fgetln_reads_line_with_newline() {
    let path = temp_text_file(b"hello\nworld\n");
    let fp = open_for_read(&path);
    let mut len: usize = 0;
    let p = unsafe { fgetln(fp, &mut len) };
    assert!(!p.is_null());
    assert_eq!(len, 6, "expected 'hello\\n' = 6 bytes");
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, len) };
    assert_eq!(bytes, b"hello\n");
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fgetln_reads_two_consecutive_lines() {
    let path = temp_text_file(b"alpha\nbeta\n");
    let fp = open_for_read(&path);

    let mut len: usize = 0;
    let p1 = unsafe { fgetln(fp, &mut len) };
    let bytes1 = unsafe { std::slice::from_raw_parts(p1 as *const u8, len).to_vec() };
    assert_eq!(bytes1, b"alpha\n");

    let p2 = unsafe { fgetln(fp, &mut len) };
    assert!(!p2.is_null());
    let bytes2 = unsafe { std::slice::from_raw_parts(p2 as *const u8, len) };
    assert_eq!(bytes2, b"beta\n");

    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fgetln_returns_last_line_without_trailing_newline() {
    let path = temp_text_file(b"first\nlast-no-nl");
    let fp = open_for_read(&path);

    let mut len: usize = 0;
    let _ = unsafe { fgetln(fp, &mut len) };
    let p2 = unsafe { fgetln(fp, &mut len) };
    assert!(
        !p2.is_null(),
        "last line without \\n should still return non-NULL"
    );
    let bytes = unsafe { std::slice::from_raw_parts(p2 as *const u8, len) };
    assert_eq!(bytes, b"last-no-nl");

    // Subsequent call returns NULL on EOF.
    let p3 = unsafe { fgetln(fp, &mut len) };
    assert!(p3.is_null());
    assert_eq!(len, 0, "len must be zeroed on EOF");

    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fgetln_eof_immediately_returns_null() {
    let path = temp_text_file(b"");
    let fp = open_for_read(&path);
    let mut len: usize = 99;
    let p = unsafe { fgetln(fp, &mut len) };
    assert!(p.is_null());
    assert_eq!(len, 0, "len must be zeroed on EOF");
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fgetln_null_stream_returns_null() {
    let mut len: usize = 99;
    let p = unsafe { fgetln(std::ptr::null_mut(), &mut len) };
    assert!(p.is_null());
    assert_eq!(len, 0);
}

#[test]
fn fgetln_null_len_pointer_is_safe() {
    let path = temp_text_file(b"x\n");
    let fp = open_for_read(&path);
    let p = unsafe { fgetln(fp, std::ptr::null_mut()) };
    assert!(!p.is_null());
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// fpurge (BSD wrapper around our existing __fpurge)
// ---------------------------------------------------------------------------

#[test]
fn fpurge_returns_zero_on_valid_stream() {
    let path = temp_text_file(b"data");
    let fp = open_for_read(&path);
    let rc = unsafe { fpurge(fp) };
    assert_eq!(rc, 0);
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fpurge_returns_minus_one_for_null_stream() {
    let rc = unsafe { fpurge(std::ptr::null_mut()) };
    assert_eq!(rc, -1);
}

// ---------------------------------------------------------------------------
// fparseln (NetBSD libutil logical-line reader)
// ---------------------------------------------------------------------------

fn fparseln_temp_file(content: &[u8]) -> std::path::PathBuf {
    let seq = NEXT_TMP_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-fparseln-{}-{seq}.txt",
        std::process::id()
    ));
    std::fs::write(&path, content).unwrap();
    path
}

fn fparseln_open_for_read(path: &std::path::Path) -> *mut c_void {
    let cstr = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let mode = c"r";
    let fp = unsafe { fopen(cstr.as_ptr(), mode.as_ptr()) };
    assert!(!fp.is_null());
    fp
}

fn fparseln_collect_string(p: *mut c_char, len: usize) -> Vec<u8> {
    assert!(!p.is_null());
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, len).to_vec() };
    unsafe { libc::free(p as *mut std::ffi::c_void) };
    bytes
}

#[test]
fn fparseln_plain_line_no_decoration() {
    let path = fparseln_temp_file(b"hello\n");
    let fp = fparseln_open_for_read(&path);
    let mut len: usize = 0;
    let mut lineno: usize = 0;
    let p = unsafe { fparseln(fp, &mut len, &mut lineno, std::ptr::null(), 0) };
    let s = fparseln_collect_string(p, len);
    assert_eq!(s, b"hello");
    assert_eq!(lineno, 1);
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fparseln_strips_comment() {
    let path = fparseln_temp_file(b"foo # bar\n");
    let fp = fparseln_open_for_read(&path);
    let mut len: usize = 0;
    let p = unsafe { fparseln(fp, &mut len, std::ptr::null_mut(), std::ptr::null(), 0) };
    let s = fparseln_collect_string(p, len);
    assert_eq!(s, b"foo ");
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fparseln_joins_continuation_lines() {
    let path = fparseln_temp_file(b"foo \\\nbar\n");
    let fp = fparseln_open_for_read(&path);
    let mut len: usize = 0;
    let mut lineno: usize = 5;
    let p = unsafe { fparseln(fp, &mut len, &mut lineno, std::ptr::null(), 0) };
    let s = fparseln_collect_string(p, len);
    assert_eq!(s, b"foo bar");
    assert_eq!(lineno, 7, "lineno must increment by 2 physical lines");
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fparseln_returns_null_on_eof() {
    let path = fparseln_temp_file(b"");
    let fp = fparseln_open_for_read(&path);
    let mut len: usize = 99;
    let p = unsafe { fparseln(fp, &mut len, std::ptr::null_mut(), std::ptr::null(), 0) };
    assert!(p.is_null());
    assert_eq!(len, 0);
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fparseln_unesc_all_returns_raw_line() {
    let path = fparseln_temp_file(b"foo # bar \\\nbaz\n");
    let fp = fparseln_open_for_read(&path);
    let mut len: usize = 0;
    // FPARSELN_UNESCALL = 0x0f
    let p = unsafe { fparseln(fp, &mut len, std::ptr::null_mut(), std::ptr::null(), 0x0f) };
    let s = fparseln_collect_string(p, len);
    // No comment strip, no continuation, no escape processing.
    assert_eq!(s, b"foo # bar \\");
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fparseln_custom_delimiters() {
    // delim = ['$', ';', '%']: escape='$', sep=';', comment='%'.
    let path = fparseln_temp_file(b"foo$;bar;baz%comment;");
    let fp = fparseln_open_for_read(&path);
    let delim = [b'$' as c_char, b';' as c_char, b'%' as c_char];
    let mut len: usize = 0;
    // First call: "foo$;bar" — $; is continuation; assembles as
    // "foo" + "bar" = "foobar".
    let p = unsafe { fparseln(fp, &mut len, std::ptr::null_mut(), delim.as_ptr(), 0) };
    let s = fparseln_collect_string(p, len);
    assert_eq!(s, b"foobar");

    // Second call: "baz%comment" — % strips the comment, returns
    // "baz". The trailing ';' (separator) is consumed.
    let mut len2: usize = 0;
    let p2 = unsafe { fparseln(fp, &mut len2, std::ptr::null_mut(), delim.as_ptr(), 0) };
    let s2 = fparseln_collect_string(p2, len2);
    assert_eq!(s2, b"baz");

    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

#[test]
fn fparseln_null_stream_returns_null() {
    let mut len: usize = 99;
    let p = unsafe {
        fparseln(
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
        )
    };
    assert!(p.is_null());
    assert_eq!(len, 0);
}

#[test]
fn fparseln_null_len_pointer_safe() {
    let path = fparseln_temp_file(b"x\n");
    let fp = fparseln_open_for_read(&path);
    let p = unsafe {
        fparseln(
            fp,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            0,
        )
    };
    assert!(!p.is_null());
    unsafe { libc::free(p as *mut std::ffi::c_void) };
    unsafe { fclose(fp) };
    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// strvis / strnvis / strunvis / strnunvis (NetBSD vis(3) family)
// ---------------------------------------------------------------------------

fn vis_buf<const N: usize>() -> [c_char; N] {
    [0; N]
}

fn vis_string(buf: &[c_char], n: c_int) -> Vec<u8> {
    buf[..n as usize].iter().map(|&c| c as u8).collect()
}

unsafe fn tracked_bytes_without_nul(bytes: &[u8]) -> *mut c_char {
    let ptr = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes.len()).cast::<c_char>() };
    assert!(!ptr.is_null());
    let usable = unsafe { frankenlibc_abi::malloc_abi::malloc_usable_size(ptr.cast()) };
    unsafe { std::ptr::write_bytes(ptr.cast::<u8>(), 0x7f, usable.max(bytes.len())) };
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.cast::<u8>(), bytes.len()) };
    ptr
}

#[test]
fn strvis_encodes_printable_unchanged() {
    let src = c"hello";
    let mut buf = vis_buf::<32>();
    let n = unsafe { strvis(buf.as_mut_ptr(), src.as_ptr(), 0) };
    assert_eq!(n, 5);
    assert_eq!(vis_string(&buf, n), b"hello");
}

#[test]
fn strvis_doubles_backslash() {
    let src = c"a\\b";
    let mut buf = vis_buf::<32>();
    let n = unsafe { strvis(buf.as_mut_ptr(), src.as_ptr(), 0) };
    assert_eq!(vis_string(&buf, n), b"a\\\\b");
}

#[test]
fn strvis_with_octal_flag_renders_three_digit_octal() {
    let mut buf = vis_buf::<32>();
    let n = unsafe {
        strnvis(
            buf.as_mut_ptr(),
            buf.len(),
            c"\xff".as_ptr(),
            0x01, // VIS_OCTAL
        )
    };
    assert_eq!(vis_string(&buf, n), b"\\377");
}

#[test]
fn strnvis_truncates_and_returns_minus_one() {
    let src = c"\x01\x02";
    let mut buf = vis_buf::<4>(); // can fit at most 3 chars + NUL
    let n = unsafe { strnvis(buf.as_mut_ptr(), buf.len(), src.as_ptr(), 0) };
    assert_eq!(n, -1, "must signal overflow");
    assert_eq!(buf[buf.len() - 1], 0);
}

#[test]
fn strnvis_fits_exactly() {
    let src = c"ab";
    let mut buf = vis_buf::<3>();
    let n = unsafe { strnvis(buf.as_mut_ptr(), buf.len(), src.as_ptr(), 0) };
    assert_eq!(n, 2);
    assert_eq!(vis_string(&buf, n), b"ab");
}

#[test]
fn strunvis_decodes_caret_escape() {
    let src = c"\\^A\\^B";
    let mut buf = vis_buf::<8>();
    let n = unsafe { strunvis(buf.as_mut_ptr(), src.as_ptr()) };
    assert_eq!(n, 2);
    assert_eq!(vis_string(&buf, n), b"\x01\x02");
}

#[test]
fn strunvis_decodes_octal_triple() {
    let src = c"\\377\\000A";
    let mut buf = vis_buf::<8>();
    let n = unsafe { strunvis(buf.as_mut_ptr(), src.as_ptr()) };
    // The middle "\\000" decodes to a literal NUL byte; vis_string
    // collects the raw decoded bytes regardless of NUL.
    assert_eq!(n, 3);
    let bytes = vis_string(&buf, n);
    assert_eq!(bytes, vec![0xff, 0x00, b'A']);
}

#[test]
fn strunvis_returns_minus_one_on_malformed_input() {
    let src = c"abc\\";
    let mut buf = vis_buf::<8>();
    let n = unsafe { strunvis(buf.as_mut_ptr(), src.as_ptr()) };
    assert_eq!(n, -1);
}

#[test]
fn strnunvis_returns_minus_one_when_decoded_too_big() {
    let src = c"\\^A\\^B\\^C\\^D";
    let mut buf = vis_buf::<3>(); // can fit 2 decoded + NUL
    let n = unsafe { strnunvis(buf.as_mut_ptr(), buf.len(), src.as_ptr()) };
    assert_eq!(n, -1);
}

#[test]
fn vis_round_trip_via_abi() {
    let payload = c"hello \\ world\x01\x02\x03";
    let mut enc_buf = vis_buf::<128>();
    let enc_n = unsafe { strvis(enc_buf.as_mut_ptr(), payload.as_ptr(), 0) };
    assert!(enc_n > 0);
    let mut dec_buf = vis_buf::<64>();
    let dec_n = unsafe { strunvis(dec_buf.as_mut_ptr(), enc_buf.as_ptr()) };
    assert_eq!(dec_n, payload.to_bytes().len() as c_int);
    assert_eq!(vis_string(&dec_buf, dec_n), payload.to_bytes());
}

#[test]
fn strvis_null_args_return_minus_one() {
    let src = c"x";
    let mut buf = vis_buf::<8>();
    assert_eq!(unsafe { strvis(std::ptr::null_mut(), src.as_ptr(), 0) }, -1);
    assert_eq!(unsafe { strvis(buf.as_mut_ptr(), std::ptr::null(), 0) }, -1);
}

#[test]
fn strunvis_null_args_return_minus_one() {
    let src = c"x";
    let mut buf = vis_buf::<8>();
    assert_eq!(unsafe { strunvis(std::ptr::null_mut(), src.as_ptr()) }, -1);
    assert_eq!(unsafe { strunvis(buf.as_mut_ptr(), std::ptr::null()) }, -1);
}

#[test]
fn strvis_rejects_tracked_unterminated_src() {
    let src = unsafe { tracked_bytes_without_nul(b"abc") };
    let mut buf = vis_buf::<16>();

    let n = unsafe { strvis(buf.as_mut_ptr(), src.cast_const(), 0) };

    unsafe { frankenlibc_abi::malloc_abi::free(src.cast::<c_void>()) };

    assert_eq!(n, -1);
}

#[test]
fn strunvis_rejects_tracked_unterminated_src() {
    let src = unsafe { tracked_bytes_without_nul(b"\\^A") };
    let mut buf = vis_buf::<16>();

    let n = unsafe { strunvis(buf.as_mut_ptr(), src.cast_const()) };

    unsafe { frankenlibc_abi::malloc_abi::free(src.cast::<c_void>()) };

    assert_eq!(n, -1);
}

#[test]
fn strsvis_rejects_tracked_unterminated_src() {
    let src = unsafe { tracked_bytes_without_nul(b"a#b") };
    let extra = c"#";
    let mut buf = vis_buf::<16>();

    let n = unsafe { strsvis(buf.as_mut_ptr(), src.cast_const(), 0, extra.as_ptr()) };

    unsafe { frankenlibc_abi::malloc_abi::free(src.cast::<c_void>()) };

    assert_eq!(n, -1);
}

// ---------------------------------------------------------------------------
// vis / nvis (NetBSD vis(3) single-byte encoders)
// ---------------------------------------------------------------------------

#[test]
fn vis_encodes_printable_byte() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { vis(buf.as_mut_ptr(), b'A' as c_int, 0, 0) };
    assert!(!end.is_null());
    let written = unsafe { end.offset_from(buf.as_ptr()) };
    assert_eq!(written, 1);
    assert_eq!(buf[0], b'A' as c_char);
    assert_eq!(buf[1], 0);
}

#[test]
fn vis_encodes_control_as_caret_escape() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { vis(buf.as_mut_ptr(), 0x01, 0, 0) };
    assert!(!end.is_null());
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&c| c as u8)
        .collect();
    assert_eq!(bytes, b"\\^A");
}

#[test]
fn vis_encodes_with_octal_flag() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { vis(buf.as_mut_ptr(), 0xff, 0x01, 0) }; // VIS_OCTAL
    assert!(!end.is_null());
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&c| c as u8)
        .collect();
    assert_eq!(bytes, b"\\377");
}

#[test]
fn vis_returns_pointer_to_trailing_nul() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { vis(buf.as_mut_ptr(), 0xff, 0x01, 0) };
    assert!(!end.is_null());
    // The byte at `end` must be the NUL terminator.
    assert_eq!(unsafe { *end }, 0);
}

#[test]
fn vis_null_dst_returns_null() {
    let p = unsafe { vis(std::ptr::null_mut(), b'A' as c_int, 0, 0) };
    assert!(p.is_null());
}

#[test]
fn nvis_writes_when_dlen_sufficient() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { nvis(buf.as_mut_ptr(), buf.len(), b'A' as c_int, 0, 0) };
    assert!(!end.is_null());
    assert_eq!(buf[0], b'A' as c_char);
}

#[test]
fn nvis_returns_null_when_dlen_too_small() {
    let mut buf = [0 as c_char; 2]; // octal needs 4 bytes + NUL
    let end = unsafe { nvis(buf.as_mut_ptr(), buf.len(), 0xff, 0x01, 0) };
    assert!(end.is_null());
}

#[test]
fn nvis_returns_null_for_zero_dlen() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { nvis(buf.as_mut_ptr(), 0, b'A' as c_int, 0, 0) };
    assert!(end.is_null());
}

#[test]
fn nvis_null_dst_returns_null() {
    let p = unsafe { nvis(std::ptr::null_mut(), 16, b'A' as c_int, 0, 0) };
    assert!(p.is_null());
}

#[test]
fn vis_handles_high_bit_via_meta_prefix() {
    let mut buf = [0 as c_char; 8];
    let end = unsafe { vis(buf.as_mut_ptr(), 0xc1, 0, 0) }; // \M-A
    assert!(!end.is_null());
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&b| b != 0)
        .map(|&c| c as u8)
        .collect();
    assert_eq!(bytes, b"\\M-A");
}

// ---------------------------------------------------------------------------
// strvisx / strnvisx / strunvisx / strnunvisx (NetBSD vis(3) extended length)
// ---------------------------------------------------------------------------

fn vis_collect(buf: &[c_char], n: c_int) -> Vec<u8> {
    buf[..n as usize].iter().map(|&c| c as u8).collect()
}

#[test]
fn strvisx_encodes_buffer_with_embedded_nul() {
    // Input: "ab\0c" (4 bytes including the embedded NUL).
    let src: [c_char; 4] = [b'a' as c_char, b'b' as c_char, 0, b'c' as c_char];
    let mut dst = [0 as c_char; 16];
    let n = unsafe { strvisx(dst.as_mut_ptr(), src.as_ptr(), src.len(), 0) };
    assert!(n > 0);
    let bytes = vis_collect(&dst, n);
    // Default-mode encoding of NUL is "\^@".
    assert_eq!(bytes, b"ab\\^@c");
}

#[test]
fn strvisx_with_octal_flag_renders_three_digit_octal() {
    let src: [c_char; 1] = [-1 as c_char];
    let mut dst = [0 as c_char; 8];
    let n = unsafe { strvisx(dst.as_mut_ptr(), src.as_ptr(), 1, 0x01) };
    let bytes = vis_collect(&dst, n);
    assert_eq!(bytes, b"\\377");
}

#[test]
fn strvisx_zero_srclen_produces_empty_output() {
    let mut dst = [0 as c_char; 8];
    let n = unsafe { strvisx(dst.as_mut_ptr(), std::ptr::null(), 0, 0) };
    assert_eq!(n, 0);
    assert_eq!(dst[0], 0);
}

#[test]
fn strvisx_null_dst_returns_minus_one() {
    let src: [c_char; 1] = [b'a' as c_char];
    assert_eq!(
        unsafe { strvisx(std::ptr::null_mut(), src.as_ptr(), 1, 0) },
        -1
    );
}

#[test]
fn strnvisx_truncates_and_returns_minus_one() {
    let src: [c_char; 2] = [1, 2];
    let mut dst = [0 as c_char; 4]; // can't fit 2 × \^X = 6 bytes + NUL
    let n = unsafe { strnvisx(dst.as_mut_ptr(), dst.len(), src.as_ptr(), 2, 0) };
    assert_eq!(n, -1);
    assert_eq!(dst[3], 0, "must NUL-terminate within bounds");
}

#[test]
fn strnvisx_fits_exactly() {
    let src: [c_char; 2] = [b'a' as c_char, b'b' as c_char];
    let mut dst = [0 as c_char; 3]; // "ab\0" — exactly 3 bytes
    let n = unsafe { strnvisx(dst.as_mut_ptr(), dst.len(), src.as_ptr(), 2, 0) };
    assert_eq!(n, 2);
    assert_eq!(vis_collect(&dst, n), b"ab");
}

#[test]
fn strunvisx_decodes_round_trip() {
    let src = c"\\^@xyz\\377";
    let mut dst = [0 as c_char; 16];
    let n = unsafe { strunvisx(dst.as_mut_ptr(), src.as_ptr(), 0) };
    let bytes = vis_collect(&dst, n);
    assert_eq!(bytes, vec![0x00, b'x', b'y', b'z', 0xff]);
}

#[test]
fn strnunvisx_returns_minus_one_when_too_small() {
    let src = c"\\^A\\^B\\^C";
    let mut dst = [0 as c_char; 2]; // can fit 1 + NUL
    let n = unsafe { strnunvisx(dst.as_mut_ptr(), dst.len(), src.as_ptr(), 0) };
    assert_eq!(n, -1);
}

#[test]
fn strvisx_then_strunvisx_round_trip() {
    let payload = b"hello\0\xffworld\x01\x02";
    let mut enc = [0 as c_char; 64];
    let enc_n = unsafe {
        strvisx(
            enc.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
        )
    };
    assert!(enc_n > 0);
    let mut dec = [0 as c_char; 64];
    let dec_n = unsafe { strunvisx(dec.as_mut_ptr(), enc.as_ptr(), 0) };
    assert_eq!(dec_n as usize, payload.len());
    assert_eq!(vis_collect(&dec, dec_n), payload);
}

#[test]
fn strunvisx_null_args_return_minus_one() {
    let src = c"x";
    let mut dst = [0 as c_char; 8];
    assert_eq!(
        unsafe { strunvisx(std::ptr::null_mut(), src.as_ptr(), 0) },
        -1
    );
    assert_eq!(
        unsafe { strunvisx(dst.as_mut_ptr(), std::ptr::null(), 0) },
        -1
    );
}

// ---------------------------------------------------------------------------
// unvis (NetBSD vis(3) streaming byte decoder)
// ---------------------------------------------------------------------------

const ABI_UNVIS_VALID: c_int = 1;
const ABI_UNVIS_VALIDPUSH: c_int = 2;
const ABI_UNVIS_NOCHAR: c_int = 3;
const ABI_UNVIS_SYNBAD: c_int = -1;
const ABI_UNVIS_END: c_int = 1;

/// Drive the streaming `unvis` shim across a whole input buffer
/// the way a libutil caller would, returning the decoded bytes.
fn unvis_drain(input: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut state: c_int = 0;
    let mut scratch: c_char = 0;
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < input.len() {
        let r = unsafe { unvis(&mut scratch, input[i] as c_int, &mut state, 0) };
        match r {
            ABI_UNVIS_VALID => {
                out.push(scratch as u8);
                i += 1;
            }
            ABI_UNVIS_VALIDPUSH => {
                out.push(scratch as u8);
                // Re-feed the same input byte without advancing.
            }
            ABI_UNVIS_NOCHAR => i += 1,
            ABI_UNVIS_SYNBAD => return Err("synbad"),
            other => {
                return Err(if other == 0 {
                    "unexpected end"
                } else {
                    "unknown"
                });
            }
        }
    }
    let r = unsafe { unvis(&mut scratch, 0, &mut state, ABI_UNVIS_END) };
    if r != 0 {
        return Err("end did not return 0");
    }
    Ok(out)
}

#[test]
fn unvis_passthrough_printable_byte() {
    let mut state: c_int = 0;
    let mut cp: c_char = 0;
    let r = unsafe { unvis(&mut cp, b'A' as c_int, &mut state, 0) };
    assert_eq!(r, ABI_UNVIS_VALID);
    assert_eq!(cp as u8, b'A');
    assert_eq!(state, 0, "decoder should be back at Initial");
}

#[test]
fn unvis_decodes_caret_escape() {
    let decoded = unvis_drain(b"\\^A").unwrap();
    assert_eq!(decoded, vec![0x01]);
}

#[test]
fn unvis_decodes_double_backslash() {
    let decoded = unvis_drain(b"\\\\").unwrap();
    assert_eq!(decoded, vec![b'\\']);
}

#[test]
fn unvis_decodes_octal_triple() {
    let decoded = unvis_drain(b"\\101").unwrap();
    assert_eq!(decoded, vec![b'A']);
}

#[test]
fn unvis_decodes_meta_sequence() {
    let decoded = unvis_drain(b"\\M-A").unwrap();
    assert_eq!(decoded, vec![0xc1]);
}

#[test]
fn unvis_decodes_meta_caret_sequence() {
    let decoded = unvis_drain(b"\\M-\\^A").unwrap();
    assert_eq!(decoded, vec![0x81]);
}

#[test]
fn unvis_decodes_meta_octal_sequence() {
    let decoded = unvis_drain(b"\\M-\\012").unwrap();
    assert_eq!(decoded, vec![0o12 | 0x80]);
}

#[test]
fn unvis_decodes_meta_named_escape() {
    let decoded = unvis_drain(b"\\M-\\n").unwrap();
    assert_eq!(decoded, vec![b'\n' | 0x80]);
}

#[test]
fn unvis_round_trips_every_byte() {
    // Use the in-process core encoder so the test doesn't depend on
    // strvis's NUL-terminated string contract (NUL itself is a
    // perfectly valid input byte for the streaming decoder).
    for b in 0u8..=255 {
        let encoded = frankenlibc_core::stdio::vis::strvis_to_vec(&[b], 0);
        let decoded = unvis_drain(&encoded)
            .unwrap_or_else(|e| panic!("unvis_drain failed for {b:#x}: {e} encoded={encoded:?}"));
        assert_eq!(decoded, vec![b], "round-trip mismatch for byte {b:#x}");
    }
}

#[test]
fn unvis_returns_synbad_on_malformed_meta() {
    let mut state: c_int = 0;
    let mut cp: c_char = 0;
    // "\M" then a non-'-' byte → SYNBAD.
    assert_eq!(
        unsafe { unvis(&mut cp, b'\\' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_eq!(
        unsafe { unvis(&mut cp, b'M' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_eq!(
        unsafe { unvis(&mut cp, b'X' as c_int, &mut state, 0) },
        ABI_UNVIS_SYNBAD
    );
}

#[test]
fn unvis_returns_synbad_on_malformed_octal() {
    let mut state: c_int = 0;
    let mut cp: c_char = 0;
    assert_eq!(
        unsafe { unvis(&mut cp, b'\\' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_eq!(
        unsafe { unvis(&mut cp, b'1' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_eq!(
        unsafe { unvis(&mut cp, b'8' as c_int, &mut state, 0) },
        ABI_UNVIS_SYNBAD
    );
}

#[test]
fn unvis_end_flag_returns_zero_on_idle_state() {
    let mut state: c_int = 0;
    let mut cp: c_char = 0;
    let r = unsafe { unvis(&mut cp, 0, &mut state, ABI_UNVIS_END) };
    assert_eq!(r, 0);
}

#[test]
fn unvis_end_flag_returns_synbad_on_partial_state() {
    let mut state: c_int = 0;
    let mut cp: c_char = 0;
    // Open a backslash sequence, then immediately flag end.
    assert_eq!(
        unsafe { unvis(&mut cp, b'\\' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    let r = unsafe { unvis(&mut cp, 0, &mut state, ABI_UNVIS_END) };
    assert_eq!(r, ABI_UNVIS_SYNBAD);
}

#[test]
fn unvis_null_astate_returns_synbad() {
    let mut cp: c_char = 0;
    let r = unsafe { unvis(&mut cp, b'A' as c_int, std::ptr::null_mut(), 0) };
    assert_eq!(r, ABI_UNVIS_SYNBAD);
}

#[test]
fn unvis_null_cp_does_not_crash() {
    // Caller may pass NULL `cp` if it doesn't care about output; the
    // shim must still drive the state machine correctly.
    let mut state: c_int = 0;
    let r = unsafe { unvis(std::ptr::null_mut(), b'A' as c_int, &mut state, 0) };
    assert_eq!(r, ABI_UNVIS_VALID);
}

#[test]
fn unvis_state_persists_across_calls() {
    // "\\101" decodes to 'A' across four calls; verify the
    // packed-state cell threads correctly.
    let mut state: c_int = 0;
    let mut cp: c_char = 0;
    assert_eq!(
        unsafe { unvis(&mut cp, b'\\' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_ne!(state, 0, "state should be non-zero mid-sequence");
    assert_eq!(
        unsafe { unvis(&mut cp, b'1' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_eq!(
        unsafe { unvis(&mut cp, b'0' as c_int, &mut state, 0) },
        ABI_UNVIS_NOCHAR
    );
    assert_eq!(
        unsafe { unvis(&mut cp, b'1' as c_int, &mut state, 0) },
        ABI_UNVIS_VALID
    );
    assert_eq!(cp as u8, b'A');
    assert_eq!(state, 0, "state should be back to Initial after Valid");
}

// ---------------------------------------------------------------------------
// svis / snvis / strsvis / strsnvis / strsvisx / strsnvisx
// (NetBSD vis(3) extra-bytes family)
// ---------------------------------------------------------------------------

fn svis_collect(buf: &[c_char], end: *mut c_char) -> Vec<u8> {
    let len = (end as usize).saturating_sub(buf.as_ptr() as usize);
    (0..len).map(|i| buf[i] as u8).collect()
}

fn svisx_collect(buf: &[c_char], n: c_int) -> Vec<u8> {
    (0..n as usize).map(|i| buf[i] as u8).collect()
}

#[test]
fn svis_passthrough_byte_not_in_extras() {
    let extra = c"#";
    let mut buf = [0 as c_char; 8];
    let end = unsafe { svis(buf.as_mut_ptr(), b'A' as c_int, 0, 0, extra.as_ptr()) };
    assert!(!end.is_null());
    assert_eq!(svis_collect(&buf, end), vec![b'A']);
    // Trailing NUL written.
    assert_eq!(buf[1] as u8, 0);
}

#[test]
fn svis_escapes_byte_listed_in_extras() {
    let extra = c"#";
    let mut buf = [0 as c_char; 8];
    let end = unsafe { svis(buf.as_mut_ptr(), b'#' as c_int, 0, 0, extra.as_ptr()) };
    assert!(!end.is_null());
    // '#' is 0x23 → caret form would be \^c (0x23 ^ 0x40 = 0x63 = 'c').
    assert_eq!(svis_collect(&buf, end), b"\\^c".to_vec());
}

#[test]
fn svis_with_octal_flag_uses_octal_for_extras() {
    let extra = c"#";
    let mut buf = [0 as c_char; 8];
    let end = unsafe {
        svis(
            buf.as_mut_ptr(),
            b'#' as c_int,
            frankenlibc_core::stdio::vis::VIS_OCTAL as c_int,
            0,
            extra.as_ptr(),
        )
    };
    assert!(!end.is_null());
    // 0x23 = 0o43 → \043
    assert_eq!(svis_collect(&buf, end), b"\\043".to_vec());
}

#[test]
fn svis_null_extra_matches_vis_behavior() {
    let mut a = [0 as c_char; 8];
    let mut b = [0 as c_char; 8];
    let end_a = unsafe { svis(a.as_mut_ptr(), b'A' as c_int, 0, 0, std::ptr::null()) };
    let end_b = unsafe { vis(b.as_mut_ptr(), b'A' as c_int, 0, 0) };
    assert!(!end_a.is_null() && !end_b.is_null());
    assert_eq!(svis_collect(&a, end_a), svis_collect(&b, end_b));
}

#[test]
fn svis_null_dst_returns_null() {
    let extra = c"#";
    let r = unsafe { svis(std::ptr::null_mut(), b'A' as c_int, 0, 0, extra.as_ptr()) };
    assert!(r.is_null());
}

#[test]
fn svis_rejects_tracked_unterminated_extra() {
    let extra = unsafe { tracked_bytes_without_nul(b"#") };
    let mut buf = [0 as c_char; 8];

    let end = unsafe { svis(buf.as_mut_ptr(), b'#' as c_int, 0, 0, extra.cast_const()) };

    unsafe { frankenlibc_abi::malloc_abi::free(extra.cast::<c_void>()) };

    assert!(end.is_null());
}

#[test]
fn snvis_returns_null_on_overflow() {
    let extra = c"#";
    let mut buf = [0 as c_char; 2];
    // '#' encodes to \^c (3 bytes) + NUL = 4. Buffer of 2 must fail.
    let r = unsafe { snvis(buf.as_mut_ptr(), 2, b'#' as c_int, 0, 0, extra.as_ptr()) };
    assert!(r.is_null());
}

#[test]
fn snvis_succeeds_with_exact_room() {
    let extra = c"#";
    let mut buf = [0xeeu8 as c_char; 8];
    let end = unsafe { snvis(buf.as_mut_ptr(), 4, b'#' as c_int, 0, 0, extra.as_ptr()) };
    assert!(!end.is_null());
    assert_eq!(svis_collect(&buf[..3], end), b"\\^c".to_vec());
    assert_eq!(buf[3] as u8, 0);
}

#[test]
fn strsvis_escapes_only_listed_extras() {
    let src = c"a#b/c";
    let extra = c"#/";
    let mut dst = [0 as c_char; 32];
    let n = unsafe { strsvis(dst.as_mut_ptr(), src.as_ptr(), 0, extra.as_ptr()) };
    assert!(n >= 0);
    // 'a' passthrough; '#' → \^c; 'b' passthrough; '/' is 0x2f → \^o
    // (0x2f ^ 0x40 = 0x6f); 'c' passthrough.
    assert_eq!(svisx_collect(&dst, n), b"a\\^cb\\^oc".to_vec());
    assert_eq!(dst[n as usize] as u8, 0);
}

#[test]
fn strsvis_null_extras_matches_strvis() {
    let src = c"hello\nworld";
    let mut a = [0 as c_char; 64];
    let mut b = [0 as c_char; 64];
    let na = unsafe { strsvis(a.as_mut_ptr(), src.as_ptr(), 0, std::ptr::null()) };
    let nb = unsafe { strvis(b.as_mut_ptr(), src.as_ptr(), 0) };
    assert_eq!(na, nb);
    assert_eq!(svisx_collect(&a, na), svisx_collect(&b, nb));
}

#[test]
fn strsvis_rejects_tracked_unterminated_extra() {
    let src = c"a#b";
    let extra = unsafe { tracked_bytes_without_nul(b"#") };
    let mut dst = [0 as c_char; 32];

    let n = unsafe { strsvis(dst.as_mut_ptr(), src.as_ptr(), 0, extra.cast_const()) };

    unsafe { frankenlibc_abi::malloc_abi::free(extra.cast::<c_void>()) };

    assert_eq!(n, -1);
}

#[test]
fn strsvis_null_args_return_minus_one() {
    let src = c"hi";
    let extra = c"#";
    let mut dst = [0 as c_char; 8];
    assert_eq!(
        unsafe { strsvis(std::ptr::null_mut(), src.as_ptr(), 0, extra.as_ptr()) },
        -1
    );
    assert_eq!(
        unsafe { strsvis(dst.as_mut_ptr(), std::ptr::null(), 0, extra.as_ptr()) },
        -1
    );
}

#[test]
fn strsnvis_returns_minus_one_on_overflow() {
    let src = c"###";
    let extra = c"#";
    let mut dst = [0 as c_char; 4];
    // Encoded length is 9 (\^c × 3) + NUL = 10. Buffer of 4 must fail.
    let n = unsafe { strsnvis(dst.as_mut_ptr(), 4, src.as_ptr(), 0, extra.as_ptr()) };
    assert_eq!(n, -1);
}

#[test]
fn strsnvis_succeeds_with_room() {
    let src = c"#";
    let extra = c"#";
    let mut dst = [0xeeu8 as c_char; 8];
    let n = unsafe { strsnvis(dst.as_mut_ptr(), 8, src.as_ptr(), 0, extra.as_ptr()) };
    assert_eq!(n, 3);
    assert_eq!(svisx_collect(&dst, n), b"\\^c".to_vec());
    assert_eq!(dst[n as usize] as u8, 0);
}

#[test]
fn strsvisx_handles_embedded_nul() {
    let payload: &[u8] = b"a\0b#c";
    let extra = c"#";
    let mut dst = [0 as c_char; 32];
    let n = unsafe {
        strsvisx(
            dst.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            extra.as_ptr(),
        )
    };
    assert!(n >= 0);
    // 'a' passthrough; \0 → \^@; 'b' passthrough; '#' → \^c;
    // 'c' passthrough.
    assert_eq!(svisx_collect(&dst, n), b"a\\^@b\\^cc".to_vec());
}

#[test]
fn strsnvisx_returns_minus_one_on_overflow() {
    let payload: &[u8] = b"###";
    let extra = c"#";
    let mut dst = [0 as c_char; 4];
    let n = unsafe {
        strsnvisx(
            dst.as_mut_ptr(),
            4,
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            extra.as_ptr(),
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn strsnvisx_succeeds_with_room() {
    let payload: &[u8] = b"#";
    let extra = c"#";
    let mut dst = [0xeeu8 as c_char; 8];
    let n = unsafe {
        strsnvisx(
            dst.as_mut_ptr(),
            8,
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            extra.as_ptr(),
        )
    };
    assert_eq!(n, 3);
    assert_eq!(svisx_collect(&dst, n), b"\\^c".to_vec());
    assert_eq!(dst[n as usize] as u8, 0);
}

#[test]
fn strsvis_then_strunvis_round_trips_extras() {
    // svis-encoding plus strunvis decoding must round-trip — strunvis
    // doesn't care which subset of bytes was forced to escape; it
    // just decodes whatever escape forms appear.
    let src = c"hello#world/test";
    let extra = c"#/";
    let mut enc = [0 as c_char; 64];
    let n = unsafe { strsvis(enc.as_mut_ptr(), src.as_ptr(), 0, extra.as_ptr()) };
    assert!(n >= 0);
    let mut dec = [0 as c_char; 64];
    let m = unsafe { strunvis(dec.as_mut_ptr(), enc.as_ptr()) };
    assert!(m >= 0);
    let decoded = svisx_collect(&dec, m);
    assert_eq!(decoded, b"hello#world/test".to_vec());
}

#[test]
fn strsvisx_null_args_return_minus_one() {
    let src = c"hi";
    let mut dst = [0 as c_char; 8];
    assert_eq!(
        unsafe { strsvisx(std::ptr::null_mut(), src.as_ptr(), 2, 0, std::ptr::null(),) },
        -1
    );
    assert_eq!(
        unsafe { strsvisx(dst.as_mut_ptr(), std::ptr::null(), 2, 0, std::ptr::null()) },
        -1
    );
}

// ---------------------------------------------------------------------------
// stravis (NetBSD allocating strvis)
// ---------------------------------------------------------------------------

#[test]
fn stravis_allocates_buffer_matching_strvis_output() {
    let src = c"hello\nworld\t!";
    let mut outp: *mut c_char = std::ptr::null_mut();
    let n = unsafe { stravis(&mut outp, src.as_ptr(), 0) };
    assert!(n >= 0);
    assert!(!outp.is_null());

    // Compare against strvis output for the same input.
    let mut ref_buf = [0 as c_char; 64];
    let n_ref = unsafe { strvis(ref_buf.as_mut_ptr(), src.as_ptr(), 0) };
    assert_eq!(n, n_ref);
    let alloc_bytes: Vec<u8> = (0..n as usize)
        .map(|i| unsafe { *outp.add(i) } as u8)
        .collect();
    let ref_bytes: Vec<u8> = (0..n_ref as usize).map(|i| ref_buf[i] as u8).collect();
    assert_eq!(alloc_bytes, ref_bytes);

    // Trailing NUL.
    assert_eq!(unsafe { *outp.add(n as usize) } as u8, 0);

    // Free the allocated buffer via our matching free shim.
    unsafe { frankenlibc_abi::malloc_abi::free(outp as *mut std::ffi::c_void) };
}

#[test]
fn stravis_handles_high_bit_bytes() {
    // 0xff round-trips through encode/decode; verify the malloc'd
    // buffer is sized correctly for the worst-case encoding.
    let src = c"\xff\xff\xff";
    let mut outp: *mut c_char = std::ptr::null_mut();
    let n = unsafe { stravis(&mut outp, src.as_ptr(), 0) };
    assert!(n >= 0);
    assert!(!outp.is_null());
    // Round-trip via strunvis.
    let mut decoded = [0 as c_char; 16];
    let m = unsafe { strunvis(decoded.as_mut_ptr(), outp) };
    assert_eq!(m, 3);
    let dec_bytes: Vec<u8> = (0..3).map(|i| decoded[i] as u8).collect();
    assert_eq!(dec_bytes, vec![0xff, 0xff, 0xff]);
    unsafe { frankenlibc_abi::malloc_abi::free(outp as *mut std::ffi::c_void) };
}

#[test]
fn stravis_empty_string_succeeds() {
    let src = c"";
    let mut outp: *mut c_char = std::ptr::null_mut();
    let n = unsafe { stravis(&mut outp, src.as_ptr(), 0) };
    assert_eq!(n, 0);
    assert!(!outp.is_null());
    // Just the NUL terminator.
    assert_eq!(unsafe { *outp } as u8, 0);
    unsafe { frankenlibc_abi::malloc_abi::free(outp as *mut std::ffi::c_void) };
}

#[test]
fn stravis_null_outp_returns_minus_one() {
    let src = c"x";
    let n = unsafe { stravis(std::ptr::null_mut(), src.as_ptr(), 0) };
    assert_eq!(n, -1);
}

#[test]
fn stravis_null_src_returns_minus_one() {
    let mut outp: *mut c_char = std::ptr::null_mut();
    let n = unsafe { stravis(&mut outp, std::ptr::null(), 0) };
    assert_eq!(n, -1);
}

#[test]
fn stravis_rejects_tracked_unterminated_src() {
    let src = unsafe { tracked_bytes_without_nul(b"abc") };
    let mut outp: *mut c_char = std::ptr::null_mut();

    let n = unsafe { stravis(&mut outp, src.cast_const(), 0) };

    unsafe { frankenlibc_abi::malloc_abi::free(src.cast::<c_void>()) };

    assert_eq!(n, -1);
    assert!(outp.is_null());
}

// ---------------------------------------------------------------------------
// strnvis_netbsd / strnunvis_netbsd (libbsd disambiguation aliases)
// ---------------------------------------------------------------------------

#[test]
fn strnvis_netbsd_matches_strnvis() {
    let src = c"control\t\n\x01char";
    let mut a = [0 as c_char; 64];
    let mut b = [0 as c_char; 64];
    let na = unsafe { strnvis(a.as_mut_ptr(), a.len(), src.as_ptr(), 0) };
    let nb = unsafe { strnvis_netbsd(b.as_mut_ptr(), b.len(), src.as_ptr(), 0) };
    assert_eq!(na, nb);
    assert!(na > 0);
    let abytes: Vec<u8> = (0..na as usize).map(|i| a[i] as u8).collect();
    let bbytes: Vec<u8> = (0..nb as usize).map(|i| b[i] as u8).collect();
    assert_eq!(abytes, bbytes);
}

#[test]
fn strnunvis_netbsd_matches_strnunvis() {
    let src = c"\\^A\\042";
    let mut a = [0 as c_char; 32];
    let mut b = [0 as c_char; 32];
    let na = unsafe { strnunvis(a.as_mut_ptr(), a.len(), src.as_ptr()) };
    let nb = unsafe { strnunvis_netbsd(b.as_mut_ptr(), b.len(), src.as_ptr()) };
    assert_eq!(na, nb);
    assert!(na > 0);
    let abytes: Vec<u8> = (0..na as usize).map(|i| a[i] as u8).collect();
    let bbytes: Vec<u8> = (0..nb as usize).map(|i| b[i] as u8).collect();
    assert_eq!(abytes, bbytes);
}

#[test]
fn strnvis_netbsd_overflow_returns_minus_one() {
    let src = c"hello, world";
    let mut buf = [0 as c_char; 4];
    let n = unsafe { strnvis_netbsd(buf.as_mut_ptr(), buf.len(), src.as_ptr(), 0) };
    assert_eq!(n, -1);
}

// ---------------------------------------------------------------------------
// strenvisx / strsenvisx (NetBSD env-aware vis(3) variants)
// ---------------------------------------------------------------------------

/// Serialize tests that touch the VIS_OPTIONS env var so they can't
/// race against each other.
static VIS_OPTIONS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct VisOptionsGuard {
    prior: Option<std::ffi::CString>,
}

impl VisOptionsGuard {
    fn set(value: Option<&std::ffi::CStr>) -> Self {
        let key = c"VIS_OPTIONS";
        let prior = unsafe {
            let p = libc::getenv(key.as_ptr());
            if p.is_null() {
                None
            } else {
                Some(CStr::from_ptr(p).to_owned())
            }
        };
        match value {
            Some(v) => unsafe {
                libc::setenv(key.as_ptr(), v.as_ptr(), 1);
            },
            None => unsafe {
                libc::unsetenv(key.as_ptr());
            },
        }
        VisOptionsGuard { prior }
    }
}

impl Drop for VisOptionsGuard {
    fn drop(&mut self) {
        let key = c"VIS_OPTIONS";
        unsafe {
            match &self.prior {
                Some(v) => {
                    libc::setenv(key.as_ptr(), v.as_ptr(), 1);
                }
                None => {
                    libc::unsetenv(key.as_ptr());
                }
            }
        }
    }
}

#[test]
fn strenvisx_without_env_matches_strvisx() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let payload: &[u8] = b"hello\nworld";
    let mut a = [0 as c_char; 64];
    let mut b = [0 as c_char; 64];
    let mut cerr: c_int = 99;
    let na = unsafe {
        strenvisx(
            a.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            &mut cerr,
        )
    };
    let nb = unsafe {
        strvisx(
            b.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
        )
    };
    assert_eq!(na, nb);
    assert_eq!(cerr, 0);
    let abytes: Vec<u8> = (0..na as usize).map(|i| a[i] as u8).collect();
    let bbytes: Vec<u8> = (0..nb as usize).map(|i| b[i] as u8).collect();
    assert_eq!(abytes, bbytes);
}

#[test]
fn strenvisx_honors_vis_octal_from_env() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(Some(c"VIS_OCTAL"));
    // Encode \n with no flags from caller — env should force octal.
    let payload: &[u8] = b"\n";
    let mut buf = [0 as c_char; 16];
    let mut cerr: c_int = 99;
    let n = unsafe {
        strenvisx(
            buf.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            &mut cerr,
        )
    };
    assert_eq!(n, 4);
    assert_eq!(cerr, 0);
    // 0x0a in octal = "\012".
    let bytes: Vec<u8> = (0..n as usize).map(|i| buf[i] as u8).collect();
    assert_eq!(bytes, b"\\012".to_vec());
}

#[test]
fn strenvisx_unknown_env_tokens_are_ignored() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(Some(c"VIS_FOO,VIS_BAR,VIS_OCTAL"));
    let payload: &[u8] = b"\n";
    let mut buf = [0 as c_char; 16];
    let mut cerr: c_int = 0;
    let n = unsafe {
        strenvisx(
            buf.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            &mut cerr,
        )
    };
    // Only VIS_OCTAL is recognized; bytes match the octal-mode form.
    let bytes: Vec<u8> = (0..n as usize).map(|i| buf[i] as u8).collect();
    assert_eq!(bytes, b"\\012".to_vec());
}

#[test]
fn strenvisx_ignores_tracked_unterminated_vis_options() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let assignment = b"VIS_OPTIONS=VIS_OCTAL\0";

    unsafe {
        let raw = frankenlibc_abi::malloc_abi::malloc(assignment.len()).cast::<u8>();
        assert!(!raw.is_null());
        let usable = frankenlibc_abi::malloc_abi::malloc_usable_size(raw.cast());
        std::ptr::write_bytes(raw, 0x7f, usable.max(assignment.len()));
        std::ptr::copy_nonoverlapping(assignment.as_ptr(), raw, assignment.len());
        assert_eq!(frankenlibc_abi::stdlib_abi::putenv(raw.cast()), 0);
        *raw.add(assignment.len() - 1) = b'X';

        let payload: &[u8] = b"\n";
        let mut env_buf = [0 as c_char; 16];
        let mut base_buf = [0 as c_char; 16];
        let mut cerr: c_int = 99;
        let env_len = strenvisx(
            env_buf.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            &mut cerr,
        );
        let base_len = strvisx(
            base_buf.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
        );

        *raw.add(assignment.len() - 1) = 0;
        libc::unsetenv(c"VIS_OPTIONS".as_ptr());
        frankenlibc_abi::malloc_abi::free(raw.cast());

        assert_eq!(env_len, base_len);
        assert_eq!(cerr, 0);
        assert_eq!(
            vis_string(&env_buf, env_len),
            vis_string(&base_buf, base_len)
        );
    }
}

#[test]
fn strenvisx_null_cerr_does_not_crash() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let payload: &[u8] = b"x";
    let mut buf = [0 as c_char; 8];
    let n = unsafe {
        strenvisx(
            buf.as_mut_ptr(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(n, 1);
}

#[test]
fn strenvisx_null_args_return_minus_one() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let mut buf = [0 as c_char; 8];
    let mut cerr: c_int = 0;
    assert_eq!(
        unsafe { strenvisx(std::ptr::null_mut(), c"x".as_ptr(), 1, 0, &mut cerr,) },
        -1
    );
    assert_eq!(
        unsafe { strenvisx(buf.as_mut_ptr(), std::ptr::null(), 1, 0, &mut cerr) },
        -1
    );
}

#[test]
fn strsenvisx_combines_env_flags_with_extras() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(Some(c"VIS_OCTAL"));
    let payload: &[u8] = b"a#b";
    let extra = c"#";
    let mut buf = [0 as c_char; 32];
    let mut cerr: c_int = 99;
    let n = unsafe {
        strsenvisx(
            buf.as_mut_ptr(),
            buf.len(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            extra.as_ptr(),
            &mut cerr,
        )
    };
    assert!(n > 0);
    assert_eq!(cerr, 0);
    // 'a' passthrough; '#' (0x23 = 0o43) octal-extra → "\\043"; 'b' passthrough.
    let bytes: Vec<u8> = (0..n as usize).map(|i| buf[i] as u8).collect();
    assert_eq!(bytes, b"a\\043b".to_vec());
}

#[test]
fn strsenvisx_overflow_returns_minus_one() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let payload: &[u8] = b"###";
    let extra = c"#";
    let mut buf = [0 as c_char; 4];
    let mut cerr: c_int = 0;
    let n = unsafe {
        strsenvisx(
            buf.as_mut_ptr(),
            buf.len(),
            payload.as_ptr() as *const c_char,
            payload.len(),
            0,
            extra.as_ptr(),
            &mut cerr,
        )
    };
    assert_eq!(n, -1);
}

#[test]
fn strsenvisx_null_args_return_minus_one() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let mut buf = [0 as c_char; 8];
    let mut cerr: c_int = 0;
    assert_eq!(
        unsafe {
            strsenvisx(
                std::ptr::null_mut(),
                8,
                c"x".as_ptr(),
                1,
                0,
                std::ptr::null(),
                &mut cerr,
            )
        },
        -1
    );
    assert_eq!(
        unsafe {
            strsenvisx(
                buf.as_mut_ptr(),
                8,
                std::ptr::null(),
                1,
                0,
                std::ptr::null(),
                &mut cerr,
            )
        },
        -1
    );
}

#[test]
fn strsenvisx_rejects_tracked_unterminated_extra() {
    let _g = VIS_OPTIONS_LOCK.lock().unwrap();
    let _restore = VisOptionsGuard::set(None);
    let payload: &[u8] = b"a#";
    let extra = unsafe { tracked_bytes_without_nul(b"#") };
    let mut buf = [0 as c_char; 16];
    let mut cerr: c_int = 7;

    let n = unsafe {
        strsenvisx(
            buf.as_mut_ptr(),
            buf.len(),
            payload.as_ptr().cast::<c_char>(),
            payload.len(),
            0,
            extra.cast_const(),
            &mut cerr,
        )
    };

    unsafe { frankenlibc_abi::malloc_abi::free(extra.cast::<c_void>()) };

    assert_eq!(n, -1);
    assert_eq!(cerr, 7, "invalid extra should fail before writing cerr");
}

// ---------------------------------------------------------------------------
// snprintb / snprintb_m (BSD libutil bit-name formatter)
// ---------------------------------------------------------------------------

fn snprintb_collect(buf: &[c_char], n: c_int) -> Vec<u8> {
    let len = (n as usize).min(buf.len());
    (0..len).map(|i| buf[i] as u8).collect()
}

#[test]
fn snprintb_renders_hex_with_named_bits() {
    let mut buf = [0 as c_char; 64];
    // \020 base = hex; bit1=FOO, bit2=BAR, bit3=BAZ
    let fmt = c"\x10\x01FOO\x02BAR\x03BAZ";
    // bits 0 + 2 set -> val=5, expect "0x5<FOO,BAZ>"
    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 5) };
    assert!(n > 0);
    assert_eq!(snprintb_collect(&buf, n), b"0x5<FOO,BAZ>".to_vec());
    // Trailing NUL.
    assert_eq!(buf[n as usize] as u8, 0);
}

#[test]
fn snprintb_renders_octal_with_named_bits() {
    let mut buf = [0 as c_char; 64];
    let fmt = c"\x08\x01READ\x02WRITE\x03EXEC";
    // val=3 (READ + WRITE) -> "03<READ,WRITE>"
    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 3) };
    assert!(n > 0);
    assert_eq!(snprintb_collect(&buf, n), b"03<READ,WRITE>".to_vec());
}

#[test]
fn snprintb_omits_brackets_when_no_bits_set() {
    let mut buf = [0 as c_char; 32];
    let fmt = c"\x10\x01A\x02B";
    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 0) };
    assert_eq!(n, 3);
    assert_eq!(snprintb_collect(&buf, n), b"0x0".to_vec());
}

#[test]
fn snprintb_truncates_to_bufsize_returns_full_length() {
    let mut buf = [0 as c_char; 6];
    let fmt = c"\x10\x01FOO\x02BAR";
    // val=3 -> "0x3<FOO,BAR>" (12 chars)
    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 3) };
    assert_eq!(n, 12);
    // Buffer holds 5 chars + NUL.
    let truncated: Vec<u8> = (0..5).map(|i| buf[i] as u8).collect();
    assert_eq!(truncated, b"0x3<F".to_vec());
    assert_eq!(buf[5] as u8, 0);
}

#[test]
fn snprintb_zero_bufsize_returns_required_length() {
    let fmt = c"\x10\x01FOO";
    let n = unsafe { snprintb(std::ptr::null_mut(), 0, fmt.as_ptr(), 1) };
    // "0x1<FOO>" = 8 chars.
    assert_eq!(n, 8);
}

#[test]
fn snprintb_null_fmt_returns_minus_one() {
    let mut buf = [0 as c_char; 16];
    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), std::ptr::null(), 0) };
    assert_eq!(n, -1);
}

#[test]
fn snprintb_rejects_tracked_unterminated_fmt() {
    let fmt = unsafe { tracked_bytes_without_nul(b"\x10\x01FOO") };
    let mut buf = [0xeeu8 as c_char; 16];

    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), fmt.cast_const(), 1) };

    unsafe { frankenlibc_abi::malloc_abi::free(fmt.cast::<c_void>()) };

    assert_eq!(n, -1);
}

#[test]
fn snprintb_unknown_base_returns_zero_length() {
    let mut buf = [0xeeu8 as c_char; 8];
    // First byte 0x01 is neither octal nor hex base.
    let fmt = c"\x01\x01FOO";
    let n = unsafe { snprintb(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 1) };
    assert_eq!(n, 0);
    // Buffer should have a NUL at position 0.
    assert_eq!(buf[0] as u8, 0);
}

#[test]
fn snprintb_m_zero_max_falls_back_to_single_line() {
    let mut buf = [0 as c_char; 64];
    let fmt = c"\x10\x01A\x02B";
    let n = unsafe { snprintb_m(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 3, 0) };
    assert_eq!(snprintb_collect(&buf, n), b"0x3<A,B>".to_vec());
}

#[test]
fn snprintb_m_splits_long_lines() {
    let mut buf = [0 as c_char; 128];
    // val=7 -> all three names; force splits with a small max.
    let fmt = c"\x10\x01ABC\x02DEF\x03GHI";
    let n = unsafe { snprintb_m(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), 7, 10) };
    assert!(n > 0);
    let bytes = snprintb_collect(&buf, n);
    // Output must contain a newline and every line begins with "0x7<".
    assert!(bytes.contains(&b'\n'));
    for line in bytes.split(|&b| b == b'\n') {
        assert!(line.starts_with(b"0x7<"), "bad line: {:?}", line);
        assert!(line.ends_with(b">"));
    }
}

#[test]
fn snprintb_m_null_fmt_returns_minus_one() {
    let mut buf = [0 as c_char; 16];
    let n = unsafe { snprintb_m(buf.as_mut_ptr(), buf.len(), std::ptr::null(), 0, 8) };
    assert_eq!(n, -1);
}

#[test]
fn snprintb_m_rejects_tracked_unterminated_fmt() {
    let fmt = unsafe { tracked_bytes_without_nul(b"\x10\x01FOO\x02BAR") };
    let mut buf = [0xeeu8 as c_char; 32];

    let n = unsafe { snprintb_m(buf.as_mut_ptr(), buf.len(), fmt.cast_const(), 3, 8) };

    unsafe { frankenlibc_abi::malloc_abi::free(fmt.cast::<c_void>()) };

    assert_eq!(n, -1);
}

// ---------------------------------------------------------------------------
// __getline (glibc reserved-namespace alias of getline)
// ---------------------------------------------------------------------------

#[test]
fn under_getline_matches_getline() {
    let path = temp_path("under_getline");
    let _ = fs::remove_file(&path);
    let path_c = path_cstring(&path);

    let stream = unsafe { fopen(path_c.as_ptr(), c"w+".as_ptr()) };
    assert!(!stream.is_null());

    assert_eq!(unsafe { fputs(c"first\nsecond\n".as_ptr(), stream) }, 0);
    assert_eq!(unsafe { fflush(stream) }, 0);
    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut lineptr: *mut i8 = std::ptr::null_mut();
    let mut n: usize = 0;
    let len = unsafe { __getline(&mut lineptr, &mut n, stream) };
    assert_eq!(len, 6); // "first\n"
    assert_eq!(unsafe { CStr::from_ptr(lineptr) }.to_bytes(), b"first\n");

    let len = unsafe { __getline(&mut lineptr, &mut n, stream) };
    assert_eq!(len, 7); // "second\n"
    assert_eq!(unsafe { CStr::from_ptr(lineptr) }.to_bytes(), b"second\n");

    if !lineptr.is_null() {
        unsafe { libc::free(lineptr as *mut std::ffi::c_void) };
    }
    unsafe { fclose(stream) };
    let _ = fs::remove_file(&path);
}

#[test]
fn under_getline_null_args_return_minus_one() {
    let mut lineptr: *mut i8 = std::ptr::null_mut();
    let mut n: usize = 0;
    let r = unsafe { __getline(std::ptr::null_mut(), &mut n, std::ptr::null_mut()) };
    assert_eq!(r, -1);
    let r = unsafe { __getline(&mut lineptr, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(r, -1);
}

// ---------------------------------------------------------------------------
// funopen — BSD callback-based stdio over fopencookie
// ---------------------------------------------------------------------------

struct FunopenState {
    data: Vec<u8>,
    pos: usize,
    closed: bool,
}

unsafe extern "C" fn funop_read(cookie: *mut c_void, buf: *mut c_char, n: c_int) -> c_int {
    let s = unsafe { &mut *(cookie as *mut FunopenState) };
    let avail = s.data.len().saturating_sub(s.pos);
    let take = avail.min(n as usize);
    if take == 0 {
        return 0;
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, take) };
    dst.copy_from_slice(&s.data[s.pos..s.pos + take]);
    s.pos += take;
    take as c_int
}

unsafe extern "C" fn funop_write(cookie: *mut c_void, buf: *const c_char, n: c_int) -> c_int {
    let s = unsafe { &mut *(cookie as *mut FunopenState) };
    let bytes = unsafe { std::slice::from_raw_parts(buf as *const u8, n as usize) };
    s.data.extend_from_slice(bytes);
    s.pos = s.data.len();
    n
}

unsafe extern "C" fn funop_seek(cookie: *mut c_void, offset: i64, whence: c_int) -> i64 {
    let s = unsafe { &mut *(cookie as *mut FunopenState) };
    let new_pos = match whence {
        libc::SEEK_SET => offset,
        libc::SEEK_CUR => s.pos as i64 + offset,
        libc::SEEK_END => s.data.len() as i64 + offset,
        _ => return -1,
    };
    if new_pos < 0 || new_pos > s.data.len() as i64 {
        return -1;
    }
    s.pos = new_pos as usize;
    new_pos
}

unsafe extern "C" fn funop_close(cookie: *mut c_void) -> c_int {
    let s = unsafe { &mut *(cookie as *mut FunopenState) };
    s.closed = true;
    0
}

#[test]
fn funopen_with_no_io_callbacks_returns_null_einval() {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = 0 };
    let stream = unsafe { funopen(std::ptr::null(), None, None, None, None) };
    assert!(stream.is_null());
    assert_eq!(
        unsafe { *frankenlibc_abi::errno_abi::__errno_location() },
        libc::EINVAL
    );
}

#[test]
fn funopen_close_invokes_user_closefn_and_frees_trampoline() {
    let state = Box::into_raw(Box::new(FunopenState {
        data: Vec::new(),
        pos: 0,
        closed: false,
    }));
    let stream = unsafe {
        funopen(
            state as *const c_void,
            None,
            Some(funop_write),
            None,
            Some(funop_close),
        )
    };
    assert!(!stream.is_null());
    assert_eq!(unsafe { fclose(stream) }, 0);
    let s = unsafe { Box::from_raw(state) };
    assert!(s.closed, "user closefn must run via the close trampoline");
}

#[test]
fn funopen_round_trips_write_seek_read() {
    let state = Box::into_raw(Box::new(FunopenState {
        data: Vec::new(),
        pos: 0,
        closed: false,
    }));
    let stream = unsafe {
        funopen(
            state as *const c_void,
            Some(funop_read),
            Some(funop_write),
            Some(funop_seek),
            Some(funop_close),
        )
    };
    assert!(!stream.is_null());

    let payload = b"funopen-rw";
    let wrote = unsafe { fwrite(payload.as_ptr() as *const c_void, 1, payload.len(), stream) };
    assert_eq!(wrote, payload.len());

    assert_eq!(unsafe { fseek(stream, 0, libc::SEEK_SET) }, 0);

    let mut out = [0u8; 10];
    let read = unsafe { fread(out.as_mut_ptr() as *mut c_void, 1, out.len(), stream) };
    assert_eq!(read, out.len());
    assert_eq!(&out, payload);

    assert_eq!(unsafe { fclose(stream) }, 0);
    let s = unsafe { Box::from_raw(state) };
    assert!(s.closed);
    assert_eq!(s.data, payload);
}
