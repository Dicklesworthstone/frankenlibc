#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fopencookie oracle

//! Differential gate for `fopencookie` streams whose read/write hooks are NULL
//! (bd-zpmf99). A NULL hook is a DOCUMENTED, legal configuration — the manual
//! says reads from such a stream return EOF and output is discarded — so it
//! must not be reported as a bad descriptor.
//!
//! fl set `EBADF` and returned -1 from both hooks. glibc never touches errno
//! on this path:
//!
//! * `_IO_cookie_read` with a NULL hook returns -1 and leaves errno alone, so
//!   `fread` yields 0 with the ERROR indicator set (not EOF).
//! * `_IO_cookie_write` with a NULL hook returns 0 and marks the stream in
//!   error, so `fwrite` still reports success (the bytes are buffered) and the
//!   failure surfaces at the following `fflush`.
//!
//! Measured on live glibc 2.42 before being asserted:
//!
//! ```text
//!   read=NULL   fread(buf,1,10,f)  -> 0   errno unchanged  ferror=1 feof=0
//!   write=NULL  fwrite(d,1,5,f)    -> 5   errno unchanged  ferror=0
//!               then fflush(f)     -> -1  errno unchanged  ferror=1
//! ```
//!
//! The errno half is the point of the bead and is asserted explicitly: each
//! call is preceded by planting a sentinel, and the sentinel must survive.
//! Asserting only the return codes would pass the implementation this gate
//! exists to catch.

use std::ffi::{c_char, c_int, c_void};

/// `cookie_io_functions_t` — four hook pointers, passed BY VALUE.
#[repr(C)]
#[derive(Clone, Copy)]
struct CookieIoFuncs {
    read: *mut c_void,
    write: *mut c_void,
    seek: *mut c_void,
    close: *mut c_void,
}

impl CookieIoFuncs {
    const fn all_null() -> Self {
        Self {
            read: std::ptr::null_mut(),
            write: std::ptr::null_mut(),
            seek: std::ptr::null_mut(),
            close: std::ptr::null_mut(),
        }
    }
}

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopencookie(
            cookie: *mut c_void,
            mode: *const c_char,
            funcs: CookieIoFuncs,
        ) -> *mut c_void;
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fflush(f: *mut c_void) -> c_int;
        pub fn setvbuf(f: *mut c_void, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn ferror(f: *mut c_void) -> c_int;
        pub fn feof(f: *mut c_void) -> c_int;
        pub fn __errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::stdio_abi as fl;

/// An errno value no path under test has any reason to produce, planted before
/// each call so "errno was left alone" is a positive observation rather than
/// the absence of one.
const SENTINEL_ERRNO: c_int = 0x5EED;

fn plant_errno() {
    unsafe { *g::__errno_location() = SENTINEL_ERRNO };
}

fn read_errno() -> c_int {
    unsafe { *g::__errno_location() }
}

/// `(return value, errno after, ferror, feof)`.
type Obs = (i64, c_int, c_int, c_int);

/// fl's `fopencookie` takes the hook struct behind a pointer rather than by
/// value, so the two sides are opened through slightly different spellings;
/// everything after the open is the same sequence.
macro_rules! null_hook_read {
    ($open:expr, $fread:path, $ferror:path, $feof:path, $fclose:path) => {{
        let mut buf = [0u8; 64];
        let f = $open;
        assert!(!f.is_null(), "fopencookie(\"r\") should succeed");
        plant_errno();
        let rc = unsafe { $fread(buf.as_mut_ptr().cast(), 1, 10, f) } as i64;
        let e = read_errno();
        let obs: Obs = (rc, e, unsafe { $ferror(f) }, unsafe { $feof(f) });
        unsafe { $fclose(f) };
        obs
    }};
}

macro_rules! null_hook_write {
    ($open:expr, $fwrite:path, $fflush:path, $ferror:path, $fclose:path) => {{
        let data = b"hello";
        let f = $open;
        assert!(!f.is_null(), "fopencookie(\"w\") should succeed");
        plant_errno();
        let wrc = unsafe { $fwrite(data.as_ptr().cast(), 1, 5, f) } as i64;
        let werr = read_errno();
        let wferr = unsafe { $ferror(f) };
        plant_errno();
        let frc = unsafe { $fflush(f) } as i64;
        let ferr = read_errno();
        let fferr = unsafe { $ferror(f) };
        unsafe { $fclose(f) };
        ((wrc, werr, wferr), (frc, ferr, fferr))
    }};
}

fn g_open(mode: &[u8]) -> *mut c_void {
    unsafe {
        g::fopencookie(
            std::ptr::null_mut(),
            mode.as_ptr().cast(),
            CookieIoFuncs::all_null(),
        )
    }
}

fn fl_open(mode: &[u8]) -> *mut c_void {
    let funcs = CookieIoFuncs::all_null();
    unsafe {
        fl::fopencookie(
            std::ptr::null_mut(),
            mode.as_ptr().cast(),
            (&funcs as *const CookieIoFuncs).cast(),
        )
    }
}

#[derive(Debug, Default)]
struct WriteHookState {
    calls: usize,
    bytes: usize,
}

unsafe extern "C" fn recording_write(
    cookie: *mut c_void,
    _buf: *const c_char,
    count: usize,
) -> isize {
    // SAFETY: each helper below passes a live `WriteHookState` as the cookie and
    // does not close the stream until after all callback observations complete.
    let state = unsafe { &mut *cookie.cast::<WriteHookState>() };
    state.calls += 1;
    state.bytes += count;
    count as isize
}

fn recording_funcs() -> CookieIoFuncs {
    CookieIoFuncs {
        read: std::ptr::null_mut(),
        write: recording_write as *const () as *mut c_void,
        seek: std::ptr::null_mut(),
        close: std::ptr::null_mut(),
    }
}

/// `(fwrite result, callback calls/bytes after fwrite, fflush result,
/// callback calls/bytes after fflush, ferror after fflush)`.
type BufferedWriteObs = (usize, usize, usize, c_int, usize, usize, c_int);

fn g_recording_write(mode: c_int) -> BufferedWriteObs {
    let mut state = WriteHookState::default();
    let stream = unsafe {
        g::fopencookie(
            (&mut state as *mut WriteHookState).cast(),
            c"w".as_ptr(),
            recording_funcs(),
        )
    };
    assert!(!stream.is_null());
    assert_eq!(
        unsafe { g::setvbuf(stream, std::ptr::null_mut(), mode, 64) },
        0
    );
    let wrote = unsafe { g::fwrite(b"hello".as_ptr().cast(), 1, 5, stream) };
    let after_write = (state.calls, state.bytes);
    let flushed = unsafe { g::fflush(stream) };
    let after_flush = (state.calls, state.bytes);
    let error = unsafe { g::ferror(stream) };
    assert_eq!(unsafe { g::fclose(stream) }, 0);
    (
        wrote,
        after_write.0,
        after_write.1,
        flushed,
        after_flush.0,
        after_flush.1,
        error,
    )
}

fn fl_recording_write(mode: c_int) -> BufferedWriteObs {
    let mut state = WriteHookState::default();
    let funcs = recording_funcs();
    let stream = unsafe {
        fl::fopencookie(
            (&mut state as *mut WriteHookState).cast(),
            c"w".as_ptr(),
            (&funcs as *const CookieIoFuncs).cast(),
        )
    };
    assert!(!stream.is_null());
    assert_eq!(
        unsafe { fl::setvbuf(stream, std::ptr::null_mut(), mode, 64) },
        0
    );
    let wrote = unsafe { fl::fwrite(b"hello".as_ptr().cast(), 1, 5, stream) };
    let after_write = (state.calls, state.bytes);
    let flushed = unsafe { fl::fflush(stream) };
    let after_flush = (state.calls, state.bytes);
    let error = unsafe { fl::ferror(stream) };
    assert_eq!(unsafe { fl::fclose(stream) }, 0);
    (
        wrote,
        after_write.0,
        after_write.1,
        flushed,
        after_flush.0,
        after_flush.1,
        error,
    )
}

#[test]
fn nonnull_write_hook_buffering_matches_glibc() {
    for (mode, expected) in [
        (0, (5, 0, 0, 0, 1, 5, 0)), // _IOFBF: callback waits for fflush.
        (2, (5, 1, 5, 0, 1, 5, 0)), // _IONBF: callback runs during fwrite.
    ] {
        let gg = g_recording_write(mode);
        let ff = fl_recording_write(mode);
        assert_eq!(gg, expected, "glibc oracle drifted for setvbuf mode {mode}");
        assert_eq!(
            ff, gg,
            "cookie write buffering mismatch for setvbuf mode {mode}"
        );
    }
}

/// A NULL read hook must not look like a bad descriptor.
#[test]
fn null_read_hook_matches_glibc() {
    let gg: Obs = null_hook_read!(g_open(b"r\0"), g::fread, g::ferror, g::feof, g::fclose);
    let ff: Obs = null_hook_read!(fl_open(b"r\0"), fl::fread, fl::ferror, fl::feof, fl::fclose);
    assert_eq!(
        ff, gg,
        "fread on a NULL-read cookie stream: fl={ff:?} glibc={gg:?} \
         (rc, errno, ferror, feof)"
    );
    // Reference half, so the two cannot drift together.
    assert_eq!(
        gg,
        (0, SENTINEL_ERRNO, 1, 0),
        "glibc: fread returns 0 with the ERROR indicator set and errno untouched"
    );
}

/// A NULL write hook discards output and leaves the stream in error, with
/// errno untouched throughout.
///
/// SCOPE — this arm asserts the END STATE and the errno invariant, not the
/// intermediate `fwrite` return value, because those diverge for a reason this
/// bead is not about. glibc gives a cookie stream a fully-buffered FILE, so
/// `fwrite` copies into the buffer and returns 5 and the hook does not run
/// until the flush; fl calls the hook straight from `fwrite`, so the short
/// write shows up in `fwrite`'s own return:
///
/// ```text
///   glibc: fwrite -> 5, ferror=0    then fflush -> -1, ferror=1
///   fl:    fwrite -> 0, ferror=1    then fflush ->  0, ferror=1
/// ```
///
/// That is a buffering difference affecting EVERY cookie stream, NULL hook or
/// not, and it is filed as bd-bpac6v with its own gate requirement (a
/// non-NULL hook recording call counts and byte counts). Asserting it here
/// would fail for a reason unrelated to bd-zpmf99. What both must agree on —
/// and what this arm pins — is that the stream ends in error and that no step
/// touches errno.
#[test]
fn null_write_hook_matches_glibc() {
    let gg = null_hook_write!(g_open(b"w\0"), g::fwrite, g::fflush, g::ferror, g::fclose);
    let ff = null_hook_write!(
        fl_open(b"w\0"),
        fl::fwrite,
        fl::fflush,
        fl::ferror,
        fl::fclose
    );

    // errno is untouched by every step, on both sides.
    assert_eq!(
        (ff.0.1, ff.1.1),
        (gg.0.1, gg.1.1),
        "errno after fwrite/fflush: fl={:?} glibc={:?}",
        (ff.0.1, ff.1.1),
        (gg.0.1, gg.1.1)
    );
    assert_eq!(
        (gg.0.1, gg.1.1),
        (SENTINEL_ERRNO, SENTINEL_ERRNO),
        "glibc leaves errno alone through both the write and the failing flush"
    );

    // And both end with the stream marked in error.
    assert_eq!(
        ff.1.2, gg.1.2,
        "ferror after fflush: fl={} glibc={}",
        ff.1.2, gg.1.2
    );
    assert_eq!(gg.1.2, 1, "glibc: the stream ends in error");
}

/// The specific regression: neither hook may report EBADF. Stated separately
/// from the differential so the intent survives even if the pair above is ever
/// narrowed.
#[test]
fn null_hooks_never_set_ebadf() {
    let r: Obs = null_hook_read!(fl_open(b"r\0"), fl::fread, fl::ferror, fl::feof, fl::fclose);
    assert_ne!(r.1, libc::EBADF, "fl set EBADF on a NULL read hook");
    assert_eq!(r.1, SENTINEL_ERRNO, "fl must leave errno untouched");

    let w = null_hook_write!(
        fl_open(b"w\0"),
        fl::fwrite,
        fl::fflush,
        fl::ferror,
        fl::fclose
    );
    assert_ne!(w.0.1, libc::EBADF, "fl set EBADF on a NULL write hook");
    assert_ne!(
        w.1.1,
        libc::EBADF,
        "fl set EBADF flushing a NULL write hook"
    );
}
