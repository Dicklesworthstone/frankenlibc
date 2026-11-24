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

use frankenlibc_abi::stdio_abi::CookieIoFuncs;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopencookie(
            cookie: *mut c_void,
            mode: *const c_char,
            funcs: CookieIoFuncs,
        ) -> *mut c_void;
        pub fn __errno_location() -> *mut c_int;
        pub fn ftrylockfile(f: *mut c_void) -> c_int;
        pub fn funlockfile(f: *mut c_void);
    }
    // Declared C-unwind to match fl's stdio entry points, which let a
    // fopencookie callback unwind through them (as glibc's do).
    unsafe extern "C-unwind" {
        pub fn fread(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fread_unlocked(p: *mut c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut c_void) -> usize;
        pub fn fflush(f: *mut c_void) -> c_int;
        pub fn fflush_unlocked(f: *mut c_void) -> c_int;
        pub fn fscanf(f: *mut c_void, format: *const c_char, ...) -> c_int;
        pub fn setvbuf(f: *mut c_void, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
        pub fn fclose(f: *mut c_void) -> c_int;
        pub fn ferror(f: *mut c_void) -> c_int;
        pub fn feof(f: *mut c_void) -> c_int;
        pub fn fgetc(f: *mut c_void) -> c_int;
        pub fn ungetc(c: c_int, f: *mut c_void) -> c_int;
        pub fn clearerr(f: *mut c_void);
        pub fn fileno(f: *mut c_void) -> c_int;
        pub fn fputc(byte: c_int, f: *mut c_void) -> c_int;
        pub fn fseeko(f: *mut c_void, offset: i64, whence: c_int) -> c_int;
        pub fn getdelim(p: *mut *mut c_char, n: *mut usize, d: c_int, f: *mut c_void) -> isize;
        pub fn getline(p: *mut *mut c_char, n: *mut usize, f: *mut c_void) -> isize;
    }
}
use frankenlibc_abi::stdio_abi as fl;

/// An errno value no path under test has any reason to produce, planted before
/// each call so "errno was left alone" is a positive observation rather than
/// the absence of one.
const SENTINEL_ERRNO: c_int = 0x5EED;

#[derive(Clone, Copy, Debug, PartialEq)]
enum InputSeekResult {
    Success,
    Error(c_int),
    SilentFailure,
    Missing,
}

#[derive(Clone, Copy, Debug)]
enum CookieInput {
    SameByte,
    DifferentByte,
    ScanLookahead,
    Consumed,
    Eof,
}

#[derive(Clone, Copy, Debug)]
enum CookieInputOperation {
    Flush,
    FlushUnlocked,
    ReplaceBuffer,
    Unbuffer,
    KeepBuffer,
    Seek,
}

struct InputSyncCookie {
    native: bool,
    position: usize,
    reads: usize,
    seeks: Vec<(i64, c_int)>,
    seek_result: InputSeekResult,
}

unsafe extern "C-unwind" fn input_sync_cookie_read(
    cookie: *mut c_void,
    buffer: *mut c_char,
    capacity: usize,
) -> isize {
    // A legal short read keeps the backend's position identical in both
    // providers without requiring their read-ahead strategies to be identical.
    // SAFETY: the observer owns this cookie and destination through the call.
    let state = unsafe { &mut *cookie.cast::<InputSyncCookie>() };
    state.reads += 1;
    if capacity == 0 || state.position == b"12 abc".len() {
        return 0;
    }
    unsafe { *buffer = b"12 abc"[state.position] as c_char };
    state.position += 1;
    1
}

unsafe extern "C-unwind" fn input_sync_cookie_seek(
    cookie: *mut c_void,
    offset: *mut i64,
    whence: c_int,
) -> c_int {
    // SAFETY: the selected provider supplies live cookie and offset storage.
    let (state, offset) = unsafe { (&mut *cookie.cast::<InputSyncCookie>(), &mut *offset) };
    state.seeks.push((*offset, whence));
    match state.seek_result {
        InputSeekResult::Success => {
            assert_eq!(whence, libc::SEEK_CUR);
            let position = state.position as i64 + *offset;
            assert!((0..=b"12 abc".len() as i64).contains(&position));
            state.position = position as usize;
            *offset = position;
            0
        }
        InputSeekResult::Error(error) => {
            // SAFETY: only the selected provider's current-thread errno changes.
            unsafe { *reentrant_errno_slot(state.native) = error };
            -1
        }
        InputSeekResult::SilentFailure => -1,
        InputSeekResult::Missing => unreachable!("a missing hook cannot be invoked"),
    }
}

#[derive(Debug, PartialEq)]
struct CookieInputObservation {
    result: c_int,
    errno: c_int,
    error: bool,
    eof: bool,
    backend_position: usize,
    seeks: Vec<(i64, c_int)>,
    next: c_int,
    next_called_read: bool,
}

fn observe_cookie_input_sync(
    native: bool,
    mode: c_int,
    input: CookieInput,
    operation: CookieInputOperation,
    seek_result: InputSeekResult,
    incoming_errno: c_int,
) -> CookieInputObservation {
    assert_ne!(fl::fopencookie as *const (), g::fopencookie as *const ());
    let mut state = InputSyncCookie {
        native,
        position: 0,
        reads: 0,
        seeks: Vec::new(),
        seek_result,
    };
    let hooks = CookieIoFuncs {
        read: Some(input_sync_cookie_read),
        write: None,
        seek: if seek_result == InputSeekResult::Missing {
            None
        } else {
            Some(input_sync_cookie_seek)
        },
        close: None,
    };
    let open = if native { fl::fopencookie } else { g::fopencookie };
    let configure = if native { fl::setvbuf } else { g::setvbuf };
    let read = if native { fl::fgetc } else { g::fgetc };
    let push = if native { fl::ungetc } else { g::ungetc };
    let close = if native { fl::fclose } else { g::fclose };
    let error = if native { fl::ferror } else { g::ferror };
    let eof = if native { fl::feof } else { g::feof };
    let mut initial_buffer = [0u8; 8];
    let mut replacement_buffer = [0u8; 16];
    // SAFETY: callback state, format/output slots, and both caller buffers stay
    // live through fclose; each FILE is used and closed through its provider.
    unsafe {
        let stream = open((&raw mut state).cast(), c"r".as_ptr(), hooks);
        assert!(!stream.is_null());
        assert_eq!(
            configure(
                stream,
                initial_buffer.as_mut_ptr().cast(),
                mode,
                initial_buffer.len()
            ),
            0
        );
        match input {
            CookieInput::SameByte | CookieInput::DifferentByte => {
                assert_eq!(read(stream), b'1' as c_int);
                let byte = if matches!(input, CookieInput::SameByte) {
                    b'1'
                } else {
                    b'Z'
                };
                assert_eq!(push(byte as c_int, stream), byte as c_int);
            }
            CookieInput::ScanLookahead => {
                let mut value: c_int = 0;
                let count = if native {
                    fl::fscanf(stream, c"%d".as_ptr(), &raw mut value)
                } else {
                    g::fscanf(stream, c"%d".as_ptr(), &raw mut value)
                };
                assert_eq!((count, value), (1, 12));
            }
            CookieInput::Consumed => assert_eq!(read(stream), b'1' as c_int),
            CookieInput::Eof => {
                for &byte in b"12 abc" {
                    assert_eq!(read(stream), byte as c_int);
                }
                assert_eq!(read(stream), libc::EOF);
            }
        }
        *reentrant_errno_slot(native) = incoming_errno;
        let result = match operation {
            CookieInputOperation::Flush => {
                if native {
                    fl::fflush(stream)
                } else {
                    g::fflush(stream)
                }
            }
            CookieInputOperation::FlushUnlocked => {
                if native {
                    fl::fflush_unlocked(stream)
                } else {
                    g::fflush_unlocked(stream)
                }
            }
            CookieInputOperation::ReplaceBuffer => configure(
                stream,
                replacement_buffer.as_mut_ptr().cast(),
                libc::_IOFBF,
                replacement_buffer.len(),
            ),
            CookieInputOperation::Unbuffer => {
                configure(stream, std::ptr::null_mut(), libc::_IONBF, 0)
            }
            CookieInputOperation::KeepBuffer => {
                configure(stream, std::ptr::null_mut(), libc::_IOLBF, 0)
            }
            CookieInputOperation::Seek => {
                if native {
                    fl::fseeko(stream, 0, libc::SEEK_CUR)
                } else {
                    g::fseeko(stream, 0, libc::SEEK_CUR)
                }
            }
        };
        let returned_errno = *reentrant_errno_slot(native);
        let error = error(stream) != 0;
        let eof = eof(stream) != 0;
        let backend_position = state.position;
        let seeks = std::mem::take(&mut state.seeks);
        let reads = state.reads;
        let next = read(stream);
        let next_called_read = state.reads != reads;
        assert_eq!(close(stream), 0);
        CookieInputObservation {
            result,
            errno: returned_errno,
            error,
            eof,
            backend_position,
            seeks,
            next,
            next_called_read,
        }
    }
}

fn cookie_input_seek_cases() -> [(InputSeekResult, c_int, c_int, c_int); 9] {
    [
        (InputSeekResult::Success, SENTINEL_ERRNO, 0, SENTINEL_ERRNO),
        (
            InputSeekResult::Error(libc::EIO),
            SENTINEL_ERRNO,
            -1,
            libc::EIO,
        ),
        (
            InputSeekResult::Error(libc::ESPIPE),
            SENTINEL_ERRNO,
            0,
            libc::ESPIPE,
        ),
        (
            InputSeekResult::SilentFailure,
            SENTINEL_ERRNO,
            -1,
            SENTINEL_ERRNO,
        ),
        (InputSeekResult::SilentFailure, 0, -1, 0),
        (InputSeekResult::SilentFailure, libc::ESPIPE, 0, libc::ESPIPE),
        (
            InputSeekResult::Missing,
            SENTINEL_ERRNO,
            -1,
            SENTINEL_ERRNO,
        ),
        (InputSeekResult::Missing, 0, -1, 0),
        (InputSeekResult::Missing, libc::ESPIPE, 0, libc::ESPIPE),
    ]
}

#[test]
fn cookie_input_flush_synchronizes_pushback_and_scan_lookahead() {
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for operation in [
            CookieInputOperation::Flush,
            CookieInputOperation::FlushUnlocked,
        ] {
            for (input, pushed, before, target, original) in [
                (CookieInput::SameByte, b'1', 1, 0, b'1'),
                (CookieInput::DifferentByte, b'Z', 1, 0, b'1'),
                (CookieInput::ScanLookahead, b' ', 3, 2, b' '),
            ] {
                for (seek_result, incoming, result, errno) in cookie_input_seek_cases() {
                    let host = observe_cookie_input_sync(
                        false, mode, input, operation, seek_result, incoming,
                    );
                    let synchronized = seek_result == InputSeekResult::Success;
                    assert_eq!(
                        host,
                        CookieInputObservation {
                            result,
                            errno,
                            error: false,
                            eof: false,
                            backend_position: if synchronized { target } else { before },
                            seeks: if seek_result == InputSeekResult::Missing {
                                vec![]
                            } else {
                                vec![(-1, libc::SEEK_CUR)]
                            },
                            next: (if synchronized { original } else { pushed }) as c_int,
                            next_called_read: synchronized,
                        }
                    );
                    assert_eq!(
                        observe_cookie_input_sync(
                            true, mode, input, operation, seek_result, incoming
                        ),
                        host,
                        "{mode}/{operation:?}/{input:?}/{seek_result:?}/{incoming}"
                    );
                }
            }
        }
    }
}

#[test]
fn cookie_input_rebuffer_synchronizes_or_preserves_existing_bytes() {
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for operation in [
            CookieInputOperation::ReplaceBuffer,
            CookieInputOperation::Unbuffer,
        ] {
            for (input, pushed, before, target, after_discard) in [
                (CookieInput::SameByte, b'1', 1, 0, b'2'),
                (CookieInput::ScanLookahead, b' ', 3, 2, b'a'),
            ] {
                for (seek_result, incoming, result, errno) in cookie_input_seek_cases() {
                    let host = observe_cookie_input_sync(
                        false, mode, input, operation, seek_result, incoming,
                    );
                    let synchronized = seek_result == InputSeekResult::Success;
                    assert_eq!(
                        host,
                        CookieInputObservation {
                            result,
                            errno,
                            error: false,
                            eof: false,
                            backend_position: if synchronized { target } else { before },
                            seeks: if seek_result == InputSeekResult::Missing {
                                vec![]
                            } else {
                                vec![(-1, libc::SEEK_CUR)]
                            },
                            next: (if result == 0 && !synchronized {
                                after_discard
                            } else {
                                pushed
                            }) as c_int,
                            next_called_read: result == 0,
                        }
                    );
                    assert_eq!(
                        observe_cookie_input_sync(
                            true, mode, input, operation, seek_result, incoming
                        ),
                        host,
                        "{mode}/{operation:?}/{input:?}/{seek_result:?}/{incoming}"
                    );
                }
            }
        }
    }
}

#[test]
fn cookie_input_flush_skips_clean_input_and_retains_eof() {
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for operation in [
            CookieInputOperation::Flush,
            CookieInputOperation::FlushUnlocked,
            CookieInputOperation::ReplaceBuffer,
            CookieInputOperation::Unbuffer,
            CookieInputOperation::KeepBuffer,
        ] {
            for (input, backend_position, next, eof, next_called_read) in [
                (CookieInput::Consumed, 1, b'2' as c_int, false, true),
                (CookieInput::Eof, 6, libc::EOF, true, false),
            ] {
                for (seek_result, incoming, _, _) in cookie_input_seek_cases() {
                    let host = observe_cookie_input_sync(
                        false, mode, input, operation, seek_result, incoming,
                    );
                    assert_eq!(
                        host,
                        CookieInputObservation {
                            result: 0,
                            errno: incoming,
                            error: false,
                            eof,
                            backend_position,
                            seeks: vec![],
                            next,
                            next_called_read,
                        }
                    );
                    assert_eq!(
                        observe_cookie_input_sync(
                            true, mode, input, operation, seek_result, incoming
                        ),
                        host,
                        "{mode}/{operation:?}/{input:?}/{seek_result:?}/{incoming}"
                    );
                }
            }
        }
    }
}

#[test]
fn cookie_input_seek_preserves_unsupplied_errno_and_failed_input() {
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for (input, before, target, retained, original, eof) in [
            (CookieInput::SameByte, 1, 0, b'1' as c_int, b'1' as c_int, false),
            (
                CookieInput::DifferentByte,
                1,
                0,
                b'Z' as c_int,
                b'1' as c_int,
                false,
            ),
            (
                CookieInput::ScanLookahead,
                3,
                2,
                b' ' as c_int,
                b' ' as c_int,
                false,
            ),
            (CookieInput::Eof, 6, 6, libc::EOF, libc::EOF, true),
        ] {
            for (seek_result, incoming, _, errno) in cookie_input_seek_cases() {
                let operation = CookieInputOperation::Seek;
                let host =
                    observe_cookie_input_sync(false, mode, input, operation, seek_result, incoming);
                let succeeded = seek_result == InputSeekResult::Success;
                assert_eq!(
                    host,
                    CookieInputObservation {
                        result: if succeeded { 0 } else { -1 },
                        errno,
                        error: false,
                        eof: eof && !succeeded,
                        backend_position: if succeeded { target } else { before },
                        seeks: if seek_result == InputSeekResult::Missing {
                            vec![]
                        } else {
                            vec![(target as i64 - before as i64, libc::SEEK_CUR)]
                        },
                        next: if succeeded { original } else { retained },
                        next_called_read: succeeded,
                    }
                );
                assert_eq!(
                    observe_cookie_input_sync(true, mode, input, operation, seek_result, incoming),
                    host,
                    "{mode}/{operation:?}/{input:?}/{seek_result:?}/{incoming}"
                );
            }
        }
    }
}

#[derive(Debug, PartialEq)]
struct CookieLineObservation {
    length: isize,
    bytes: Vec<u8>,
    error: bool,
    eof: bool,
    errno: c_int,
}

#[derive(Debug, PartialEq)]
struct CookieLineSequence {
    lines: Vec<CookieLineObservation>,
    buffer_result: c_int,
    push_result: c_int,
    sticky_line_called: bool,
    sticky_char_called: bool,
    eof_char: c_int,
    close_result: c_int,
    close_calls: usize,
}

struct LineCookie {
    data: &'static [u8],
    position: usize,
    calls: usize,
    closed: usize,
    error: c_int,
}

unsafe extern "C-unwind" fn line_cookie_read(
    cookie: *mut c_void,
    output: *mut c_char,
    count: usize,
) -> isize {
    // SAFETY: observe_cookie_lines keeps this state alive through fclose and
    // performs its stream operations sequentially.
    let state = unsafe { &mut *cookie.cast::<LineCookie>() };
    state.calls += 1;
    let copied = count.min(3).min(state.data.len() - state.position);
    if copied == 0 {
        if state.error != 0 {
            // SAFETY: glibc supplies this thread's writable errno slot.
            unsafe { *g::__errno_location() = state.error };
            return -1;
        }
        return 0;
    }
    // SAFETY: the callback receives count writable bytes; the static input is
    // disjoint and copied is bounded by both regions' remaining lengths.
    unsafe {
        std::ptr::copy_nonoverlapping(
            state.data.as_ptr().add(state.position),
            output.cast(),
            copied,
        );
    }
    state.position += copied;
    copied as isize
}

unsafe extern "C-unwind" fn line_cookie_close(cookie: *mut c_void) -> c_int {
    // SAFETY: the state remains live until the single fclose below completes.
    unsafe { (*cookie.cast::<LineCookie>()).closed += 1 };
    0
}

#[derive(Debug, PartialEq)]
struct CookieReadObservation {
    elements: usize,
    bytes: [u8; 8],
    error: bool,
    eof: bool,
    errno: c_int,
    callback_called: bool,
}

unsafe fn observe_cookie_fread(
    native: bool,
    unlocked: bool,
    stream: *mut c_void,
    state: *const LineCookie,
    size: usize,
    count: usize,
) -> CookieReadObservation {
    assert!(size * count <= 8);
    let read = match (native, unlocked) {
        (true, false) => fl::fread,
        (true, true) => fl::fread_unlocked,
        (false, false) => g::fread,
        (false, true) => g::fread_unlocked,
    };
    let error = if native { fl::ferror } else { g::ferror };
    let eof = if native { fl::feof } else { g::feof };
    let mut bytes = [0xa5; 8];
    // SAFETY: the sequence below retains the cookie and FILE through close.
    // Read the counter only before and after the callback, without keeping a
    // reference to cookie state across a callback that mutates it.
    unsafe {
        let previous_calls = (*state).calls;
        plant_errno();
        let elements = read(bytes.as_mut_ptr().cast(), size, count, stream);
        let errno = read_errno();
        CookieReadObservation {
            elements,
            bytes,
            error: error(stream) != 0,
            eof: eof(stream) != 0,
            errno,
            callback_called: (*state).calls != previous_calls,
        }
    }
}

fn cookie_fread_sequence(
    native: bool,
    unlocked: bool,
    buffer_mode: c_int,
    scenario: &str,
) -> (Vec<CookieReadObservation>, c_int, usize) {
    let mut state = LineCookie {
        data: b"abc",
        position: 0,
        calls: 0,
        closed: 0,
        error: if scenario == "retry-error" {
            libc::EIO
        } else {
            0
        },
    };
    let funcs = CookieIoFuncs {
        read: Some(line_cookie_read),
        close: Some(line_cookie_close),
        ..CookieIoFuncs::default()
    };
    let open_mode = match scenario {
        "write-only" => c"w",
        "append-only" => c"a",
        _ => c"r",
    };
    // SAFETY: cookie state and all buffers stay live through the provider's
    // fclose. Every request fits the eight-byte output used by the observer.
    unsafe {
        let cookie = std::ptr::addr_of_mut!(state);
        let stream = if native {
            fl::fopencookie(cookie.cast(), open_mode.as_ptr(), funcs)
        } else {
            g::fopencookie(cookie.cast(), open_mode.as_ptr(), funcs)
        };
        assert!(!stream.is_null());
        let set_buffer = if native { fl::setvbuf } else { g::setvbuf };
        let clear = if native { fl::clearerr } else { g::clearerr };
        let push = if native { fl::ungetc } else { g::ungetc };
        let close = if native { fl::fclose } else { g::fclose };
        assert_eq!(set_buffer(stream, std::ptr::null_mut(), buffer_mode, 0), 0);
        let read =
            |size, count| observe_cookie_fread(native, unlocked, stream, cookie, size, count);
        let observations = match scenario {
            "write-only" | "append-only" => vec![read(0, 2), read(2, 0), read(1, 2)],
            "sticky-eof" => {
                let mut observations = vec![read(2, 2)];
                // The backend gains new input, but EOF is a stream state: a
                // subsequent fread must not call it until EOF is cleared.
                state.data = b"abcde";
                observations.push(read(1, 2));
                clear(stream);
                observations.push(read(1, 2));
                observations.push(read(1, 1));
                assert_eq!(push(b'P' as c_int, stream), b'P' as c_int);
                observations.push(read(1, 2));
                observations
            }
            "retry-error" => {
                let mut observations = vec![read(1, 4)];
                state.data = b"abcde";
                // Unlike EOF, an error indicator must not suppress a new
                // input attempt; successful input retains the old ferror.
                observations.push(read(1, 1));
                observations
            }
            _ => unreachable!(),
        };
        (observations, close(stream), state.closed)
    }
}

#[test]
fn cookie_fread_write_only_never_invokes_read_hook() {
    assert_ne!(g::fread as *const (), fl::fread as *const ());
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for unlocked in [false, true] {
            for scenario in ["write-only", "append-only"] {
                let host = cookie_fread_sequence(false, unlocked, mode, scenario);
                assert_eq!((host.1, host.2), (0, 1));
                for (index, observation) in host.0.iter().enumerate() {
                    assert_eq!(observation.elements, 0);
                    assert_eq!(observation.bytes, [0xa5; 8]);
                    assert!(!observation.callback_called && !observation.eof);
                    assert_eq!(observation.error, index == 2);
                    assert_eq!(
                        observation.errno,
                        if index == 2 {
                            libc::EBADF
                        } else {
                            SENTINEL_ERRNO
                        }
                    );
                }
                assert_eq!(cookie_fread_sequence(true, unlocked, mode, scenario), host);
            }
        }
    }
}

#[test]
fn cookie_fread_eof_stays_set_until_clearerr_or_pushback() {
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for unlocked in [false, true] {
            let host = cookie_fread_sequence(false, unlocked, mode, "sticky-eof");
            assert_eq!((host.1, host.2), (0, 1));
            assert_eq!(
                host.0.iter().map(|o| o.elements).collect::<Vec<_>>(),
                [1, 0, 2, 0, 1]
            );
            assert_eq!(
                host.0.iter().map(|o| o.eof).collect::<Vec<_>>(),
                [true, true, false, true, true]
            );
            assert_eq!(
                host.0[0].bytes,
                [b'a', b'b', b'c', 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]
            );
            assert_eq!(host.0[1].bytes, [0xa5; 8]);
            assert!(!host.0[1].callback_called);
            assert_eq!(&host.0[2].bytes[..2], b"de");
            assert_eq!(host.0[4].bytes[0], b'P');
            assert!(host.0.iter().all(|o| !o.error && o.errno == SENTINEL_ERRNO));
            assert_eq!(
                cookie_fread_sequence(true, unlocked, mode, "sticky-eof"),
                host
            );
        }
    }
}

#[test]
fn cookie_fread_previous_error_allows_retry_and_stays_visible() {
    for mode in [libc::_IOFBF, libc::_IOLBF, libc::_IONBF] {
        for unlocked in [false, true] {
            let host = cookie_fread_sequence(false, unlocked, mode, "retry-error");
            assert_eq!((host.1, host.2), (0, 1));
            assert_eq!((host.0[0].elements, host.0[0].errno), (3, libc::EIO));
            assert_eq!((host.0[1].elements, host.0[1].errno), (1, SENTINEL_ERRNO));
            assert_eq!(host.0[1].bytes[0], b'd');
            assert!(
                host.0
                    .iter()
                    .all(|o| o.error && !o.eof && o.callback_called)
            );
            assert_eq!(
                cookie_fread_sequence(true, unlocked, mode, "retry-error"),
                host
            );
        }
    }
}

fn observe_cookie_lines(native: bool, mode: c_int, delimiter: u8) -> CookieLineSequence {
    let mut state = LineCookie {
        data: if delimiter == b'\n' {
            b"a\0b\nnext\nlast"
        } else {
            b"a\0b;next;last"
        },
        position: 0,
        calls: 0,
        closed: 0,
        error: 0,
    };
    let funcs = CookieIoFuncs {
        read: Some(line_cookie_read),
        close: Some(line_cookie_close),
        ..CookieIoFuncs::default()
    };
    // SAFETY: the hook state, NUL-terminated mode, and output slots stay live
    // through the matching provider's fclose. No stream escapes this helper.
    unsafe {
        let cookie = (&mut state as *mut LineCookie).cast();
        let stream = if native {
            fl::fopencookie(cookie, c"r".as_ptr(), funcs)
        } else {
            g::fopencookie(cookie, c"r".as_ptr(), funcs)
        };
        assert!(!stream.is_null());
        let set_buffer = if native { fl::setvbuf } else { g::setvbuf };
        let push = if native { fl::ungetc } else { g::ungetc };
        let scan = if native { fl::getdelim } else { g::getdelim };
        let error = if native { fl::ferror } else { g::ferror };
        let eof = if native { fl::feof } else { g::feof };
        let clear = if native { fl::clearerr } else { g::clearerr };
        let read_char = if native { fl::fgetc } else { g::fgetc };
        let close = if native { fl::fclose } else { g::fclose };
        let buffer_result = set_buffer(stream, std::ptr::null_mut(), mode, 0);
        let push_result = push(b'P' as c_int, stream);
        let mut line = std::ptr::null_mut();
        let mut capacity = 0;
        let mut read_line = || {
            plant_errno();
            let length = scan(&mut line, &mut capacity, delimiter as c_int, stream);
            let saved_errno = read_errno();
            let bytes = if length >= 0 && !line.is_null() && capacity > length as usize {
                // SAFETY: successful getdelim initializes length bytes plus a
                // NUL in this allocation; the reported capacity is checked.
                std::slice::from_raw_parts(line.cast::<u8>(), length as usize + 1).to_vec()
            } else {
                Vec::new()
            };
            CookieLineObservation {
                length,
                bytes,
                error: error(stream) != 0,
                eof: eof(stream) != 0,
                errno: saved_errno,
            }
        };
        let mut lines = vec![read_line(), read_line(), read_line()];
        let stopped_calls = state.calls;
        lines.push(read_line());
        let sticky_line_called = state.calls != stopped_calls;
        let eof_char = read_char(stream);
        let sticky_char_called = state.calls != stopped_calls;
        clear(stream);
        state.position = 0;
        lines.push(read_line());
        let close_result = close(stream);
        if native {
            frankenlibc_abi::malloc_abi::free(line.cast());
        } else {
            libc::free(line.cast());
        }
        CookieLineSequence {
            lines,
            buffer_result,
            push_result,
            sticky_line_called,
            sticky_char_called,
            eof_char,
            close_result,
            close_calls: state.closed,
        }
    }
}

#[test]
fn cookie_line_input_uses_callbacks_and_preserves_stop_state() {
    assert_ne!(g::getdelim as *const (), fl::getdelim as *const ());
    for mode in [libc::_IOFBF, libc::_IONBF] {
        for delimiter in *b"\n;" {
            let host = observe_cookie_lines(false, mode, delimiter);
            assert_eq!(
                host.lines.iter().map(|l| l.length).collect::<Vec<_>>(),
                [5, 5, 4, -1, 4]
            );
            assert_eq!(host.lines[0].bytes, [b'P', b'a', 0, b'b', delimiter, 0]);
            assert_eq!(host.lines[1].bytes, [b'n', b'e', b'x', b't', delimiter, 0]);
            assert_eq!(host.lines[2].bytes, b"last\0");
            assert!(host.lines[3].bytes.is_empty());
            assert_eq!(host.lines[4].bytes, [b'a', 0, b'b', delimiter, 0]);
            assert!(
                host.lines
                    .iter()
                    .all(|l| l.errno == SENTINEL_ERRNO && !l.error)
            );
            assert_eq!(
                host.lines.iter().map(|l| l.eof).collect::<Vec<_>>(),
                [false, false, true, true, false]
            );
            assert_eq!((host.buffer_result, host.push_result), (0, b'P' as c_int));
            assert!(!host.sticky_line_called && !host.sticky_char_called);
            assert_eq!(host.eof_char, libc::EOF);
            assert_eq!((host.close_result, host.close_calls), (0, 1));
            assert_eq!(observe_cookie_lines(true, mode, delimiter), host);
        }
    }
}

#[derive(Debug, PartialEq)]
struct NullBufferObservation {
    line: CookieLineObservation,
    buffer_null: bool,
    capacity_valid: bool,
    buffer_result: c_int,
    preflight: Option<c_int>,
    called_after_error: bool,
    close_result: c_int,
    close_calls: usize,
}

fn observe_null_line_buffer(
    native_call: bool,
    native_stream: bool,
    use_getline: bool,
    mode: c_int,
    stopped: bool,
) -> NullBufferObservation {
    let mut state = LineCookie {
        data: if stopped { b"" } else { b"line\n" },
        position: 0,
        calls: 0,
        closed: 0,
        error: if stopped { libc::EIO } else { 0 },
    };
    let funcs = CookieIoFuncs {
        read: Some(line_cookie_read),
        close: Some(line_cookie_close),
        ..CookieIoFuncs::default()
    };
    // SAFETY: all slots and the cookie stay live until fclose; the capacity
    // slot is output-only while line is NULL. It is read only after success.
    unsafe {
        let cookie = (&mut state as *mut LineCookie).cast();
        let stream = if native_stream {
            fl::fopencookie(cookie, c"r".as_ptr(), funcs)
        } else {
            g::fopencookie(cookie, c"r".as_ptr(), funcs)
        };
        assert!(!stream.is_null());
        let set_buffer = if native_stream {
            fl::setvbuf
        } else {
            g::setvbuf
        };
        let read_char = if native_stream { fl::fgetc } else { g::fgetc };
        let error = if native_stream { fl::ferror } else { g::ferror };
        let eof = if native_stream { fl::feof } else { g::feof };
        let close = if native_stream { fl::fclose } else { g::fclose };
        let buffer_result = set_buffer(stream, std::ptr::null_mut(), mode, 0);
        let preflight = stopped.then(|| read_char(stream));
        let previous_calls = state.calls;
        let mut line = std::ptr::null_mut();
        let mut capacity = std::mem::MaybeUninit::<usize>::uninit();
        plant_errno();
        let length = if use_getline {
            let scan = if native_call { fl::getline } else { g::getline };
            scan(&mut line, capacity.as_mut_ptr(), stream)
        } else {
            let scan = if native_call {
                fl::getdelim
            } else {
                g::getdelim
            };
            scan(&mut line, capacity.as_mut_ptr(), b'\n' as c_int, stream)
        };
        let saved_errno = read_errno();
        let capacity_valid = if length >= 0 {
            capacity.assume_init() > length as usize
        } else {
            false
        };
        let bytes = if length >= 0 && !line.is_null() && capacity_valid {
            std::slice::from_raw_parts(line.cast::<u8>(), length as usize + 1).to_vec()
        } else {
            Vec::new()
        };
        let observation = CookieLineObservation {
            length,
            bytes,
            error: error(stream) != 0,
            eof: eof(stream) != 0,
            errno: saved_errno,
        };
        let buffer_null = line.is_null();
        let called_after_error = stopped && state.calls != previous_calls;
        let close_result = close(stream);
        if native_call {
            frankenlibc_abi::malloc_abi::free(line.cast());
        } else {
            libc::free(line.cast());
        }
        NullBufferObservation {
            line: observation,
            buffer_null,
            capacity_valid,
            buffer_result,
            preflight,
            called_after_error,
            close_result,
            close_calls: state.closed,
        }
    }
}

#[test]
fn cookie_line_null_buffer_ignores_uninitialized_capacity() {
    assert_ne!(g::getline as *const (), fl::getline as *const ());
    for mode in [libc::_IOFBF, libc::_IONBF] {
        for use_getline in [false, true] {
            for stopped in [false, true] {
                let host = observe_null_line_buffer(false, false, use_getline, mode, stopped);
                assert_eq!(host.line.length, if stopped { -1 } else { 5 });
                assert_eq!(
                    host.line.bytes,
                    if stopped { &b""[..] } else { &b"line\n\0"[..] }
                );
                assert_eq!(host.line.errno, SENTINEL_ERRNO);
                assert_eq!((host.line.error, host.line.eof), (stopped, false));
                assert_eq!((host.buffer_null, host.capacity_valid), (stopped, !stopped));
                assert_eq!(host.preflight, stopped.then_some(libc::EOF));
                assert!(!host.called_after_error);
                assert_eq!(
                    (host.buffer_result, host.close_result, host.close_calls),
                    (0, 0, 1)
                );
                for native_stream in [false, true] {
                    assert_eq!(
                        observe_null_line_buffer(true, native_stream, use_getline, mode, stopped),
                        host
                    );
                }
            }
        }
    }
}

fn plant_errno() {
    unsafe { *g::__errno_location() = SENTINEL_ERRNO };
}

fn read_errno() -> c_int {
    unsafe { *g::__errno_location() }
}

/// `(return value, errno after, ferror, feof)`.
type Obs = (i64, c_int, c_int, c_int);

/// Both providers receive the same by-value hook table and run the same sequence.
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
            CookieIoFuncs::default(),
        )
    }
}

fn fl_open(mode: &[u8]) -> *mut c_void {
    let funcs = CookieIoFuncs::default();
    unsafe { fl::fopencookie(std::ptr::null_mut(), mode.as_ptr().cast(), funcs) }
}

#[derive(Debug, Default)]
struct WriteHookState {
    calls: usize,
    bytes: usize,
}

unsafe extern "C-unwind" fn recording_write(
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
        read: None,
        write: Some(recording_write),
        seek: None,
        close: None,
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
            funcs,
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
fn cookie_flush_short_write_does_not_retry_or_replay_output() {
    unsafe extern "C-unwind" fn short_write(
        cookie: *mut c_void,
        buf: *const c_char,
        count: usize,
    ) -> isize {
        // SAFETY: the helper keeps the byte vector alive until fclose returns;
        // the callback receives count readable bytes from the stdio backend.
        let output = unsafe { &mut *cookie.cast::<Vec<u8>>() };
        let count = count.min(2);
        output.extend_from_slice(unsafe { std::slice::from_raw_parts(buf.cast(), count) });
        count as isize
    }

    fn observe(native: bool) -> (c_int, bool, c_int, Vec<u8>) {
        let mut output = Vec::<u8>::new();
        let funcs = CookieIoFuncs {
            write: Some(short_write),
            ..CookieIoFuncs::default()
        };
        // SAFETY: the cookie, hook table, and stream remain valid throughout
        // the sequence. Both providers receive the same five-byte payload.
        unsafe {
            let cookie = (&mut output as *mut Vec<u8>).cast();
            let stream = if native {
                fl::fopencookie(cookie, c"w".as_ptr(), funcs)
            } else {
                g::fopencookie(cookie, c"w".as_ptr(), funcs)
            };
            assert!(!stream.is_null());
            let write = if native { fl::fwrite } else { g::fwrite };
            let flush = if native { fl::fflush } else { g::fflush };
            let error = if native { fl::ferror } else { g::ferror };
            let close = if native { fl::fclose } else { g::fclose };
            assert_eq!(write(b"abcde".as_ptr().cast(), 1, 5, stream), 5);
            let first = flush(stream);
            let failed = error(stream) != 0;
            let second = flush(stream);
            assert_eq!(close(stream), 0);
            (first, failed, second, output)
        }
    }

    let host = observe(false);
    assert_eq!(host, (-1, true, 0, b"ab".to_vec()));
    assert_eq!(observe(true), host);
}

#[test]
fn cookie_read_eintr_is_reported_without_retry() {
    unsafe extern "C-unwind" fn interrupted_read(
        cookie: *mut c_void,
        buf: *mut c_char,
        count: usize,
    ) -> isize {
        // SAFETY: observe keeps the call counter alive through fclose.
        let calls = unsafe { &mut *cookie.cast::<usize>() };
        *calls += 1;
        if *calls == 1 {
            // SAFETY: errno points to this thread's live errno cell.
            unsafe { *g::__errno_location() = libc::EINTR };
            return -1;
        }
        let copied = count.min(10);
        // SAFETY: the backend supplies count writable bytes.
        unsafe { std::ptr::copy_nonoverlapping(b"retry-read".as_ptr(), buf.cast(), copied) };
        copied as isize
    }

    fn observe(native: bool) -> (Obs, usize, [u8; 10], c_int) {
        let mut calls = 0usize;
        let funcs = CookieIoFuncs {
            read: Some(interrupted_read),
            ..CookieIoFuncs::default()
        };
        let mut output = [0xA5; 10];
        // SAFETY: cookie and output remain live, and each provider closes its own stream.
        unsafe {
            let cookie = (&mut calls as *mut usize).cast();
            let stream = if native {
                fl::fopencookie(cookie, c"r+".as_ptr(), funcs)
            } else {
                g::fopencookie(cookie, c"r+".as_ptr(), funcs)
            };
            assert!(!stream.is_null());
            let read = if native { fl::fread } else { g::fread };
            let error = if native { fl::ferror } else { g::ferror };
            let eof = if native { fl::feof } else { g::feof };
            let close = if native { fl::fclose } else { g::fclose };
            plant_errno();
            let count = read(output.as_mut_ptr().cast(), 1, output.len(), stream);
            let observed = (count as i64, read_errno(), error(stream), eof(stream));
            let closed = close(stream);
            (observed, calls, output, closed)
        }
    }

    let host = observe(false);
    assert_eq!(host, ((0, libc::EINTR, 1, 0), 1, [0xA5; 10], 0));
    assert_eq!(observe(true), host);
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

#[derive(Debug, PartialEq)]
struct ReentrantObservation {
    callback: &'static str,
    error: bool,
    eof: bool,
    descriptor: c_int,
    descriptor_errno: c_int,
    lock_result: c_int,
    cleared_error: bool,
    cleared_eof: bool,
}

struct ReentrantCookie {
    native: bool,
    stream: *mut c_void,
    position: i64,
    output: Vec<u8>,
    observations: Vec<ReentrantObservation>,
    write_limit: usize,
    recursive_output: u8,
    panic_on_write: bool,
}

fn reentrant_errno_slot(native: bool) -> *mut c_int {
    // SAFETY: both providers return the calling thread's writable errno slot.
    unsafe {
        if native {
            frankenlibc_abi::errno_abi::__errno_location()
        } else {
            g::__errno_location()
        }
    }
}

fn observe_reentrant_callback(state: &mut ReentrantCookie, callback: &'static str) {
    let error = if state.native { fl::ferror } else { g::ferror };
    let eof = if state.native { fl::feof } else { g::feof };
    let descriptor = if state.native { fl::fileno } else { g::fileno };
    let try_lock = if state.native {
        fl::ftrylockfile
    } else {
        g::ftrylockfile
    };
    let unlock = if state.native {
        fl::funlockfile
    } else {
        g::funlockfile
    };
    let clear = if state.native {
        fl::clearerr
    } else {
        g::clearerr
    };
    // SAFETY: the outer operation keeps this FILE and cookie live. These
    // callbacks deliberately reenter its status operations and recursive lock.
    let observation = unsafe {
        let error_before = error(state.stream) != 0;
        let eof_before = eof(state.stream) != 0;
        *reentrant_errno_slot(state.native) = SENTINEL_ERRNO;
        let fd = descriptor(state.stream);
        let descriptor_errno = *reentrant_errno_slot(state.native);
        let lock_result = try_lock(state.stream);
        if lock_result == 0 {
            unlock(state.stream);
        }
        clear(state.stream);
        ReentrantObservation {
            callback,
            error: error_before,
            eof: eof_before,
            descriptor: fd,
            descriptor_errno,
            lock_result,
            cleared_error: error(state.stream) != 0,
            cleared_eof: eof(state.stream) != 0,
        }
    };
    state.observations.push(observation);
}

unsafe extern "C-unwind" fn reentrant_cookie_read(
    cookie: *mut c_void,
    buffer: *mut c_char,
    capacity: usize,
) -> isize {
    // SAFETY: the test keeps the cookie alive through the corresponding close.
    let state = unsafe { &mut *cookie.cast::<ReentrantCookie>() };
    observe_reentrant_callback(state, "read");
    if capacity == 0 || state.position != 0 {
        return 0;
    }
    // SAFETY: the callback was supplied at least one writable byte.
    unsafe { *buffer = b'R' as c_char };
    state.position = 1;
    1
}

unsafe extern "C-unwind" fn reentrant_cookie_write(
    cookie: *mut c_void,
    buffer: *const c_char,
    length: usize,
) -> isize {
    // End this borrow before any nested output callback borrows the same
    // cookie. Recursion is limited to one additional write/flush operation.
    let (native, stream, recursive, panic_on_write) = {
        // SAFETY: the caller keeps the cookie alive for the complete operation.
        let state = unsafe { &mut *cookie.cast::<ReentrantCookie>() };
        observe_reentrant_callback(state, "write");
        let recursive = std::mem::take(&mut state.recursive_output);
        (state.native, state.stream, recursive, state.panic_on_write)
    };
    let put = if native { fl::fputc } else { g::fputc };
    let flush = if native { fl::fflush } else { g::fflush };
    // SAFETY: the public FILE lock is recursive and the stream is still live.
    unsafe {
        if recursive & 1 != 0 {
            assert_eq!(put(b'Z' as c_int, stream), b'Z' as c_int);
        }
        if recursive & 2 != 0 {
            assert_eq!(flush(stream), 0);
        }
    }
    if panic_on_write {
        // SAFETY: this is the callback provider's current-thread errno slot.
        unsafe { *reentrant_errno_slot(native) = SENTINEL_ERRNO };
        std::panic::panic_any("cookie callback unwind");
    }
    // SAFETY: nested callbacks have returned; no earlier cookie borrow remains.
    let state = unsafe { &mut *cookie.cast::<ReentrantCookie>() };
    let bytes = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    let accepted = length.min(state.write_limit);
    state.output.extend_from_slice(&bytes[..accepted]);
    state.position += accepted as i64;
    // Callbacks are allowed to set errno, including when accepting a short
    // prefix. Reacquiring libc's private lock must not replace that value.
    unsafe {
        *reentrant_errno_slot(native) = if accepted < length {
            libc::ENOSPC
        } else {
            SENTINEL_ERRNO
        };
    }
    accepted as isize
}

unsafe extern "C-unwind" fn reentrant_cookie_seek(
    cookie: *mut c_void,
    offset: *mut i64,
    whence: c_int,
) -> c_int {
    // SAFETY: the selected provider supplies the live cookie and offset slot.
    let state = unsafe { &mut *cookie.cast::<ReentrantCookie>() };
    observe_reentrant_callback(state, "seek");
    unsafe {
        if whence == libc::SEEK_CUR {
            *offset += state.position;
        }
        state.position = *offset;
    }
    0
}

unsafe extern "C-unwind" fn reentrant_cookie_close(cookie: *mut c_void) -> c_int {
    // SAFETY: the cookie remains live until this close callback returns.
    let state = unsafe { &mut *cookie.cast::<ReentrantCookie>() };
    observe_reentrant_callback(state, "close");
    0
}

fn reentrant_cookie_transcript(native: bool, phase: &str) -> String {
    let mut state = ReentrantCookie {
        native,
        stream: std::ptr::null_mut(),
        position: 0,
        output: Vec::new(),
        observations: Vec::new(),
        write_limit: if phase.ends_with("-short") {
            1
        } else if phase.ends_with("-fail") || phase == "retry" {
            0
        } else {
            usize::MAX
        },
        recursive_output: match phase {
            "recursive-write" => 1,
            "recursive-flush" => 2,
            "recursive-both" => 3,
            _ => 0,
        },
        panic_on_write: phase == "unwind",
    };
    let hooks = CookieIoFuncs {
        read: Some(reentrant_cookie_read),
        write: Some(reentrant_cookie_write),
        seek: Some(reentrant_cookie_seek),
        close: Some(reentrant_cookie_close),
    };
    let open = if native {
        fl::fopencookie
    } else {
        g::fopencookie
    };
    let configure = if native { fl::setvbuf } else { g::setvbuf };
    let write = if native { fl::fwrite } else { g::fwrite };
    let flush = if native { fl::fflush } else { g::fflush };
    let seek = if native { fl::fseeko } else { g::fseeko };
    let read = if native { fl::fgetc } else { g::fgetc };
    let close = if native { fl::fclose } else { g::fclose };
    let error = if native { fl::ferror } else { g::ferror };
    let mut results = Vec::new();
    // SAFETY: all inputs and callback storage outlive the stream; every branch
    // closes through its creator. The subprocess timer bounds a lock regression.
    unsafe {
        state.stream = open((&raw mut state).cast(), c"r+".as_ptr(), hooks);
        assert!(!state.stream.is_null());
        assert_eq!(
            configure(
                state.stream,
                std::ptr::null_mut(),
                if phase.starts_with("write") || phase == "retry" {
                    libc::_IONBF
                } else {
                    libc::_IOFBF
                },
                0
            ),
            0
        );
        let stream = state.stream;
        *reentrant_errno_slot(native) = SENTINEL_ERRNO;
        let mut record = |result: isize| {
            let error_number = *reentrant_errno_slot(native);
            results.push((result, error_number, error(stream) != 0));
        };
        if phase.starts_with("input-") {
            assert_eq!(read(stream), b'R' as c_int);
            let push = if native { fl::ungetc } else { g::ungetc };
            assert_eq!(push(b'R' as c_int, stream), b'R' as c_int);
            let result = match phase {
                "input-flush" => flush(stream),
                "input-flush-unlocked" => {
                    if native {
                        fl::fflush_unlocked(stream)
                    } else {
                        g::fflush_unlocked(stream)
                    }
                }
                "input-rebuffer" => configure(stream, std::ptr::null_mut(), libc::_IONBF, 0),
                _ => panic!("unknown input callback phase"),
            };
            record(result as isize);
            assert_eq!(read(stream), b'R' as c_int);
        } else if phase == "read" {
            assert_eq!(read(state.stream), b'R' as c_int);
        } else {
            let written = write(c"abc".as_ptr().cast(), 1, 3, stream);
            record(written as isize);
            if phase.starts_with("write") || phase == "retry" {
                assert_eq!(written, state.write_limit.min(3));
            } else {
                assert_eq!(written, 3);
            }
            match phase {
                "write" | "write-short" | "write-fail" | "flush" | "flush-short" | "flush-fail"
                | "recursive-write" | "recursive-flush" | "recursive-both" => {
                    record(flush(stream) as isize)
                }
                "seek" | "seek-fail" => record(seek(stream, 0, libc::SEEK_SET) as isize),
                "global" => record(flush(std::ptr::null_mut()) as isize),
                "rebuffer" => {
                    record(configure(stream, std::ptr::null_mut(), libc::_IONBF, 0) as isize)
                }
                "close" | "close-fail" => {}
                "retry" => {
                    state.write_limit = usize::MAX;
                    record(write(c"xy".as_ptr().cast(), 1, 2, stream) as isize);
                    assert_eq!(error(stream), 0, "callback clearerr must remain effective");
                }
                "unwind" => {
                    std::panic::set_hook(Box::new(|_| {}));
                    let unwound = std::panic::catch_unwind(|| flush(stream));
                    assert!(unwound.is_err());
                    assert_eq!(*reentrant_errno_slot(native), SENTINEL_ERRNO);
                    // A different thread proves the outer recursive FILE lock
                    // was released, not merely reacquirable by its old owner.
                    let address = stream as usize;
                    assert_eq!(
                        std::thread::spawn(move || {
                            let stream = address as *mut c_void;
                            let lock = if native {
                                fl::ftrylockfile
                            } else {
                                g::ftrylockfile
                            };
                            let unlock = if native {
                                fl::funlockfile
                            } else {
                                g::funlockfile
                            };
                            let result = lock(stream);
                            if result == 0 {
                                unlock(stream);
                            }
                            result
                        })
                        .join()
                        .unwrap(),
                        0
                    );
                    state.panic_on_write = false;
                    record(flush(stream) as isize);
                }
                _ => panic!("unknown callback phase"),
            }
        }
        let closed = close(stream);
        assert_eq!(closed, if phase == "close-fail" { libc::EOF } else { 0 });
        results.push((closed as isize, *reentrant_errno_slot(native), false));
    }
    assert!(!state.observations.is_empty());
    assert_eq!(state.observations.last().unwrap().callback, "close");
    for observation in &state.observations {
        assert_eq!(
            (observation.descriptor, observation.descriptor_errno),
            (-1, libc::EBADF)
        );
        assert_eq!(observation.lock_result, 0);
        assert!(!observation.cleared_error && !observation.cleared_eof);
    }
    match phase {
        "recursive-write" => assert_eq!(state.output, b"abc"),
        "recursive-flush" => assert_eq!(state.output, b"abcabc"),
        "recursive-both" => assert_eq!(state.output, b"abcZabc"),
        "retry" => {
            assert_eq!(state.output, b"xy");
            assert!(
                state
                    .observations
                    .iter()
                    .any(|entry| entry.callback == "write" && entry.error)
            );
        }
        "close-fail" => assert!(state.observations.last().unwrap().error),
        "unwind" => assert_eq!(state.output, b"abc"),
        _ => {}
    }
    format!("{:?} {:?} {results:?}", state.output, state.observations)
}

#[test]
fn cookie_callbacks_can_query_and_clear_their_stream() {
    const TEST: &str = "cookie_callbacks_can_query_and_clear_their_stream";
    const CHILD: &str = "FRANKENLIBC_COOKIE_REENTRY_CHILD";
    const PHASE: &str = "FRANKENLIBC_COOKIE_REENTRY_PHASE";
    if let Some(provider) = std::env::var_os(CHILD) {
        assert_ne!(fl::fopencookie as *const (), g::fopencookie as *const ());
        let phase = std::env::var(PHASE).unwrap();
        // SAFETY: only this selected test runs in the isolated process.
        unsafe { libc::alarm(5) };
        let transcript = reentrant_cookie_transcript(provider == "native", &phase);
        unsafe { libc::alarm(0) };
        println!("\nCOOKIE_REENTRY={transcript}");
        return;
    }
    for phase in [
        "write",
        "flush",
        "seek",
        "close",
        "read",
        "global",
        "rebuffer",
        "input-flush",
        "input-flush-unlocked",
        "input-rebuffer",
        "write-short",
        "write-fail",
        "flush-short",
        "flush-fail",
        "seek-fail",
        "close-fail",
        "retry",
        "recursive-write",
        "recursive-flush",
        "recursive-both",
        "unwind",
    ] {
        let mut oracle = None;
        for provider in ["host", "native"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture", "--test-threads=1"])
                .env(CHILD, provider)
                .env(PHASE, phase)
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{phase}/{provider}: {:?}\n{stdout}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                stdout.contains("1 passed"),
                "child must execute the regression"
            );
            let transcript = stdout
                .lines()
                .find_map(|line| line.strip_prefix("COOKIE_REENTRY="))
                .expect("callback transcript")
                .to_owned();
            if let Some(expected) = &oracle {
                assert_eq!(&transcript, expected, "{phase}");
            } else {
                oracle = Some(transcript);
            }
        }
    }
}
