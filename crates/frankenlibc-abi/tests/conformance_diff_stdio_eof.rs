#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // Real FILE operations, compared with separately resolved glibc.

//! fread's sticky EOF applies to buffer underflow, while GNU's direct-read
//! path can read newly appended bytes with the old EOF indicator still set.
//! Run this target in both strict and hardened modes.

use std::ffi::{CString, c_char, c_int, c_long, c_void};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

struct StdioArm {
    name: &'static str,
    fopen: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    fdopen: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void,
    fmemopen: unsafe extern "C" fn(*mut c_void, usize, *const c_char) -> *mut c_void,
    open_memstream: unsafe extern "C" fn(*mut *mut c_char, *mut usize) -> *mut c_void,
    fopencookie: unsafe extern "C" fn(*mut c_void, *const c_char, fl::CookieIoFuncs) -> *mut c_void,
    fgetc: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    fputc: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    putc: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    fputc_unlocked: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    putc_unlocked: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    ungetc: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    fgets: unsafe extern "C-unwind" fn(*mut c_char, c_int, *mut c_void) -> *mut c_char,
    fscanf: unsafe extern "C-unwind" fn(*mut c_void, *const c_char, ...) -> c_int,
    getline: unsafe extern "C-unwind" fn(*mut *mut c_char, *mut usize, *mut c_void) -> isize,
    fclose: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    fflush: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    fflush_unlocked: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    fileno: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    setvbuf: unsafe extern "C-unwind" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int,
    fread: unsafe extern "C-unwind" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    fseek: unsafe extern "C-unwind" fn(*mut c_void, c_long, c_int) -> c_int,
    ftell: unsafe extern "C-unwind" fn(*mut c_void) -> c_long,
    feof: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    ferror: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    clearerr: unsafe extern "C-unwind" fn(*mut c_void),
}

fn candidate() -> StdioArm {
    StdioArm {
        name: "fl",
        fopen: fl::fopen,
        fdopen: fl::fdopen,
        fmemopen: fl::fmemopen,
        open_memstream: fl::open_memstream,
        fopencookie: fl::fopencookie,
        fgetc: fl::fgetc,
        fputc: fl::fputc,
        putc: fl::putc,
        fputc_unlocked: fl::fputc_unlocked,
        putc_unlocked: fl::putc_unlocked,
        ungetc: fl::ungetc,
        fgets: fl::fgets,
        fscanf: fl::fscanf,
        getline: fl::getline,
        fclose: fl::fclose,
        fflush: fl::fflush,
        fflush_unlocked: fl::fflush_unlocked,
        fileno: fl::fileno,
        setvbuf: fl::setvbuf,
        fread: fl::fread,
        fseek: fl::fseek,
        ftell: fl::ftell,
        feof: fl::feof,
        ferror: fl::ferror,
        clearerr: fl::clearerr,
    }
}

fn host() -> StdioArm {
    // SAFETY: each function type matches its named ABI. The resolver verifies
    // that no oracle pointer binds back to the candidate implementation.
    unsafe {
        StdioArm {
            name: "glibc",
            fopen: dlsym_oracle::host_fn(c"fopen", fl::fopen as *const ()),
            fdopen: dlsym_oracle::host_fn(c"fdopen", fl::fdopen as *const ()),
            fmemopen: dlsym_oracle::host_fn(c"fmemopen", fl::fmemopen as *const ()),
            open_memstream: dlsym_oracle::host_fn(
                c"open_memstream",
                fl::open_memstream as *const (),
            ),
            fopencookie: dlsym_oracle::host_fn(c"fopencookie", fl::fopencookie as *const ()),
            fgetc: dlsym_oracle::host_fn(c"fgetc", fl::fgetc as *const ()),
            fputc: dlsym_oracle::host_fn(c"fputc", fl::fputc as *const ()),
            putc: dlsym_oracle::host_fn(c"putc", fl::putc as *const ()),
            fputc_unlocked: dlsym_oracle::host_fn(
                c"fputc_unlocked",
                fl::fputc_unlocked as *const (),
            ),
            putc_unlocked: dlsym_oracle::host_fn(c"putc_unlocked", fl::putc_unlocked as *const ()),
            ungetc: dlsym_oracle::host_fn(c"ungetc", fl::ungetc as *const ()),
            fgets: dlsym_oracle::host_fn(c"fgets", fl::fgets as *const ()),
            fscanf: dlsym_oracle::host_fn(c"fscanf", fl::fscanf as *const ()),
            getline: dlsym_oracle::host_fn(c"getline", fl::getline as *const ()),
            fclose: dlsym_oracle::host_fn(c"fclose", fl::fclose as *const ()),
            fflush: dlsym_oracle::host_fn(c"fflush", fl::fflush as *const ()),
            fflush_unlocked: dlsym_oracle::host_fn(
                c"fflush_unlocked",
                fl::fflush_unlocked as *const (),
            ),
            fileno: dlsym_oracle::host_fn(c"fileno", fl::fileno as *const ()),
            setvbuf: dlsym_oracle::host_fn(c"setvbuf", fl::setvbuf as *const ()),
            fread: dlsym_oracle::host_fn(c"fread", fl::fread as *const ()),
            fseek: dlsym_oracle::host_fn(c"fseek", fl::fseek as *const ()),
            ftell: dlsym_oracle::host_fn(c"ftell", fl::ftell as *const ()),
            feof: dlsym_oracle::host_fn(c"feof", fl::feof as *const ()),
            ferror: dlsym_oracle::host_fn(c"ferror", fl::ferror as *const ()),
            clearerr: dlsym_oracle::host_fn(c"clearerr", fl::clearerr as *const ()),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct ReadAfterEof {
    count: usize,
    first_byte: u8,
    eof: bool,
    error: bool,
    eof_after_clear: bool,
    retry_count: usize,
    retry_first_byte: u8,
    retry_eof: bool,
    retry_error: bool,
}

fn observe(arm: &StdioArm, mode: c_int, request: usize) -> ReadAfterEof {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "fl-stdio-eof-{}-{}-{}",
        std::process::id(),
        arm.name,
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, b"x").unwrap();
    let c_path = CString::new(path.to_str().unwrap()).unwrap();
    let mut storage = [0u8; 64];
    let mut bytes = [0xa5u8; 128];
    // SAFETY: the regular file and caller-owned stdio buffer remain live until
    // fclose; every read fits bytes and every operation uses the same provider.
    unsafe {
        let stream = (arm.fopen)(c_path.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null(), "{}: fopen", arm.name);
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }
        assert_eq!(
            (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), mode, storage.len()),
            0
        );
        assert_eq!((arm.fread)(bytes.as_mut_ptr().cast(), 1, 1, stream), 1);
        assert_eq!(bytes[0], b'x');
        assert_eq!((arm.fread)(bytes.as_mut_ptr().cast(), 1, 1, stream), 0);
        assert_ne!((arm.feof)(stream), 0);
        assert_eq!((arm.ferror)(stream), 0);

        // A separate descriptor extends the file without changing this FILE's
        // cursor, buffer or EOF flag. The next read must choose its real path.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"y")
            .unwrap();
        bytes.fill(0xa5);
        let count = (arm.fread)(bytes.as_mut_ptr().cast(), 1, request, stream);
        let first_byte = bytes[0];
        assert!(bytes[1..].iter().all(|&byte| byte == 0xa5));
        let eof = (arm.feof)(stream) != 0;
        let error = (arm.ferror)(stream) != 0;
        (arm.clearerr)(stream);
        let eof_after_clear = (arm.feof)(stream) != 0;
        bytes[0] = 0xa5;
        let retry_count = (arm.fread)(bytes.as_mut_ptr().cast(), 1, 1, stream);
        let result = ReadAfterEof {
            count,
            first_byte,
            eof,
            error,
            eof_after_clear,
            retry_count,
            retry_first_byte: bytes[0],
            retry_eof: (arm.feof)(stream) != 0,
            retry_error: (arm.ferror)(stream) != 0,
        };
        assert_eq!((arm.fclose)(stream), 0);
        result
    }
}

fn compare(mode: c_int, request: usize, direct: bool) {
    let oracle = observe(&host(), mode, request);
    assert_eq!(
        oracle,
        ReadAfterEof {
            count: usize::from(direct),
            first_byte: if direct { b'y' } else { 0xa5 },
            eof: true,
            error: false,
            eof_after_clear: false,
            retry_count: usize::from(!direct),
            retry_first_byte: if direct { 0xa5 } else { b'y' },
            retry_eof: direct,
            retry_error: false,
        },
        "GNU oracle mode={mode} request={request}"
    );
    assert_eq!(
        observe(&candidate(), mode, request),
        oracle,
        "fread after file growth: mode={mode} request={request}"
    );
}

#[test]
fn fread_small_request_keeps_eof_until_clearerr() {
    compare(libc::_IOFBF, 1, false);
}

#[test]
fn fread_direct_requests_preserve_gnu_eof_bypass() {
    // Exact buffer capacity and larger reads both bypass underflow.
    for request in [64, 128] {
        compare(libc::_IOFBF, request, true);
    }
}

#[test]
fn fread_unbuffered_request_preserves_gnu_eof_bypass() {
    compare(libc::_IONBF, 1, true);
}

const RETRY_ERRNO_SENTINEL: c_int = 0x5eed;

#[derive(Clone, Copy, Debug, PartialEq)]
enum InputSyncOperation {
    Flush,
    FlushUnlocked,
    Rebuffer,
    Close,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum InputSyncBackend {
    Regular,
    Closed,
    InvalidSeek,
    Pipe,
}

#[derive(Debug, PartialEq)]
struct InputSyncObservation {
    result: c_int,
    errno: c_int,
    state: Option<(bool, bool, c_int)>,
}

fn observe_input_sync(
    arm: &StdioArm,
    backend: InputSyncBackend,
    operation: InputSyncOperation,
) -> InputSyncObservation {
    let mut initial_buffer = [0u8; 8];
    let mut replacement_buffer = [0u8; 16];
    // SAFETY: every descriptor belongs exclusively to this probe. The stream
    // retains its backing buffers through fclose, including a failed setvbuf.
    // The Closed case executes in a dedicated test subprocess so another test
    // cannot reuse the deliberately retired descriptor before fclose.
    unsafe {
        let fd = if backend == InputSyncBackend::Pipe {
            let mut pipe = [-1; 2];
            assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC), 0);
            assert_eq!(libc::write(pipe[1], b"abcdef".as_ptr().cast(), 6), 6);
            assert_eq!(libc::close(pipe[1]), 0);
            pipe[0]
        } else {
            let fd = libc::memfd_create(c"fl-input-sync".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::write(fd, b"abcdef".as_ptr().cast(), 6), 6);
            assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
            fd
        };
        let stream = (arm.fdopen)(fd, c"r".as_ptr());
        assert!(!stream.is_null());
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }
        assert_eq!((arm.fileno)(stream), fd);
        assert_eq!(
            (arm.setvbuf)(
                stream,
                initial_buffer.as_mut_ptr().cast(),
                libc::_IOFBF,
                initial_buffer.len(),
            ),
            0
        );
        assert_eq!((arm.fgetc)(stream), c_int::from(b'a'));
        match backend {
            InputSyncBackend::Closed => assert_eq!(libc::close(fd), 0),
            InputSyncBackend::InvalidSeek => {
                // Moving the shared descriptor behind stdio makes the
                // necessary relative rewind fail with EINVAL. Input already
                // buffered by stdio must survive that synchronization error.
                assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
            }
            InputSyncBackend::Regular | InputSyncBackend::Pipe => {}
        }
        *libc::__errno_location() = RETRY_ERRNO_SENTINEL;
        let result = match operation {
            InputSyncOperation::Flush => (arm.fflush)(stream),
            InputSyncOperation::FlushUnlocked => (arm.fflush_unlocked)(stream),
            InputSyncOperation::Rebuffer => (arm.setvbuf)(
                stream,
                replacement_buffer.as_mut_ptr().cast(),
                libc::_IOFBF,
                replacement_buffer.len(),
            ),
            InputSyncOperation::Close => (arm.fclose)(stream),
        };
        let errno = *libc::__errno_location();
        let state = if operation == InputSyncOperation::Close {
            None
        } else {
            let error = (arm.ferror)(stream) != 0;
            let eof = (arm.feof)(stream) != 0;
            let next = (arm.fgetc)(stream);
            let _ = (arm.fclose)(stream);
            Some((error, eof, next))
        };
        InputSyncObservation {
            result,
            errno,
            state,
        }
    }
}

fn input_sync_child(test: &str) -> bool {
    const CHILD: &str = "FRANKENLIBC_INPUT_SYNC_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(test) {
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, test)
        .output()
        .expect("run isolated input synchronization probe");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed;"),
        "{test}: {}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

#[test]
fn input_fflush_reports_seek_errors_without_discarding_buffered_bytes() {
    if !input_sync_child("input_fflush_reports_seek_errors_without_discarding_buffered_bytes") {
        return;
    }
    for operation in [InputSyncOperation::Flush, InputSyncOperation::FlushUnlocked] {
        for (backend, result, errno) in [
            (InputSyncBackend::Regular, 0, RETRY_ERRNO_SENTINEL),
            (InputSyncBackend::Closed, -1, libc::EBADF),
            (InputSyncBackend::InvalidSeek, -1, libc::EINVAL),
            (InputSyncBackend::Pipe, 0, libc::ESPIPE),
        ] {
            let oracle = observe_input_sync(&host(), backend, operation);
            assert_eq!(
                oracle,
                InputSyncObservation {
                    result,
                    errno,
                    state: Some((false, false, c_int::from(b'b'))),
                },
                "GNU {backend:?} {operation:?}"
            );
            assert_eq!(
                observe_input_sync(&candidate(), backend, operation),
                oracle,
                "{backend:?} {operation:?}"
            );
        }
    }
}

#[test]
fn input_setvbuf_preserves_old_buffer_when_synchronization_fails() {
    if !input_sync_child("input_setvbuf_preserves_old_buffer_when_synchronization_fails") {
        return;
    }
    for (backend, result, errno, next) in [
        (
            InputSyncBackend::Regular,
            0,
            RETRY_ERRNO_SENTINEL,
            c_int::from(b'b'),
        ),
        (InputSyncBackend::Closed, -1, libc::EBADF, c_int::from(b'b')),
        (
            InputSyncBackend::InvalidSeek,
            -1,
            libc::EINVAL,
            c_int::from(b'b'),
        ),
        (InputSyncBackend::Pipe, 0, libc::ESPIPE, libc::EOF),
    ] {
        let oracle = observe_input_sync(&host(), backend, InputSyncOperation::Rebuffer);
        assert_eq!(
            oracle,
            InputSyncObservation {
                result,
                errno,
                state: Some((false, false, next)),
            },
            "GNU {backend:?}"
        );
        assert_eq!(
            observe_input_sync(&candidate(), backend, InputSyncOperation::Rebuffer),
            oracle,
            "{backend:?}"
        );
    }
}

#[test]
fn input_fclose_reports_close_failure_but_ignores_input_reposition_failure() {
    if !input_sync_child("input_fclose_reports_close_failure_but_ignores_input_reposition_failure")
    {
        return;
    }
    for backend in [
        InputSyncBackend::Regular,
        InputSyncBackend::Closed,
        InputSyncBackend::InvalidSeek,
        InputSyncBackend::Pipe,
    ] {
        let oracle = observe_input_sync(&host(), backend, InputSyncOperation::Close);
        assert_eq!(
            oracle,
            InputSyncObservation {
                result: if backend == InputSyncBackend::Closed {
                    -1
                } else {
                    0
                },
                errno: if backend == InputSyncBackend::Closed {
                    libc::EBADF
                } else {
                    RETRY_ERRNO_SENTINEL
                },
                state: None,
            },
            "GNU {backend:?}"
        );
        assert_eq!(
            observe_input_sync(&candidate(), backend, InputSyncOperation::Close),
            oracle,
            "{backend:?}"
        );
    }
}

#[derive(Clone, Copy, Debug)]
enum RetryRead {
    Block,
    Line,
    AllocatedLine,
}

#[derive(Debug, PartialEq, Eq)]
struct ReadAfterError {
    result: isize,
    bytes: [u8; 32],
    errno: c_int,
    error: bool,
    eof: bool,
}

unsafe extern "C-unwind" fn pipe_cookie_read(
    cookie: *mut c_void,
    buf: *mut c_char,
    size: usize,
) -> isize {
    // SAFETY: observe_error_retry keeps this descriptor and callback buffer live.
    unsafe { libc::read(*cookie.cast::<c_int>(), buf.cast(), size) }
}

unsafe extern "C-unwind" fn pipe_cookie_close(cookie: *mut c_void) -> c_int {
    // SAFETY: this callback owns the descriptor until fclose invokes it once.
    unsafe { libc::close(*cookie.cast::<c_int>()) }
}

fn observe_error_retry(
    arm: &StdioArm,
    mode: c_int,
    request: usize,
    payload: &[u8],
    close_writer: bool,
    cookie: bool,
    operation: RetryRead,
) -> ReadAfterError {
    let mut pipe = [-1; 2];
    let mut storage = [0u8; 8];
    let mut bytes = [0xa5u8; 32];
    assert!(request > 1 && request <= bytes.len());
    // SAFETY: the pipe descriptor, cookie context and caller-owned buffers stay
    // live until fclose; requests fit bytes. Each arm owns its own real pipe.
    unsafe {
        assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_NONBLOCK), 0);
        let mut read_fd = pipe[0];
        let stream = if cookie {
            (arm.fopencookie)(
                (&mut read_fd as *mut c_int).cast(),
                c"r".as_ptr(),
                fl::CookieIoFuncs {
                    read: Some(pipe_cookie_read),
                    close: Some(pipe_cookie_close),
                    ..Default::default()
                },
            )
        } else {
            (arm.fdopen)(read_fd, c"r".as_ptr())
        };
        assert!(!stream.is_null(), "{}: open stream", arm.name);
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }
        assert_eq!(
            (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), mode, storage.len()),
            0
        );

        // The first read creates a real transient error. No clearerr occurs
        // between that error and the operation under test.
        *libc::__errno_location() = 0;
        let first = (arm.fgetc)(stream);
        let first_errno = *libc::__errno_location();
        assert_eq!(first, libc::EOF, "{}: initial read", arm.name);
        assert_eq!(first_errno, libc::EAGAIN, "{}: initial errno", arm.name);
        assert_ne!((arm.ferror)(stream), 0);
        assert_eq!((arm.feof)(stream), 0);
        if !payload.is_empty() {
            assert_eq!(
                libc::write(pipe[1], payload.as_ptr().cast(), payload.len()),
                payload.len() as isize
            );
        }
        if close_writer {
            assert_eq!(libc::close(pipe[1]), 0);
        }

        *libc::__errno_location() = RETRY_ERRNO_SENTINEL;
        let result = match operation {
            RetryRead::Block => (arm.fread)(bytes.as_mut_ptr().cast(), 1, request, stream) as isize,
            RetryRead::Line => {
                let result = (arm.fgets)(bytes.as_mut_ptr().cast(), request as c_int, stream);
                assert!(result.is_null() || result == bytes.as_mut_ptr().cast());
                isize::from(!result.is_null())
            }
            RetryRead::AllocatedLine => {
                // getline owns reallocatable storage. Never give it a pointer
                // into the stack array, even when the expected result is -1.
                let initial = libc::malloc(bytes.len()).cast::<c_char>();
                assert!(!initial.is_null());
                std::ptr::write_bytes(initial, 0xa5, bytes.len());
                let mut line = initial;
                let mut capacity = bytes.len();
                *libc::__errno_location() = RETRY_ERRNO_SENTINEL;
                let result = (arm.getline)(&mut line, &mut capacity, stream);
                let saved_errno = *libc::__errno_location();
                assert_eq!(line, initial, "{}: getline changed buffer", arm.name);
                assert_eq!(capacity, bytes.len());
                std::ptr::copy_nonoverlapping(line.cast::<u8>(), bytes.as_mut_ptr(), bytes.len());
                libc::free(line.cast());
                *libc::__errno_location() = saved_errno;
                result
            }
        };
        let saved_errno = *libc::__errno_location();
        let observation = ReadAfterError {
            result,
            bytes,
            errno: saved_errno,
            error: (arm.ferror)(stream) != 0,
            eof: (arm.feof)(stream) != 0,
        };
        assert_eq!((arm.fclose)(stream), 0);
        if !close_writer {
            assert_eq!(libc::close(pipe[1]), 0);
        }
        observation
    }
}

#[test]
fn fread_retries_after_error_without_clearerr() {
    let payload = b"payload\n";
    for mode in [libc::_IOFBF, libc::_IONBF] {
        // With an eight-byte buffer, these cover refill, exact direct read,
        // and a partial direct read followed by fresh EAGAIN or EOF.
        for request in [3, 8, 16] {
            for close_writer in [false, true] {
                let copied = request.min(payload.len());
                let exhausted = request > payload.len();
                let mut bytes = [0xa5; 32];
                bytes[..copied].copy_from_slice(&payload[..copied]);
                let oracle = observe_error_retry(
                    &host(),
                    mode,
                    request,
                    payload,
                    close_writer,
                    false,
                    RetryRead::Block,
                );
                assert_eq!(
                    oracle,
                    ReadAfterError {
                        result: copied as isize,
                        bytes,
                        errno: if exhausted && !close_writer {
                            libc::EAGAIN
                        } else {
                            RETRY_ERRNO_SENTINEL
                        },
                        error: true,
                        eof: exhausted && close_writer,
                    },
                    "GNU fread mode={mode} request={request} closed={close_writer}"
                );
                assert_eq!(
                    observe_error_retry(
                        &candidate(),
                        mode,
                        request,
                        payload,
                        close_writer,
                        false,
                        RetryRead::Block,
                    ),
                    oracle,
                    "fread mode={mode} request={request} closed={close_writer}"
                );
            }
        }
    }
}

#[test]
fn fgets_distinguishes_old_error_from_new_error_and_eof() {
    for cookie in [false, true] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            for (payload, request, copied, exhausted) in [
                (b"line\n".as_slice(), 16, 5, false),
                (b"abcdef".as_slice(), 4, 3, false),
                (b"tail".as_slice(), 16, 4, true),
                (b"".as_slice(), 16, 0, true),
            ] {
                for close_writer in [false, true] {
                    let mut bytes = [0xa5; 32];
                    bytes[..copied].copy_from_slice(&payload[..copied]);
                    if copied > 0 {
                        bytes[copied] = 0;
                    }
                    let oracle = observe_error_retry(
                        &host(),
                        mode,
                        request,
                        payload,
                        close_writer,
                        cookie,
                        RetryRead::Line,
                    );
                    assert_eq!(
                        oracle,
                        ReadAfterError {
                            result: isize::from(copied > 0),
                            bytes,
                            errno: if exhausted && !close_writer {
                                libc::EAGAIN
                            } else {
                                RETRY_ERRNO_SENTINEL
                            },
                            error: true,
                            eof: exhausted && close_writer,
                        },
                        "GNU fgets cookie={cookie} mode={mode} request={request} \
                         copied={copied} closed={close_writer}"
                    );
                    assert_eq!(
                        observe_error_retry(
                            &candidate(),
                            mode,
                            request,
                            payload,
                            close_writer,
                            cookie,
                            RetryRead::Line,
                        ),
                        oracle,
                        "fgets cookie={cookie} mode={mode} request={request} \
                         copied={copied} closed={close_writer}"
                    );
                }
            }
        }
    }
}

#[test]
fn getline_keeps_its_existing_error_short_circuit() {
    for cookie in [false, true] {
        let oracle = observe_error_retry(
            &host(),
            libc::_IOFBF,
            32,
            b"line\n",
            false,
            cookie,
            RetryRead::AllocatedLine,
        );
        assert_eq!(
            oracle,
            ReadAfterError {
                result: -1,
                bytes: [0xa5; 32],
                errno: RETRY_ERRNO_SENTINEL,
                error: true,
                eof: false,
            }
        );
        assert_eq!(
            observe_error_retry(
                &candidate(),
                libc::_IOFBF,
                32,
                b"line\n",
                false,
                cookie,
                RetryRead::AllocatedLine,
            ),
            oracle,
            "getline cookie={cookie}"
        );
    }
}

const WRITE_ONLY_PAYLOAD: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz012345";

fn observe_write_only_reads(
    arm: &StdioArm,
    mode: c_int,
    operation: RetryRead,
    request: usize,
    prior_error: bool,
) -> [(ReadAfterError, i64); 2] {
    let mut storage = [0u8; 8];
    // SAFETY: memfd_create produces O_RDWR, independently of the FILE's "w"
    // mode. The descriptor and caller-owned buffer remain live until fclose.
    unsafe {
        let fd = libc::memfd_create(c"stdio-write-only".as_ptr(), 0);
        assert!(fd >= 0);
        assert_eq!(
            libc::write(
                fd,
                WRITE_ONLY_PAYLOAD.as_ptr().cast(),
                WRITE_ONLY_PAYLOAD.len()
            ),
            WRITE_ONLY_PAYLOAD.len() as isize
        );
        assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
        let stream = (arm.fdopen)(fd, c"w".as_ptr());
        assert!(!stream.is_null());
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }
        assert_eq!(
            (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), mode, storage.len()),
            0
        );
        if prior_error {
            assert_eq!((arm.fgetc)(stream), libc::EOF);
            assert_eq!(*libc::__errno_location(), libc::EBADF);
            assert_ne!((arm.ferror)(stream), 0);
        }
        let observations = std::array::from_fn(|_| {
            let mut bytes = [0xa5u8; 32];
            *libc::__errno_location() = RETRY_ERRNO_SENTINEL;
            let result = match operation {
                RetryRead::Block => {
                    (arm.fread)(bytes.as_mut_ptr().cast(), 1, request, stream) as isize
                }
                RetryRead::Line => isize::from(
                    !(arm.fgets)(bytes.as_mut_ptr().cast(), request as c_int, stream).is_null(),
                ),
                RetryRead::AllocatedLine => unreachable!(),
            };
            let saved_errno = *libc::__errno_location();
            let observation = ReadAfterError {
                result,
                bytes,
                errno: saved_errno,
                error: (arm.ferror)(stream) != 0,
                eof: (arm.feof)(stream) != 0,
            };
            (observation, libc::lseek(fd, 0, libc::SEEK_CUR))
        });
        assert_eq!((arm.fclose)(stream), 0);
        observations
    }
}

#[test]
fn write_only_reads_match_gnu_underflow_and_direct_paths() {
    for mode in [libc::_IOFBF, libc::_IONBF] {
        for operation in [RetryRead::Block, RetryRead::Line] {
            for request in [3, 8, 16] {
                for prior_error in [false, true] {
                    // GNU checks the FILE read mode at underflow. Its direct
                    // fread path bypasses that check, just as it bypasses EOF;
                    // successful direct reads preserve any old ferror value.
                    let direct = matches!(operation, RetryRead::Block)
                        && (mode == libc::_IONBF || request >= 8);
                    let expected: [(ReadAfterError, i64); 2] = std::array::from_fn(|attempt| {
                        let copied = if direct { request } else { 0 };
                        let start = attempt * copied;
                        let mut bytes = [0xa5; 32];
                        bytes[..copied].copy_from_slice(&WRITE_ONLY_PAYLOAD[start..start + copied]);
                        (
                            ReadAfterError {
                                result: copied as isize,
                                bytes,
                                errno: if direct {
                                    RETRY_ERRNO_SENTINEL
                                } else {
                                    libc::EBADF
                                },
                                error: prior_error || !direct,
                                eof: false,
                            },
                            (start + copied) as i64,
                        )
                    });
                    let oracle =
                        observe_write_only_reads(&host(), mode, operation, request, prior_error);
                    assert_eq!(
                        oracle, expected,
                        "GNU mode={mode} operation={operation:?} request={request} prior={prior_error}"
                    );
                    assert_eq!(
                        observe_write_only_reads(
                            &candidate(),
                            mode,
                            operation,
                            request,
                            prior_error,
                        ),
                        oracle,
                        "mode={mode} operation={operation:?} request={request} prior={prior_error}"
                    );
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum PushbackBackend {
    Descriptor,
    Memory,
    Cookie,
}

unsafe extern "C-unwind" fn seekable_cookie_seek(
    cookie: *mut c_void,
    offset: *mut i64,
    whence: c_int,
) -> c_int {
    // SAFETY: the fixture owns this descriptor and supplies a live offset slot.
    unsafe {
        let position = libc::lseek(*cookie.cast::<c_int>(), *offset, whence);
        if position < 0 {
            -1
        } else {
            *offset = position;
            0
        }
    }
}

struct PushbackStreamGuard<'a> {
    arm: &'a StdioArm,
    stream: *mut c_void,
}

impl Drop for PushbackStreamGuard<'_> {
    fn drop(&mut self) {
        if !self.stream.is_null() {
            // SAFETY: the guard drops before the fixture's backing/context,
            // including when an assertion in the operation unwinds.
            unsafe { (self.arm.fclose)(self.stream) };
        }
    }
}

fn with_pushback_stream<T>(
    arm: &StdioArm,
    backend: PushbackBackend,
    mode: c_int,
    payload: &[u8],
    run: impl FnOnce(*mut c_void) -> T,
) -> T {
    let mut memory = payload.to_vec();
    let mut storage = [0u8; 8];
    let mut descriptor;
    // SAFETY: memory, stdio storage and the cookie context outlive the stream.
    // Descriptor/cookie streams own their fd until their provider closes it.
    unsafe {
        let stream = match backend {
            PushbackBackend::Memory => {
                (arm.fmemopen)(memory.as_mut_ptr().cast(), memory.len(), c"r".as_ptr())
            }
            PushbackBackend::Descriptor | PushbackBackend::Cookie => {
                descriptor = libc::memfd_create(c"stdio-pushback".as_ptr(), 0);
                assert!(descriptor >= 0);
                assert_eq!(
                    libc::write(descriptor, payload.as_ptr().cast(), payload.len()),
                    payload.len() as isize
                );
                assert_eq!(libc::lseek(descriptor, 0, libc::SEEK_SET), 0);
                if matches!(backend, PushbackBackend::Cookie) {
                    (arm.fopencookie)(
                        (&mut descriptor as *mut c_int).cast(),
                        c"r".as_ptr(),
                        fl::CookieIoFuncs {
                            read: Some(pipe_cookie_read),
                            seek: Some(seekable_cookie_seek),
                            close: Some(pipe_cookie_close),
                            ..Default::default()
                        },
                    )
                } else {
                    (arm.fdopen)(descriptor, c"r".as_ptr())
                }
            }
        };
        assert!(!stream.is_null(), "{}: {backend:?}", arm.name);
        let mut close = PushbackStreamGuard { arm, stream };
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }
        assert_eq!(
            (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), mode, storage.len()),
            0
        );
        let result = run(stream);
        let closed = (arm.fclose)(stream);
        close.stream = std::ptr::null_mut();
        assert_eq!(closed, 0);
        result
    }
}

#[derive(Debug, PartialEq, Eq)]
struct PushbackObservation {
    position_after_push: Option<c_long>,
    position_after_read: c_long,
    eof_after_push: bool,
    bytes: Vec<u8>,
    tail: Vec<u8>,
    eof_after_tail: bool,
    error: bool,
}

fn observe_deep_pushback(
    arm: &StdioArm,
    backend: PushbackBackend,
    mode: c_int,
    payload: &[u8],
    pushed: &[u8],
    consumed: usize,
) -> PushbackObservation {
    with_pushback_stream(arm, backend, mode, payload, |stream| {
        // SAFETY: the fixture owns this stream; all fixed-size reads fit the
        // destinations. No operation shares FILE or backing storage across arms.
        unsafe {
            for &byte in &payload[..consumed] {
                assert_eq!((arm.fgetc)(stream), c_int::from(byte));
            }
            if consumed == payload.len() {
                assert_eq!((arm.fgetc)(stream), libc::EOF);
                assert_ne!((arm.feof)(stream), 0);
            }
            for (index, &byte) in pushed.iter().enumerate() {
                assert_eq!(
                    (arm.ungetc)(c_int::from(byte), stream),
                    c_int::from(byte),
                    "{}: {backend:?} mode={mode} consumed={consumed} push={index}",
                    arm.name
                );
            }
            let position_after_push = (consumed >= pushed.len()).then(|| (arm.ftell)(stream));
            let eof_after_push = (arm.feof)(stream) != 0;
            let mut bytes = Vec::with_capacity(pushed.len());
            for _ in 0..16 {
                let byte = (arm.fgetc)(stream);
                assert!((0..=255).contains(&byte));
                bytes.push(byte as u8);
            }
            let mut middle = [0u8; 128];
            assert_eq!(
                (arm.fread)(middle.as_mut_ptr().cast(), 1, middle.len(), stream),
                middle.len()
            );
            bytes.extend_from_slice(&middle);
            // The pushed alphabet contains no newline or NUL. Finish with a
            // bounded fgets to exercise the line reader's shared pushback queue.
            let mut line = [0xa5u8; 369];
            assert_eq!(
                (arm.fgets)(line.as_mut_ptr().cast(), line.len() as c_int, stream),
                line.as_mut_ptr().cast()
            );
            assert_eq!(line[368], 0);
            bytes.extend_from_slice(&line[..368]);
            let position_after_read = (arm.ftell)(stream);
            let mut tail = [0xa5u8; 1025];
            let count = (arm.fread)(tail.as_mut_ptr().cast(), 1, tail.len(), stream);
            assert!(tail[count..].iter().all(|&byte| byte == 0xa5));
            PushbackObservation {
                position_after_push,
                position_after_read,
                eof_after_push,
                bytes,
                tail: tail[..count].to_vec(),
                eof_after_tail: (arm.feof)(stream) != 0,
                error: (arm.ferror)(stream) != 0,
            }
        }
    })
}

#[test]
fn ungetc_grows_beyond_the_stream_buffer_and_preserves_lifo() {
    let payload: Vec<u8> = (0..1024).map(|i| b'a' + (i % 26) as u8).collect();
    let pushed: Vec<u8> = (0..512).map(|i| b'A' + (i % 26) as u8).collect();
    for backend in [
        PushbackBackend::Descriptor,
        PushbackBackend::Memory,
        PushbackBackend::Cookie,
    ] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            for consumed in [0, 512, 1024] {
                let oracle =
                    observe_deep_pushback(&host(), backend, mode, &payload, &pushed, consumed);
                assert_eq!(
                    oracle,
                    PushbackObservation {
                        position_after_push: (consumed >= pushed.len())
                            .then(|| (consumed - pushed.len()) as c_long),
                        position_after_read: consumed as c_long,
                        eof_after_push: false,
                        bytes: pushed.iter().rev().copied().collect(),
                        tail: payload[consumed..].to_vec(),
                        eof_after_tail: true,
                        error: false,
                    },
                    "GNU {backend:?} mode={mode} consumed={consumed}"
                );
                assert_eq!(
                    observe_deep_pushback(&candidate(), backend, mode, &payload, &pushed, consumed,),
                    oracle,
                    "{backend:?} mode={mode} consumed={consumed}"
                );
            }
        }
    }
}

#[test]
fn ungetc_seek_discards_deep_pushback_from_the_logical_position() {
    let payload: Vec<u8> = (0..1024).map(|i| b'a' + (i % 26) as u8).collect();
    for backend in [
        PushbackBackend::Descriptor,
        PushbackBackend::Memory,
        PushbackBackend::Cookie,
    ] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            let observe = |arm: &StdioArm| {
                with_pushback_stream(arm, backend, mode, &payload, |stream| {
                    // SAFETY: the fixture retains every object until fclose.
                    unsafe {
                        for &byte in &payload[..768] {
                            assert_eq!((arm.fgetc)(stream), c_int::from(byte));
                        }
                        for _ in 0..512 {
                            assert_eq!((arm.ungetc)(c_int::from(b'X'), stream), c_int::from(b'X'));
                        }
                        let before = (arm.ftell)(stream);
                        let relative = (arm.fseek)(stream, 0, libc::SEEK_CUR);
                        let after_relative = (arm.ftell)(stream);
                        let first = (arm.fgetc)(stream);
                        for _ in 0..64 {
                            assert_eq!((arm.ungetc)(c_int::from(b'Y'), stream), c_int::from(b'Y'));
                        }
                        let absolute = (arm.fseek)(stream, 512, libc::SEEK_SET);
                        let after_absolute = (arm.ftell)(stream);
                        let second = (arm.fgetc)(stream);
                        (
                            before,
                            relative,
                            after_relative,
                            first,
                            absolute,
                            after_absolute,
                            second,
                            (arm.feof)(stream) != 0,
                            (arm.ferror)(stream) != 0,
                        )
                    }
                })
            };
            let oracle = observe(&host());
            assert_eq!(
                oracle,
                (
                    256,
                    0,
                    256,
                    c_int::from(payload[256]),
                    0,
                    512,
                    c_int::from(payload[512]),
                    false,
                    false
                ),
                "GNU {backend:?} mode={mode}"
            );
            assert_eq!(observe(&candidate()), oracle, "{backend:?} mode={mode}");
        }
    }
}

#[test]
fn ungetc_preserves_scanner_rollback_ahead_of_pending_input() {
    let payload: Vec<u8> = (0..1024).map(|i| b'a' + (i % 26) as u8).collect();
    let mut replay = vec![b'Z'; 512];
    replay[..4].copy_from_slice(b"42x\n");
    for backend in [
        PushbackBackend::Descriptor,
        PushbackBackend::Memory,
        PushbackBackend::Cookie,
    ] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            let observe = |arm: &StdioArm| {
                with_pushback_stream(arm, backend, mode, &payload, |stream| {
                    // SAFETY: the stream and all destinations remain live. The
                    // single integer destination matches the variadic format.
                    unsafe {
                        for &byte in &payload[..512] {
                            assert_eq!((arm.fgetc)(stream), c_int::from(byte));
                        }
                        for &byte in replay.iter().rev() {
                            assert_eq!((arm.ungetc)(c_int::from(byte), stream), c_int::from(byte));
                        }
                        let mut value: c_int = -1;
                        assert_eq!(
                            (arm.fscanf)(stream, c"%d".as_ptr(), &mut value as *mut c_int),
                            1
                        );
                        assert_eq!(value, 42);
                        assert_eq!((arm.ftell)(stream), 2);
                        // scanf restored its lookahead 'x' ahead of a long
                        // pending queue. New ungetc bytes must precede both.
                        assert_eq!((arm.ungetc)(c_int::from(b'Q'), stream), c_int::from(b'Q'));
                        assert_eq!((arm.ungetc)(c_int::from(b'R'), stream), c_int::from(b'R'));
                        let mut line = [0xa5u8; 8];
                        assert_eq!(
                            (arm.fgets)(line.as_mut_ptr().cast(), line.len() as c_int, stream),
                            line.as_mut_ptr().cast()
                        );
                        assert_eq!(&line, b"RQx\n\0\xa5\xa5\xa5");
                        let position = (arm.ftell)(stream);
                        let mut tail = [0xa5u8; 1021];
                        let count = (arm.fread)(tail.as_mut_ptr().cast(), 1, tail.len(), stream);
                        assert!(count <= tail.len());
                        assert!(tail[count..].iter().all(|&byte| byte == 0xa5));
                        (
                            position,
                            tail[..count].to_vec(),
                            (arm.feof)(stream) != 0,
                            (arm.ferror)(stream) != 0,
                        )
                    }
                })
            };
            let oracle = observe(&host());
            let expected_tail = [&replay[4..], &payload[512..]].concat();
            assert_eq!(
                oracle,
                (4, expected_tail, true, false),
                "GNU {backend:?} mode={mode}"
            );
            assert_eq!(observe(&candidate()), oracle, "{backend:?} mode={mode}");
        }
    }
}

#[test]
fn character_pushback_returns_unsigned_bytes_except_eof() {
    let oracle = host();
    let implementation = candidate();
    let payload = b"ab";
    let inputs = [
        c_int::MIN,
        -257,
        -256,
        -255,
        -129,
        -128,
        -2,
        0,
        127,
        128,
        255,
        256,
        321,
        c_int::MAX,
    ];

    for backend in [
        PushbackBackend::Descriptor,
        PushbackBackend::Memory,
        PushbackBackend::Cookie,
    ] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            for consumed in 0..=payload.len() {
                let observe = |arm: &StdioArm| {
                    with_pushback_stream(arm, backend, mode, payload, |stream| {
                        // SAFETY: the fixture owns the live stream and all
                        // backing/context storage until the closing guard runs.
                        unsafe {
                            for &byte in &payload[..consumed] {
                                assert_eq!((arm.fgetc)(stream), c_int::from(byte));
                            }
                            if consumed == payload.len() {
                                assert_eq!((arm.fgetc)(stream), libc::EOF);
                                assert_ne!((arm.feof)(stream), 0);
                            }

                            let eof_before = (arm.feof)(stream) != 0;
                            let rejected = (arm.ungetc)(libc::EOF, stream);
                            let eof_after_rejection = (arm.feof)(stream) != 0;
                            let mut observations = Vec::new();
                            for input in inputs {
                                let pushed = (arm.ungetc)(input, stream);
                                let eof_after_push = (arm.feof)(stream) != 0;
                                let byte = (arm.fgetc)(stream);
                                observations.push((pushed, byte, eof_after_push));
                            }

                            let mut tail = [0xa5u8; 4];
                            let count =
                                (arm.fread)(tail.as_mut_ptr().cast(), 1, tail.len(), stream);
                            assert!(count <= tail.len());
                            (
                                rejected,
                                eof_before,
                                eof_after_rejection,
                                observations,
                                tail[..count].to_vec(),
                                (arm.feof)(stream) != 0,
                                (arm.ferror)(stream) != 0,
                            )
                        }
                    })
                };
                let reference = observe(&oracle);
                let expected: Vec<_> = inputs
                    .iter()
                    .map(|&input| {
                        let byte = c_int::from(input as u8);
                        (byte, byte, false)
                    })
                    .collect();
                assert_eq!(
                    reference,
                    (
                        libc::EOF,
                        consumed == payload.len(),
                        consumed == payload.len(),
                        expected,
                        payload[consumed..].to_vec(),
                        true,
                        false,
                    ),
                    "GNU {backend:?} mode={mode} consumed={consumed}"
                );
                assert_eq!(
                    observe(&implementation),
                    reference,
                    "{backend:?} mode={mode} consumed={consumed}"
                );
            }
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum CharacterOutputBackend {
    Descriptor,
    Cookie,
    FixedMemory,
    DynamicMemory,
}

#[derive(Debug, PartialEq, Eq)]
struct CharacterOutputObservation {
    results: Vec<c_int>,
    bytes: Vec<u8>,
    error_before_flush: bool,
    flush_result: c_int,
    error_after_flush: bool,
    close_result: c_int,
}

unsafe extern "C-unwind" fn character_cookie_write(
    cookie: *mut c_void,
    bytes: *const c_char,
    count: usize,
) -> isize {
    // SAFETY: the fixture retains its descriptor slot until fclose and
    // the FILE supplies count readable bytes for this callback invocation.
    unsafe { libc::write(*cookie.cast::<c_int>(), bytes.cast(), count) }
}

fn observe_character_output(
    arm: &StdioArm,
    backend: CharacterOutputBackend,
    mode: c_int,
    writer: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    inputs: &[c_int],
) -> CharacterOutputObservation {
    let mut descriptor = -1;
    let mut fixed = [0xa5u8; 64];
    let mut storage = [0u8; 8];
    let mut published: *mut c_char = std::ptr::null_mut();
    let mut published_len = 0usize;
    assert!(inputs.len() < fixed.len());

    // SAFETY: all FILE backing storage, callback context, buffer storage and
    // open_memstream publication slots outlive the closing guard. Each arm
    // creates, operates on, and closes its own independent stream.
    unsafe {
        let stream = match backend {
            CharacterOutputBackend::Descriptor | CharacterOutputBackend::Cookie => {
                descriptor = libc::memfd_create(c"stdio-character-output".as_ptr(), 0);
                assert!(descriptor >= 0);
                if matches!(backend, CharacterOutputBackend::Cookie) {
                    (arm.fopencookie)(
                        (&raw mut descriptor).cast(),
                        c"w".as_ptr(),
                        fl::CookieIoFuncs {
                            write: Some(character_cookie_write),
                            close: Some(pipe_cookie_close),
                            ..Default::default()
                        },
                    )
                } else {
                    (arm.fdopen)(descriptor, c"w".as_ptr())
                }
            }
            CharacterOutputBackend::FixedMemory => {
                (arm.fmemopen)(fixed.as_mut_ptr().cast(), fixed.len(), c"w".as_ptr())
            }
            CharacterOutputBackend::DynamicMemory => {
                (arm.open_memstream)(&mut published, &mut published_len)
            }
        };
        assert!(!stream.is_null(), "{}: {backend:?}", arm.name);
        let mut close = PushbackStreamGuard { arm, stream };
        if arm.name == "fl" {
            assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
        }

        // open_memstream has its own growing-memory buffering contract.
        // Retain its default instead of asking GNU to replace that storage.
        if !matches!(backend, CharacterOutputBackend::DynamicMemory) {
            assert_eq!(
                (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), mode, storage.len()),
                0
            );
        }

        let results = inputs.iter().map(|&input| writer(input, stream)).collect();
        let error_before_flush = (arm.ferror)(stream) != 0;
        let flush_result = (arm.fflush)(stream);
        let error_after_flush = (arm.ferror)(stream) != 0;
        let bytes = match backend {
            CharacterOutputBackend::Descriptor | CharacterOutputBackend::Cookie => {
                assert_eq!(libc::lseek(descriptor, 0, libc::SEEK_SET), 0);
                let mut bytes = vec![0xa5u8; inputs.len() + 1];
                let count = libc::read(descriptor, bytes.as_mut_ptr().cast(), bytes.len());
                assert!(count >= 0);
                bytes.truncate(count as usize);
                bytes
            }
            CharacterOutputBackend::FixedMemory => {
                assert_eq!(fixed[inputs.len()], 0);
                fixed[..inputs.len()].to_vec()
            }
            CharacterOutputBackend::DynamicMemory => {
                assert!(!published.is_null());
                assert_eq!(published_len, inputs.len());
                assert_eq!(*published.add(published_len), 0);
                std::slice::from_raw_parts(published.cast::<u8>(), published_len).to_vec()
            }
        };

        let close_result = (arm.fclose)(stream);
        close.stream = std::ptr::null_mut();
        if matches!(backend, CharacterOutputBackend::DynamicMemory) {
            // fclose transfers the final buffer to the caller; release it
            // through the allocator belonging to the stream's provider.
            if arm.name == "fl" {
                frankenlibc_abi::malloc_abi::free(published.cast());
            } else {
                libc::free(published.cast());
            }
        }

        CharacterOutputObservation {
            results,
            bytes,
            error_before_flush,
            flush_result,
            error_after_flush,
            close_result,
        }
    }
}

#[test]
fn character_output_returns_unsigned_bytes_including_eof_input() {
    let oracle = host();
    let implementation = candidate();
    // EOF is an ordinary int argument to output: it writes byte 255 and
    // succeeds. Repetition crosses the eight-byte buffer and exercises used
    // streams as well as the cold first call.
    let inputs = [
        libc::EOF,
        -257,
        -256,
        -2,
        0,
        127,
        128,
        255,
        256,
        321,
        c_int::MIN,
        c_int::MAX,
    ]
    .repeat(2);
    let expected = CharacterOutputObservation {
        results: inputs
            .iter()
            .map(|&input| c_int::from(input as u8))
            .collect(),
        bytes: inputs.iter().map(|&input| input as u8).collect(),
        error_before_flush: false,
        flush_result: 0,
        error_after_flush: false,
        close_result: 0,
    };
    let writers = [
        ("fputc", oracle.fputc, implementation.fputc),
        ("putc", oracle.putc, implementation.putc),
        (
            "fputc_unlocked",
            oracle.fputc_unlocked,
            implementation.fputc_unlocked,
        ),
        (
            "putc_unlocked",
            oracle.putc_unlocked,
            implementation.putc_unlocked,
        ),
    ];

    for backend in [
        CharacterOutputBackend::Descriptor,
        CharacterOutputBackend::Cookie,
        CharacterOutputBackend::FixedMemory,
        CharacterOutputBackend::DynamicMemory,
    ] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            if matches!(backend, CharacterOutputBackend::DynamicMemory) && mode != libc::_IOFBF {
                continue;
            }
            for (name, host_writer, candidate_writer) in writers {
                let reference =
                    observe_character_output(&oracle, backend, mode, host_writer, &inputs);
                assert_eq!(reference, expected, "GNU {name} {backend:?} mode={mode}");
                assert_eq!(
                    observe_character_output(
                        &implementation,
                        backend,
                        mode,
                        candidate_writer,
                        &inputs,
                    ),
                    reference,
                    "{name} {backend:?} mode={mode}"
                );
            }
        }
    }
}

#[test]
fn rewind_clears_indicators_on_host_owned_streams() {
    let host = host();
    // SAFETY: all FILE operations other than the candidate rewind use glibc's
    // own entrypoints on a live, read-only glibc FILE.
    unsafe {
        let host_rewind: unsafe extern "C-unwind" fn(*mut c_void) =
            dlsym_oracle::host_fn(c"rewind", fl::rewind as *const ());
        for candidate in [false, true] {
            for pipe in [false, true] {
                let stream = if pipe {
                    let mut fds = [-1; 2];
                    assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
                    assert_eq!(libc::close(fds[1]), 0);
                    (host.fdopen)(fds[0], c"r".as_ptr())
                } else {
                    (host.fopen)(c"/dev/null".as_ptr(), c"r".as_ptr())
                };
                assert!(!stream.is_null());
                assert_eq!((host.fgetc)(stream), libc::EOF);
                assert_eq!((host.fputc)(i32::from(b'X'), stream), libc::EOF);
                assert_ne!((host.feof)(stream), 0);
                assert_ne!((host.ferror)(stream), 0);

                let error = if candidate {
                    let slot = frankenlibc_abi::errno_abi::__errno_location();
                    *slot = 0;
                    fl::rewind(stream);
                    *slot
                } else {
                    let slot = libc::__errno_location();
                    *slot = 0;
                    host_rewind(stream);
                    *slot
                };
                assert_eq!((host.feof)(stream), 0);
                assert_eq!((host.ferror)(stream), 0);
                if pipe {
                    assert_eq!(error, libc::ESPIPE);
                }
                assert_eq!((host.fclose)(stream), 0);
            }
        }
    }
}

#[test]
fn input_descriptor_readahead_matches_glibc() {
    let gnu = host();
    let fl = candidate();
    // Include both sides of GNU's small-buffer threshold, a non-power-of-two
    // buffer, exact multiples, and caller buffers larger than BUFSIZ.
    for (capacity, request) in [
        (127, 263),
        (128, 263),
        (257, 521),
        (4096, 8192),
        (16384, 1),
        (16384, 16384),
        (16384, 32775),
    ] {
        let observe = |arm: &StdioArm| {
            let path = std::env::temp_dir().join(format!(
                "fl-stdio-readahead-{}-{capacity}-{request}-{}",
                std::process::id(),
                arm.name
            ));
            let data: Vec<u8> = (0..request + capacity + 1)
                .map(|index| (index % 251) as u8)
                .collect();
            std::fs::write(&path, &data).unwrap();
            let cpath = CString::new(path.to_str().unwrap()).unwrap();
            let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            let mut storage = vec![0u8; capacity];
            let mut destination = vec![0u8; request];
            // SAFETY: each FILE and its backing buffer remain live through
            // fclose. The positional write does not change the descriptor offset.
            unsafe {
                let stream = (arm.fopen)(cpath.as_ptr(), c"r".as_ptr());
                assert!(!stream.is_null());
                std::fs::remove_file(&path).unwrap();
                if arm.name == "fl" {
                    assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
                }
                assert_eq!(
                    (arm.setvbuf)(stream, storage.as_mut_ptr().cast(), libc::_IOFBF, capacity),
                    0
                );
                assert_eq!(
                    (arm.fread)(destination.as_mut_ptr().cast(), 1, request, stream),
                    request
                );
                assert_eq!(destination, &data[..request]);
                let fd = (arm.fileno)(stream);
                let physical = libc::lseek(fd, 0, libc::SEEK_CUR);
                let logical = (arm.ftell)(stream);
                // Make it observable whether the unread suffix was prefetched.
                use std::os::unix::fs::FileExt;
                assert_eq!(writer.write_at(&[255], request as u64).unwrap(), 1);
                let next = (arm.fgetc)(stream);
                assert_eq!((arm.fflush)(stream), 0);
                let synchronized = libc::lseek(fd, 0, libc::SEEK_CUR);
                assert_eq!((arm.fclose)(stream), 0);
                (physical, logical, next, synchronized)
            }
        };
        let oracle = observe(&gnu);
        assert_eq!(oracle.1, request as c_long);
        assert_eq!(oracle.3, request as libc::off_t + 1);
        assert_eq!(
            observe(&fl),
            oracle,
            "capacity={capacity}, request={request}"
        );
    }
}
