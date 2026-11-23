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
    fopencookie: unsafe extern "C" fn(*mut c_void, *const c_char, fl::CookieIoFuncs) -> *mut c_void,
    fgetc: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    ungetc: unsafe extern "C-unwind" fn(c_int, *mut c_void) -> c_int,
    fgets: unsafe extern "C-unwind" fn(*mut c_char, c_int, *mut c_void) -> *mut c_char,
    fscanf: unsafe extern "C-unwind" fn(*mut c_void, *const c_char, ...) -> c_int,
    getline: unsafe extern "C-unwind" fn(*mut *mut c_char, *mut usize, *mut c_void) -> isize,
    fclose: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
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
        fopencookie: fl::fopencookie,
        fgetc: fl::fgetc,
        ungetc: fl::ungetc,
        fgets: fl::fgets,
        fscanf: fl::fscanf,
        getline: fl::getline,
        fclose: fl::fclose,
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
            fopencookie: dlsym_oracle::host_fn(c"fopencookie", fl::fopencookie as *const ()),
            fgetc: dlsym_oracle::host_fn(c"fgetc", fl::fgetc as *const ()),
            ungetc: dlsym_oracle::host_fn(c"ungetc", fl::ungetc as *const ()),
            fgets: dlsym_oracle::host_fn(c"fgets", fl::fgets as *const ()),
            fscanf: dlsym_oracle::host_fn(c"fscanf", fl::fscanf as *const ()),
            getline: dlsym_oracle::host_fn(c"getline", fl::getline as *const ()),
            fclose: dlsym_oracle::host_fn(c"fclose", fl::fclose as *const ()),
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
