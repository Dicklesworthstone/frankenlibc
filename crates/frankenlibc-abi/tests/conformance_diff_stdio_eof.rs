#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // Real FILE operations, compared with separately resolved glibc.

//! fread's sticky EOF applies to buffer underflow, while GNU's direct-read
//! path can read newly appended bytes with the old EOF indicator still set.
//! Run this target in both strict and hardened modes.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};

use frankenlibc_abi::stdio_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

struct StdioArm {
    name: &'static str,
    fopen: unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_void,
    fdopen: unsafe extern "C" fn(c_int, *const c_char) -> *mut c_void,
    fopencookie: unsafe extern "C" fn(*mut c_void, *const c_char, fl::CookieIoFuncs) -> *mut c_void,
    fgetc: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    fgets: unsafe extern "C-unwind" fn(*mut c_char, c_int, *mut c_void) -> *mut c_char,
    getline: unsafe extern "C-unwind" fn(*mut *mut c_char, *mut usize, *mut c_void) -> isize,
    fclose: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    setvbuf: unsafe extern "C-unwind" fn(*mut c_void, *mut c_char, c_int, usize) -> c_int,
    fread: unsafe extern "C-unwind" fn(*mut c_void, usize, usize, *mut c_void) -> usize,
    feof: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    ferror: unsafe extern "C-unwind" fn(*mut c_void) -> c_int,
    clearerr: unsafe extern "C-unwind" fn(*mut c_void),
}

fn candidate() -> StdioArm {
    StdioArm {
        name: "fl",
        fopen: fl::fopen,
        fdopen: fl::fdopen,
        fopencookie: fl::fopencookie,
        fgetc: fl::fgetc,
        fgets: fl::fgets,
        getline: fl::getline,
        fclose: fl::fclose,
        setvbuf: fl::setvbuf,
        fread: fl::fread,
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
            fopencookie: dlsym_oracle::host_fn(c"fopencookie", fl::fopencookie as *const ()),
            fgetc: dlsym_oracle::host_fn(c"fgetc", fl::fgetc as *const ()),
            fgets: dlsym_oracle::host_fn(c"fgets", fl::fgets as *const ()),
            getline: dlsym_oracle::host_fn(c"getline", fl::getline as *const ()),
            fclose: dlsym_oracle::host_fn(c"fclose", fl::fclose as *const ()),
            setvbuf: dlsym_oracle::host_fn(c"setvbuf", fl::setvbuf as *const ()),
            fread: dlsym_oracle::host_fn(c"fread", fl::fread as *const ()),
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
            RetryRead::Block => {
                (arm.fread)(bytes.as_mut_ptr().cast(), 1, request, stream) as isize
            }
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

#[test]
fn retryable_error_does_not_allow_reading_write_only_streams() {
    for arm in [host(), candidate()] {
        for mode in [libc::_IOFBF, libc::_IONBF] {
            for operation in [RetryRead::Block, RetryRead::Line] {
                let mut storage = [0u8; 8];
                // SAFETY: memfd_create produces O_RDWR, so only the FILE mode
                // can reject reading. The descriptor and buffer live to fclose.
                unsafe {
                    let fd = libc::memfd_create(c"stdio-write-only".as_ptr(), 0);
                    assert!(fd >= 0);
                    let payload = b"secret\n";
                    assert_eq!(
                        libc::write(fd, payload.as_ptr().cast(), payload.len()),
                        payload.len() as isize
                    );
                    assert_eq!(libc::lseek(fd, 0, libc::SEEK_SET), 0);
                    let stream = (arm.fdopen)(fd, c"w".as_ptr());
                    assert!(!stream.is_null());
                    if arm.name == "fl" {
                        assert!(!fl::stdio_may_delegate_to_host_for_tests(stream));
                    }
                    assert_eq!(
                        (arm.setvbuf)(
                            stream,
                            storage.as_mut_ptr().cast(),
                            mode,
                            storage.len(),
                        ),
                        0
                    );
                    for attempt in 0..2 {
                        let mut bytes = [0xa5u8; 32];
                        *libc::__errno_location() = RETRY_ERRNO_SENTINEL;
                        let result = match operation {
                            RetryRead::Block => {
                                (arm.fread)(bytes.as_mut_ptr().cast(), 1, 3, stream) as isize
                            }
                            RetryRead::Line => isize::from(
                                !(arm.fgets)(bytes.as_mut_ptr().cast(), 4, stream).is_null(),
                            ),
                            RetryRead::AllocatedLine => unreachable!(),
                        };
                        let saved_errno = *libc::__errno_location();
                        assert_eq!(
                            (result, saved_errno, bytes),
                            (0, libc::EBADF, [0xa5; 32]),
                            "{}: mode={mode} operation={operation:?} attempt={attempt}",
                            arm.name
                        );
                        assert_ne!((arm.ferror)(stream), 0);
                        assert_eq!((arm.feof)(stream), 0);
                        assert_eq!(libc::lseek(fd, 0, libc::SEEK_CUR), 0);
                    }
                    assert_eq!((arm.fclose)(stream), 0);
                }
            }
        }
    }
}
