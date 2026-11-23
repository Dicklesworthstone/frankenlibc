#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc open_memstream oracle

//! Differential test for `open_memstream` vs host glibc. Drives an identical
//! sequence of writes / seeks / flushes on both engines and compares, at each
//! checkpoint, the reported `*sizeloc` and the buffer bytes (`*ptr`). Exercises
//! the subtle semantics programs rely on: an empty stream yields a 1-byte
//! NUL buffer with size 0; the buffer is NUL-terminated at its maximum extent;
//! `*sizeloc` is the CURRENT position after flush (so seeking back shrinks the
//! reported size while the tail bytes survive); seeking past the end leaves a
//! NUL-filled hole.

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn open_memstream(ptr: *mut *mut libc::c_char, sizeloc: *mut usize) -> *mut libc::FILE;
    fn fputs(s: *const libc::c_char, stream: *mut libc::FILE) -> libc::c_int;
    fn fputc(c: libc::c_int, stream: *mut libc::FILE) -> libc::c_int;
    fn fseek(stream: *mut libc::FILE, off: libc::c_long, whence: libc::c_int) -> libc::c_int;
    fn fflush(stream: *mut libc::FILE) -> libc::c_int;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
}

/// One engine: run the op script, recording (label, sizeloc, buf[..view]) at
/// each checkpoint.
fn run(engine_glibc: bool) -> Vec<(&'static str, usize, Vec<u8>)> {
    let mut ptr: *mut libc::c_char = std::ptr::null_mut();
    let mut sz: usize = 999;
    let mut log = Vec::new();

    // The stream pointer type differs (glibc FILE* vs fl's c_void handle); a
    // tiny closure set captures the engine choice.
    let stream: *mut libc::FILE = if engine_glibc {
        unsafe { open_memstream(&mut ptr, &mut sz) }
    } else {
        unsafe {
            fl::open_memstream(&mut ptr as *mut *mut libc::c_char, &mut sz) as *mut libc::FILE
        }
    };
    assert!(
        !stream.is_null(),
        "open_memstream failed (glibc={engine_glibc})"
    );

    let puts = |s: &[u8]| {
        if engine_glibc {
            unsafe { fputs(s.as_ptr() as *const libc::c_char, stream) };
        } else {
            unsafe {
                fl::fputs(
                    s.as_ptr() as *const libc::c_char,
                    stream as *mut libc::c_void,
                )
            };
        }
    };
    let putc = |c: i32| {
        if engine_glibc {
            unsafe { fputc(c, stream) };
        } else {
            unsafe { fl::fputc(c, stream as *mut libc::c_void) };
        }
    };
    let seek = |off: i64| {
        if engine_glibc {
            unsafe { fseek(stream, off as libc::c_long, libc::SEEK_SET) };
        } else {
            unsafe {
                fl::fseek(
                    stream as *mut libc::c_void,
                    off as libc::c_long,
                    libc::SEEK_SET,
                )
            };
        }
    };
    let flush = || {
        if engine_glibc {
            unsafe { fflush(stream) };
        } else {
            unsafe { fl::fflush(stream as *mut libc::c_void) };
        }
    };
    let snapshot = |ptr: *mut libc::c_char, initialized: usize| -> Vec<u8> {
        if ptr.is_null() {
            return Vec::new();
        }
        // Only the initialized extent plus its terminator is readable. In
        // particular the empty native stream owns a one-byte allocation.
        unsafe { std::slice::from_raw_parts(ptr as *const u8, initialized + 1) }.to_vec()
    };

    flush();
    log.push(("empty", sz, snapshot(ptr, 0)));
    puts(b"abc\0");
    flush();
    log.push(("abc", sz, snapshot(ptr, 3)));
    seek(6);
    putc(b'X' as i32);
    flush();
    log.push(("hole+X", sz, snapshot(ptr, 7)));
    seek(1);
    putc(b'Z' as i32);
    flush();
    log.push(("mid-Z", sz, snapshot(ptr, 7)));

    if engine_glibc {
        unsafe { fclose(stream) };
    } else {
        unsafe { fl::fclose(stream as *mut libc::c_void) };
    }
    // After fclose glibc truncates the buffer at the position (realloc to
    // size + 1, NUL there), so only size + 1 bytes are readable.
    let closed = if ptr.is_null() {
        Vec::new()
    } else {
        unsafe { std::slice::from_raw_parts(ptr as *const u8, sz + 1) }.to_vec()
    };
    log.push(("closed", sz, closed));
    if engine_glibc {
        // SAFETY: fclose transfers the final GNU buffer to this caller.
        unsafe { libc::free(ptr.cast()) };
    } else {
        // SAFETY: release the native buffer with its matching allocator.
        unsafe { frankenlibc_abi::malloc_abi::free(ptr.cast()) };
    }
    log
}

#[test]
fn open_memstream_matches_glibc() {
    let fl_log = run(false);
    let lc_log = run(true);
    assert_eq!(
        fl_log, lc_log,
        "open_memstream diverged from glibc:\n  fl   ={fl_log:02x?}\n  glibc={lc_log:02x?}"
    );
}

#[test]
fn open_memstream_publication_allocation_failure() {
    const NAME: &str = "open_memstream_publication_allocation_failure";
    const CHILD: &str = "FRANKENLIBC_MEMSTREAM_ALLOCATION_CHILD";
    let Ok(operation) = std::env::var(CHILD) else {
        for mode in ["strict", "hardened"] {
            for operation in ["flush", "flush_all", "seek", "close"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", NAME, "--nocapture"])
                    .env(CHILD, operation)
                    .env("FRANKENLIBC_MODE", mode)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{mode}/{operation}: {:?}\n{}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
            }
        }
        return;
    };

    use frankenlibc_abi::{errno_abi, malloc_abi};
    const PAYLOAD: usize = 16 * 1024 * 1024;
    // Each scenario owns its process limits and watchdog. Prepare the complete
    // stream contents before restricting additional mappings; only publishing
    // the already-buffered output should need a large allocation afterwards.
    unsafe { libc::alarm(30) };
    let payload = vec![0xa5u8; PAYLOAD];
    let mut pointer = std::ptr::null_mut();
    let mut size = 0;
    let stream = unsafe { fl::open_memstream(&mut pointer, &mut size) };
    assert!(!stream.is_null());
    assert!(unsafe { fl::fputs(c"seed".as_ptr(), stream) } >= 0);
    assert_eq!(unsafe { fl::fflush(stream) }, 0);
    assert_eq!(unsafe { fl::fseek(stream, 0, libc::SEEK_CUR) }, 0);
    assert_eq!(unsafe { fl::fflush(std::ptr::null_mut()) }, 0);
    assert_eq!(size, 4);
    let previous_pointer = pointer;
    assert_eq!(
        unsafe { fl::fwrite(payload.as_ptr().cast(), 1, payload.len(), stream) },
        payload.len()
    );

    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let vm_kib = status
        .lines()
        .find(|line| line.starts_with("VmSize:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("Linux supplies VmSize")
        .parse::<libc::rlim_t>()
        .unwrap();
    let mut previous = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut previous) },
        0
    );
    let constrained = libc::rlimit {
        rlim_cur: (vm_kib * 1024 + 1024 * 1024).min(previous.rlim_cur),
        rlim_max: previous.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &constrained) }, 0);
    // Do not allocate assertion/reporting strings before restoring the limit.
    // The probe rejects an environment that can satisfy this request from a
    // pre-existing free arena, instead of mistaking it for a tested failure.
    let (allocation_failed, result, error, stream_error, position) = unsafe {
        let probe = malloc_abi::malloc(PAYLOAD + 5);
        let allocation_failed = probe.is_null();
        if !probe.is_null() {
            malloc_abi::free(probe);
        }
        *errno_abi::__errno_location() = libc::EDOM;
        let result = match operation.as_str() {
            "flush" => fl::fflush(stream),
            "flush_all" => fl::fflush(std::ptr::null_mut()),
            "seek" => fl::fseek(stream, 0, libc::SEEK_SET),
            "close" => fl::fclose(stream),
            _ => libc::_exit(99),
        };
        let error = *errno_abi::__errno_location();
        let stream_error = if operation == "close" {
            0
        } else {
            fl::ferror(stream)
        };
        let position = if operation == "close" {
            0
        } else {
            fl::ftell(stream)
        };
        (allocation_failed, result, error, stream_error, position)
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &previous) }, 0);
    assert!(
        allocation_failed,
        "the bounded allocation must actually fail"
    );
    assert_eq!(
        result,
        libc::EOF,
        "{operation} must report publication failure"
    );
    assert_eq!(
        error,
        libc::ENOMEM,
        "{operation} must preserve the allocation error"
    );
    assert_eq!(
        pointer, previous_pointer,
        "failure must retain the published buffer"
    );
    assert_eq!(size, 4, "failure must retain the published size");
    // SAFETY: the failed publication must leave the previous allocation live.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), 5) },
        b"seed\0"
    );

    if operation != "close" {
        assert_ne!(
            stream_error, 0,
            "failure must set the stream error indicator"
        );
        assert_eq!(position, (PAYLOAD + 4) as libc::c_long);
        unsafe { fl::clearerr(stream) };
        assert_eq!(
            unsafe { fl::fflush(stream) },
            0,
            "retry after recovery must succeed"
        );
        assert_eq!(size, PAYLOAD + 4);
        // SAFETY: a successful flush publishes the complete initialized extent.
        let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), size + 1) };
        assert_eq!(&bytes[..4], b"seed");
        assert_eq!(&bytes[4..size], payload.as_slice());
        assert_eq!(bytes[size], 0);
        assert_eq!(unsafe { fl::fclose(stream) }, 0);
    }
    // Even a failed close leaves the last successfully published allocation
    // owned by the caller; it must remain valid and independently freeable.
    unsafe {
        malloc_abi::free(pointer.cast());
        libc::alarm(0);
    }
}

#[cfg(not(feature = "standalone"))]
#[test]
fn fflush_all_preserves_host_error_after_successful_native_flush() {
    const NAME: &str = "fflush_all_preserves_host_error_after_successful_native_flush";
    const CHILD: &str = "FRANKENLIBC_FLUSH_ALL_HOST_ERROR_CHILD";
    if std::env::var_os(CHILD).is_none() {
        for mode in ["strict", "hardened"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--nocapture"])
                .env(CHILD, "1")
                .env("FRANKENLIBC_MODE", mode)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
        }
        return;
    }

    unsafe extern "C-unwind" fn successful_write_changes_errno(
        cookie: *mut libc::c_void,
        _bytes: *const libc::c_char,
        length: usize,
    ) -> isize {
        // SAFETY: this subprocess keeps the byte counter live until fclose.
        // Successful callbacks may change errno; that must not erase a
        // different stream's failure during the same fflush(NULL).
        unsafe {
            *cookie.cast::<usize>() += length;
            *libc::__errno_location() = libc::EDOM;
            *frankenlibc_abi::errno_abi::__errno_location() = libc::EDOM;
        }
        length as isize
    }

    // Isolate process-global fflush and guard against callback lock regressions.
    unsafe { libc::alarm(30) };
    let host = unsafe { libc::fopen(c"/dev/full".as_ptr(), c"w".as_ptr()) };
    assert!(!host.is_null());
    let mut host_buffer = [0u8; 4096];
    assert_eq!(
        unsafe {
            libc::setvbuf(
                host,
                host_buffer.as_mut_ptr().cast(),
                libc::_IOFBF,
                host_buffer.len(),
            )
        },
        0
    );
    let mut written = 0usize;
    let cookie = unsafe {
        fl::fopencookie(
            (&mut written as *mut usize).cast(),
            c"w".as_ptr(),
            fl::CookieIoFuncs {
                write: Some(successful_write_changes_errno),
                ..fl::CookieIoFuncs::default()
            },
        )
    };
    assert!(!cookie.is_null());
    assert_eq!(
        unsafe { fl::setvbuf(cookie, std::ptr::null_mut(), libc::_IOFBF, 4096) },
        0
    );
    assert_eq!(
        unsafe { libc::fwrite(c"host".as_ptr().cast(), 1, 4, host) },
        4
    );
    assert_eq!(unsafe { libc::ferror(host) }, 0);
    assert_eq!(
        unsafe { fl::fwrite(c"native".as_ptr().cast(), 1, 6, cookie) },
        6
    );
    assert_eq!(
        written, 0,
        "the successful native write must still be pending"
    );

    let result = unsafe { fl::fflush(std::ptr::null_mut()) };
    let error = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    let native_error = unsafe { fl::ferror(cookie) };
    let host_error = unsafe { libc::ferror(host) };
    // Close both streams before reporting any assertion failure, so no later
    // test or process shutdown inherits the deliberately failing host stream.
    let native_close = unsafe { fl::fclose(cookie) };
    unsafe {
        libc::fclose(host);
        libc::alarm(0);
    }
    assert_eq!(
        written, 6,
        "native output must still flush after host failure"
    );
    assert_eq!(native_error, 0);
    assert_ne!(host_error, 0);
    assert_eq!(native_close, 0);
    assert_eq!(result, libc::EOF);
    assert_eq!(
        error,
        libc::ENOSPC,
        "host failure must survive successful native flush"
    );
}
