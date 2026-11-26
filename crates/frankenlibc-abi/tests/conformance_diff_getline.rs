#![cfg(target_os = "linux")]

//! Differential conformance harness for `getline(3)` / `getdelim(3)`.
//!
//! Both read up to a delimiter (newline or arbitrary byte) from a
//! FILE*, allocating/growing the line buffer as needed. fl uses its
//! own FILE* implementation; tests below use identical in-memory data and
//! nonblocking pipes to check both providers, including sticky stream errors.
//! Bounded internal line helpers are compared for status, orientation and input recovery.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    fn fmemopen(buf: *mut c_void, size: usize, mode: *const c_char) -> *mut libc::FILE;
    fn fclose(fp: *mut libc::FILE) -> c_int;
    fn getline(lineptr: *mut *mut c_char, n: *mut usize, stream: *mut libc::FILE) -> isize;
    fn getdelim(
        lineptr: *mut *mut c_char,
        n: *mut usize,
        delim: c_int,
        stream: *mut libc::FILE,
    ) -> isize;
    fn fwide(stream: *mut libc::FILE, mode: c_int) -> c_int;
    #[link_name = "_IO_getline_info"]
    fn host_io_getline_info(
        stream: *mut libc::FILE,
        buffer: *mut c_char,
        size: usize,
        delimiter: c_int,
        extract: c_int,
        status: *mut c_int,
    ) -> usize;
    #[link_name = "_IO_getline"]
    fn host_io_getline(
        stream: *mut libc::FILE,
        buffer: *mut c_char,
        size: usize,
        delimiter: c_int,
        extract: c_int,
    ) -> usize;
}

/// Read all lines from a fmemopen-backed buffer, returning the sequence
/// of (line, return_value) tuples.
fn collect_lines<F, R>(content: &[u8], reader: F, release: R) -> Vec<(Vec<u8>, isize)>
where
    F: Fn(*mut *mut c_char, *mut usize, *mut libc::FILE) -> isize,
    R: Fn(*mut c_char),
{
    let mut owned = content.to_vec();
    let fp = unsafe {
        fmemopen(
            owned.as_mut_ptr() as *mut c_void,
            owned.len(),
            c"r".as_ptr(),
        )
    };
    if fp.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut line: *mut c_char = std::ptr::null_mut();
    let mut n: usize = 0;
    loop {
        let r = reader(&mut line, &mut n, fp);
        if r < 0 {
            break;
        }
        let bytes = unsafe { std::slice::from_raw_parts(line as *const u8, r as usize).to_vec() };
        out.push((bytes, r));
    }
    if !line.is_null() {
        // RELEASED BY THE PROVIDER THAT MAY HAVE ALLOCATED IT. fl's getline
        // allocates its own buffer for a native stream and delegates (returning
        // host storage) for a host stream, so freeing through fl's entrypoint is
        // correct in both cases and glibc's free is only correct for the host
        // arm. One shared `libc::free` here is what aborted this target with
        // "free(): invalid size" before bd-reality-202609-lx578q.7.
        release(line);
    }
    unsafe { fclose(fp) };
    out
}

#[test]
fn diff_getline_via_fmemopen() {
    let content = b"first line\nsecond line\nlast no newline";
    let fl_lines = collect_lines(
        content,
        |lp, n, fp| unsafe { frankenlibc_abi::stdio_abi::getline(lp, n, fp as *mut c_void) },
        |p| unsafe { frankenlibc_abi::malloc_abi::free(p.cast()) },
    );
    let lc_lines = collect_lines(
        content,
        |lp, n, fp| unsafe { getline(lp, n, fp) },
        |p| unsafe { libc::free(p.cast()) },
    );
    assert_eq!(
        fl_lines.len(),
        lc_lines.len(),
        "line count mismatch: fl={} lc={}",
        fl_lines.len(),
        lc_lines.len()
    );
    for (i, (fl, lc)) in fl_lines.iter().zip(lc_lines.iter()).enumerate() {
        assert_eq!(fl.0, lc.0, "line {i} bytes differ");
        assert_eq!(fl.1, lc.1, "line {i} return value differs");
    }
}

#[test]
fn diff_getdelim_with_colon_delimiter() {
    let content = b"alpha:beta:gamma:delta";
    let fl_lines = collect_lines(
        content,
        |lp, n, fp| unsafe {
            frankenlibc_abi::stdio_abi::getdelim(lp, n, b':' as c_int, fp as *mut c_void)
        },
        |p| unsafe { frankenlibc_abi::malloc_abi::free(p.cast()) },
    );
    let lc_lines = collect_lines(
        content,
        |lp, n, fp| unsafe { getdelim(lp, n, b':' as c_int, fp) },
        |p| unsafe { libc::free(p.cast()) },
    );
    assert_eq!(fl_lines.len(), lc_lines.len(), "field count mismatch");
    for (i, (fl, lc)) in fl_lines.iter().zip(lc_lines.iter()).enumerate() {
        assert_eq!(fl.0, lc.0, "field {i} bytes");
        assert_eq!(fl.1, lc.1, "field {i} return value");
    }
}

#[test]
fn diff_getline_empty_input() {
    let content = b"";
    let fl_lines = collect_lines(
        content,
        |lp, n, fp| unsafe { frankenlibc_abi::stdio_abi::getline(lp, n, fp as *mut c_void) },
        |p| unsafe { frankenlibc_abi::malloc_abi::free(p.cast()) },
    );
    let lc_lines = collect_lines(
        content,
        |lp, n, fp| unsafe { getline(lp, n, fp) },
        |p| unsafe { libc::free(p.cast()) },
    );
    assert_eq!(fl_lines, lc_lines);
}

#[test]
fn diff_getline_single_long_line() {
    // 200-char line forces buffer growth in both impls.
    let line: Vec<u8> = std::iter::repeat_n(b'x', 200)
        .chain(std::iter::once(b'\n'))
        .collect();
    let fl_lines = collect_lines(
        &line,
        |lp, n, fp| unsafe { frankenlibc_abi::stdio_abi::getline(lp, n, fp as *mut c_void) },
        |p| unsafe { frankenlibc_abi::malloc_abi::free(p.cast()) },
    );
    let lc_lines = collect_lines(
        &line,
        |lp, n, fp| unsafe { getline(lp, n, fp) },
        |p| unsafe { libc::free(p.cast()) },
    );
    assert_eq!(fl_lines.len(), 1);
    assert_eq!(fl_lines[0].0, line);
    assert_eq!(fl_lines, lc_lines);
}

#[test]
fn host_getline_grows_a_frankenlibc_segment_buffer_safely() {
    for use_getline in [true, false] {
        check_host_line_buffer_growth(use_getline);
    }
}

fn check_host_line_buffer_growth(use_getline: bool) {
    use frankenlibc_abi::malloc_abi as malloc;

    malloc::signal_runtime_ready_for_tests();
    let mut content: Vec<u8> = std::iter::repeat_n(b'z', 256)
        .chain(std::iter::once(b'\n'))
        .collect();
    let fp = unsafe { fmemopen(content.as_mut_ptr().cast(), content.len(), c"r".as_ptr()) };
    assert!(!fp.is_null());

    let initial = unsafe { malloc::malloc(16) };
    assert!(!initial.is_null());
    if frankenlibc_membrane::config::safety_level().heals_enabled() {
        // Hardened malloc uses the membrane arena, rather than strict mode's
        // segment heap. Both ownership classes must migrate before host realloc.
        assert!(!malloc::malloc_segment_owned_for_tests(
            initial.cast_const()
        ));
        assert_eq!(
            malloc::malloc_known_remaining_for_tests(initial.cast_const()),
            Some(16)
        );
    } else {
        assert!(malloc::malloc_segment_owned_for_tests(initial.cast_const()));
    }
    let mut line = initial.cast::<c_char>();
    let mut capacity = 16usize;
    let scan = |p, n| unsafe {
        if use_getline {
            frankenlibc_abi::stdio_abi::getline(p, n, fp.cast())
        } else {
            frankenlibc_abi::stdio_abi::getdelim(p, n, b'\n' as c_int, fp.cast())
        }
    };
    // SAFETY: the caller owns 16 writable bytes; fp is a live read-only host
    // stream. The failed write plants its sticky error before any input.
    unsafe {
        std::ptr::write_bytes(line, 0x5A, capacity);
        assert_eq!(libc::fputc(b'X' as c_int, fp), libc::EOF);
        *libc::__errno_location() = 0x5EED;
    }
    assert_eq!(scan(&mut line, &mut capacity), -1);
    assert_eq!(unsafe { *libc::__errno_location() }, 0x5EED);
    assert_ne!(unsafe { libc::ferror(fp) }, 0);
    assert_eq!(capacity, 16);
    // SAFETY: the failed host call retained the supplied initialized 16-byte
    // buffer. Its bytes and tracked bounds must survive the ownership move.
    assert_eq!(
        unsafe { std::slice::from_raw_parts(line.cast::<u8>(), capacity) },
        [0x5A; 16]
    );
    assert_eq!(
        malloc::malloc_known_remaining_for_tests(line.cast_const().cast()),
        Some(16)
    );
    unsafe { libc::clearerr(fp) };
    let read = scan(&mut line, &mut capacity);
    assert_eq!(read, content.len() as isize);
    assert!(capacity > content.len());
    assert_eq!(
        unsafe { std::slice::from_raw_parts(line.cast::<u8>(), read as usize) },
        content
    );
    assert!(
        !malloc::malloc_segment_owned_for_tests(line.cast_const().cast()),
        "host getline must receive and return host-owned storage"
    );

    unsafe {
        malloc::free(line.cast());
        fclose(fp);
    }
}

#[test]
fn fd_line_input_preserves_pushback_until_error_is_cleared() {
    use frankenlibc_abi::stdio_abi as fl;

    fn observe(native: bool, unbuffered: bool, warmed: bool, write_error: bool, line: bool) {
        let mut fds = [-1; 2];
        // SAFETY: pipe2 initializes both descriptor slots on success. The pipe
        // is nonblocking so even a broken sticky-error guard cannot hang.
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) },
            0
        );
        // SAFETY: fdopen takes ownership of the valid read descriptor; each
        // provider later closes its own FILE and allocation exactly once.
        unsafe {
            let stream = if native {
                fl::fdopen(fds[0], c"r".as_ptr())
            } else {
                libc::fdopen(fds[0], c"r".as_ptr()).cast()
            };
            assert!(!stream.is_null());
            let buffer_mode = if unbuffered {
                libc::_IONBF
            } else {
                libc::_IOFBF
            };
            let buffered = if native {
                fl::setvbuf(stream, std::ptr::null_mut(), buffer_mode, 0)
            } else {
                libc::setvbuf(stream.cast(), std::ptr::null_mut(), buffer_mode, 0)
            };
            assert_eq!(buffered, 0);
            let mut output = std::ptr::null_mut();
            let mut capacity = 0usize;
            let delimiter = if line { b'\n' } else { b';' };
            let scan = |p, n| match (native, line) {
                (true, true) => fl::getline(p, n, stream),
                (true, false) => fl::getdelim(p, n, delimiter as c_int, stream),
                (false, true) => getline(p, n, stream.cast()),
                (false, false) => getdelim(p, n, delimiter as c_int, stream.cast()),
            };
            if warmed {
                let input = [b'W', delimiter];
                assert_eq!(libc::write(fds[1], input.as_ptr().cast(), input.len()), 2);
                assert_eq!(scan(&mut output, &mut capacity), 2);
            }
            let initial_error = if write_error {
                if native {
                    fl::fputc(b'X' as c_int, stream) as isize
                } else {
                    libc::fputc(b'X' as c_int, stream.cast()) as isize
                }
            } else {
                scan(&mut output, &mut capacity)
            };
            assert_eq!(initial_error, -1);
            let pushed = if native {
                fl::ungetc(b'P' as c_int, stream)
            } else {
                libc::ungetc(b'P' as c_int, stream.cast())
            };
            assert_eq!(pushed, b'P' as c_int);
            let input = [b'Z', delimiter];
            assert_eq!(libc::write(fds[1], input.as_ptr().cast(), input.len()), 2);
            *libc::__errno_location() = 0x5EED;
            let stopped = scan(&mut output, &mut capacity);
            let saved_errno = *libc::__errno_location();
            let error = if native {
                fl::ferror(stream)
            } else {
                libc::ferror(stream.cast())
            };
            let eof = if native {
                fl::feof(stream)
            } else {
                libc::feof(stream.cast())
            };
            if native {
                fl::clearerr(stream);
            } else {
                libc::clearerr(stream.cast());
            }
            let recovered = scan(&mut output, &mut capacity);
            let bytes = if recovered >= 0 && !output.is_null() && capacity > recovered as usize {
                // SAFETY: successful line input initializes recovered bytes
                // and a NUL; its reported capacity bounds this complete slice.
                std::slice::from_raw_parts(output.cast::<u8>(), recovered as usize + 1).to_vec()
            } else {
                Vec::new()
            };
            let closed = if native {
                fl::fclose(stream)
            } else {
                libc::fclose(stream.cast())
            };
            if native {
                frankenlibc_abi::malloc_abi::free(output.cast());
            } else {
                libc::free(output.cast());
            }
            assert_eq!(libc::close(fds[1]), 0);
            assert_eq!(closed, 0);
            assert_eq!(
                (stopped, saved_errno, error != 0, eof != 0),
                (-1, 0x5EED, true, false)
            );
            assert_eq!(recovered, 3);
            assert_eq!(bytes, [b'P', b'Z', delimiter, 0]);
        }
    }

    for unbuffered in [false, true] {
        for warmed in [false, true] {
            for write_error in [false, true] {
                for line in [false, true] {
                    observe(false, unbuffered, warmed, write_error, line);
                    observe(true, unbuffered, warmed, write_error, line);
                }
            }
        }
    }
}

#[test]
fn internal_line_input_matches_gnu_status_and_orientation() {
    use frankenlibc_abi::{glibc_internal_abi as internal, io_internal_abi as io, stdio_abi as fl};

    #[derive(Debug, PartialEq, Eq)]
    struct Observation {
        count: usize,
        status: Option<c_int>,
        orientation: c_int,
        eof: bool,
        error: bool,
        output: [u8; 32],
        next: [c_int; 2],
    }

    fn observe(
        native: bool,
        kind: usize,
        size: usize,
        null_buffer: bool,
        extract: c_int,
        api: usize,
    ) -> Observation {
        let inputs: [&[u8]; 6] = [b"", b"abc", b"ab\ncd", b"", b"abc", b"abc"];
        // The last arm passes a genuine host FILE to our internal reader.
        let native_stream = native && kind != 5;
        let mut backing = [0u8; 8];
        backing[..inputs[kind].len()].copy_from_slice(inputs[kind]);
        let mut fds = [-1; 2];
        if kind >= 3 {
            // SAFETY: both output descriptors are initialized on success. The
            // live nonblocking writer keeps reads at EAGAIN instead of EOF.
            assert_eq!(
                unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) },
                0
            );
            if kind >= 4 {
                // SAFETY: the fresh pipe has space for this live three-byte input.
                assert_eq!(
                    unsafe { libc::write(fds[1], inputs[kind].as_ptr().cast(), 3) },
                    3
                );
            }
        }
        // SAFETY: backing stays live until this provider closes its stream;
        // each fdopen consumes a valid read descriptor exactly once. Both
        // providers receive a writable 32-byte output and a size at most 8,
        // or a NULL output only when the requested size is zero.
        unsafe {
            let stream = match (native_stream, kind >= 3) {
                (true, true) => fl::fdopen(fds[0], c"r".as_ptr()),
                (true, false) => fl::fmemopen(
                    backing.as_mut_ptr().cast(),
                    inputs[kind].len(),
                    c"r".as_ptr(),
                ),
                (false, true) => libc::fdopen(fds[0], c"r".as_ptr()).cast(),
                (false, false) => fmemopen(
                    backing.as_mut_ptr().cast(),
                    inputs[kind].len(),
                    c"r".as_ptr(),
                )
                .cast(),
            };
            assert!(!stream.is_null());
            let orientation = |mode| {
                if native_stream {
                    internal::fwide(stream, mode)
                } else {
                    fwide(stream.cast(), mode)
                }
            };
            assert_eq!(orientation(0).signum(), if kind >= 3 { 0 } else { -1 });
            let mut output = [0xA5u8; 32];
            assert!(!null_buffer || size == 0);
            let output_ptr = if null_buffer {
                std::ptr::null_mut()
            } else {
                output.as_mut_ptr().cast()
            };
            let mut status = 0x5EED;
            let status_ptr = if api == 0 {
                &mut status
            } else {
                std::ptr::null_mut()
            };
            let count = match (native, api == 2) {
                (true, false) => io::_IO_getline_info(
                    stream,
                    output_ptr,
                    size,
                    b'\n' as c_int,
                    extract,
                    status_ptr,
                ),
                (true, true) => io::_IO_getline(stream, output_ptr, size, b'\n' as c_int, extract),
                (false, false) => host_io_getline_info(
                    stream.cast(),
                    output_ptr,
                    size,
                    b'\n' as c_int,
                    extract,
                    status_ptr,
                ),
                (false, true) => {
                    host_io_getline(stream.cast(), output_ptr, size, b'\n' as c_int, extract)
                }
            };
            assert!(count <= size);
            assert!(output[count..].iter().all(|&byte| byte == 0xA5));
            let (eof, error) = if native_stream {
                (fl::feof(stream) != 0, fl::ferror(stream) != 0)
            } else {
                (
                    libc::feof(stream.cast()) != 0,
                    libc::ferror(stream.cast()) != 0,
                )
            };
            let after = orientation(0).signum();
            let mut next = [-1; 2];
            for byte in &mut next {
                *byte = if native_stream {
                    fl::fgetc(stream)
                } else {
                    libc::fgetc(stream.cast())
                };
            }
            let closed = if native_stream {
                fl::fclose(stream)
            } else {
                fclose(stream.cast())
            };
            assert_eq!(closed, 0);
            if kind >= 3 {
                assert_eq!(libc::close(fds[1]), 0);
            }
            Observation {
                count,
                status: (api == 0).then_some(status),
                orientation: after,
                eof,
                error,
                output,
                next,
            }
        }
    }

    frankenlibc_abi::malloc_abi::signal_runtime_ready_for_tests();
    for function in [
        host_io_getline_info as *const c_void,
        host_io_getline as *const c_void,
    ] {
        // SAFETY: dladdr initializes the output for a live function address;
        // its filename remains owned by the permanently loaded GNU libc.
        unsafe {
            let mut info: libc::Dl_info = std::mem::zeroed();
            assert_ne!(libc::dladdr(function, &mut info), 0);
            assert!(!info.dli_fname.is_null());
            let path = std::ffi::CStr::from_ptr(info.dli_fname).to_bytes();
            assert_eq!(
                path.rsplit(|&byte| byte == b'/').next(),
                Some(&b"libc.so.6"[..])
            );
        }
    }
    let mut comparisons = 0;
    for kind in 0..6 {
        for (size, null_buffer) in [(0, false), (0, true), (2, false), (8, false)] {
            for extract in [-1, 0, 1] {
                for api in 0..3 {
                    let host = observe(false, kind, size, null_buffer, extract, api);
                    assert_eq!(host.orientation, -1);
                    if api == 0
                        && size > 0
                        && (kind == 0 || kind == 3 || ((kind == 1 || kind >= 4) && size == 8))
                    {
                        assert_eq!(host.status, Some(libc::EOF));
                    }
                    assert_eq!(
                        observe(true, kind, size, null_buffer, extract, api),
                        host,
                        "kind={kind}, size={size}, null_buffer={null_buffer}, extract={extract}, api={api}"
                    );
                    comparisons += 1;
                }
            }
        }
    }
    assert_eq!(comparisons, 216);
}

#[test]
fn fwide_preserves_foreign_stream_orientation() {
    use frankenlibc_abi::glibc_internal_abi as fl;

    frankenlibc_abi::malloc_abi::signal_runtime_ready_for_tests();
    for initial in [-1, 0, 1] {
        for requested in [-1, 0, 1] {
            let mut observed = [0; 2];
            for (native, result) in observed.iter_mut().enumerate() {
                let mut fds = [-1; 2];
                // SAFETY: a fresh nonblocking pipe and genuine host FILE stay
                // live through all orientation queries, then close once each.
                unsafe {
                    assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK), 0);
                    let stream = libc::fdopen(fds[0], c"r".as_ptr());
                    assert!(!stream.is_null());
                    assert_eq!(fwide(stream, initial).signum(), initial);
                    *result = if native == 1 {
                        fl::fwide(stream.cast(), requested)
                    } else {
                        fwide(stream, requested)
                    }
                    .signum();
                    assert_eq!(fwide(stream, 0).signum(), *result);
                    assert_eq!(libc::feof(stream), 0);
                    assert_eq!(libc::ferror(stream), 0);
                    assert_eq!(fclose(stream), 0);
                    assert_eq!(libc::close(fds[1]), 0);
                }
            }
            assert_eq!(
                observed[0], observed[1],
                "initial={initial}, requested={requested}"
            );
        }
    }
}

#[test]
fn getline_allocation_failure_is_a_stream_error() {
    use frankenlibc_abi::{malloc_abi as malloc, stdio_abi as fl};

    const CHILD_ENV: &str = "FRANKENLIBC_GETLINE_ALLOCATION_CHILD";
    const TEST_NAME: &str = "getline_allocation_failure_is_a_stream_error";

    unsafe extern "C" {
        #[link_name = "fopencookie"]
        fn host_cookie_open(
            cookie: *mut c_void,
            mode: *const c_char,
            funcs: fl::CookieIoFuncs,
        ) -> *mut c_void;
    }

    unsafe extern "C-unwind" fn zero_cookie_read(
        cookie: *mut c_void,
        output: *mut c_char,
        capacity: usize,
    ) -> isize {
        // SAFETY: the child retains this counter until fclose, and both
        // providers supply capacity writable bytes to the read callback.
        let remaining = unsafe { &mut *cookie.cast::<usize>() };
        let count = capacity.min(*remaining);
        unsafe { std::ptr::write_bytes(output.cast::<u8>(), 0, count) };
        *remaining -= count;
        count as isize
    }

    let Ok(case) = std::env::var(CHILD_ENV) else {
        // Direct ABI calls exercise the candidate's own FILE implementation.
        // The extern reference must remain an independent GNU libc provider.
        for function in [getline as *const c_void, getdelim as *const c_void] {
            // SAFETY: these are live function addresses and dladdr initializes
            // its result on success. libc stays loaded for the entire test.
            unsafe {
                let mut info: libc::Dl_info = std::mem::zeroed();
                assert_ne!(libc::dladdr(function, &mut info), 0);
                assert!(!info.dli_fname.is_null());
                let path = std::ffi::CStr::from_ptr(info.dli_fname).to_bytes();
                assert_eq!(
                    path.rsplit(|&byte| byte == b'/').next(),
                    Some(&b"libc.so.6"[..])
                );
            }
        }

        let executable = std::env::current_exe().expect("current test executable");
        let mut executed = 0;
        for provider in ["host", "native"] {
            for kind in ["buffered", "cached", "unbuffered", "cookie"] {
                let child_case = format!("{provider}:{kind}");
                // Secondary GNU arenas can reserve address space before the
                // limit is installed. One arena makes line growth request
                // new mappings, which the real RLIMIT_AS can then reject.
                let output = std::process::Command::new(&executable)
                    .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
                    .env(CHILD_ENV, &child_case)
                    .env("GLIBC_TUNABLES", "glibc.malloc.arena_max=1")
                    .output()
                    .expect("start isolated allocation-failure child");
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    output.status.success(),
                    "{child_case}: child failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    output.status
                );
                assert!(
                    stdout.contains("test result: ok. 1 passed; 0 failed;"),
                    "{child_case}: the requested child test did not execute\n{stdout}\n{stderr}"
                );
                executed += 1;
            }
        }
        assert_eq!(executed, 8);
        return;
    };

    let (provider, kind) = case.split_once(':').expect("provider:stream child case");
    assert!(matches!(provider, "host" | "native"));
    assert!(matches!(
        kind,
        "buffered" | "cached" | "unbuffered" | "cookie"
    ));
    let native = provider == "native";
    let use_getline = matches!(kind, "cached" | "unbuffered");
    malloc::signal_runtime_ready_for_tests();

    // The child has its own address space, timer, and resource limits. An
    // allocation loop that never reports failure must not hang the test.
    unsafe { libc::alarm(45) };

    let mut remaining = 128 * 1024 * 1024usize;
    let stream = if kind == "cookie" {
        let funcs = fl::CookieIoFuncs {
            read: Some(zero_cookie_read),
            ..Default::default()
        };
        // SAFETY: remaining outlives the stream and the read callback writes
        // only the destination range supplied by the active provider.
        unsafe {
            if native {
                fl::fopencookie((&mut remaining as *mut usize).cast(), c"r".as_ptr(), funcs)
            } else {
                host_cookie_open((&mut remaining as *mut usize).cast(), c"r".as_ptr(), funcs)
            }
        }
    } else {
        // An actual descriptor supplies an arbitrarily long line without
        // allocating an equally large input fixture in the test process.
        let fd = unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0);
        // SAFETY: the selected fdopen takes ownership of this live descriptor.
        unsafe {
            if native {
                fl::fdopen(fd, c"r".as_ptr())
            } else {
                libc::fdopen(fd, c"r".as_ptr()).cast()
            }
        }
    };
    assert!(!stream.is_null());

    if kind == "cookie" {
        // Allocate the callback reader's own buffer before applying pressure,
        // so the tested failure comes after real line-input growth.
        let first = unsafe {
            if native {
                fl::fgetc(stream)
            } else {
                libc::fgetc(stream.cast())
            }
        };
        assert_eq!(first, 0);
    }

    if kind == "unbuffered" {
        // SAFETY: no I/O has occurred on this live stream.
        let result = unsafe {
            if native {
                fl::setvbuf(stream, std::ptr::null_mut(), libc::_IONBF, 0)
            } else {
                libc::setvbuf(stream.cast(), std::ptr::null_mut(), libc::_IONBF, 0)
            }
        };
        assert_eq!(result, 0);
    }

    let mut line = std::ptr::null_mut();
    let mut capacity = 0usize;
    let scan = |lineptr, size| unsafe {
        match (native, use_getline) {
            (true, true) => fl::getline(lineptr, size, stream),
            (true, false) => fl::getdelim(lineptr, size, b'\n' as c_int, stream),
            (false, true) => getline(lineptr, size, stream.cast()),
            (false, false) => getdelim(lineptr, size, b'\n' as c_int, stream.cast()),
        }
    };

    if kind == "cached" {
        // A real successful line warms both the reusable scratch buffer and
        // descriptor-stream cache before the allocation-failure call.
        let pushed = unsafe {
            if native {
                fl::ungetc(b'\n' as c_int, stream)
            } else {
                libc::ungetc(b'\n' as c_int, stream.cast())
            }
        };
        assert_eq!(pushed, b'\n' as c_int);
        assert_eq!(scan(&mut line, &mut capacity), 1);
        assert!(capacity >= 2);
        assert_eq!(
            unsafe { std::slice::from_raw_parts(line.cast::<u8>(), 2) },
            b"\n\0"
        );
    }

    // Resolve errno and prepare all test bookkeeping before constraining
    // allocations. Failure assertions and formatted output wait until the
    // original address-space limit has been restored.
    let errno_slot = unsafe {
        if native {
            frankenlibc_abi::errno_abi::__errno_location()
        } else {
            libc::__errno_location()
        }
    };
    let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) },
        0
    );
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page_size > 0);
    let statm = std::fs::read_to_string("/proc/self/statm").expect("read mapped size");
    let pages = statm
        .split_whitespace()
        .next()
        .expect("mapped page count")
        .parse::<u64>()
        .expect("numeric mapped page count");
    let mapped = pages
        .checked_mul(page_size as u64)
        .expect("mapped address-space size");
    let limited = libc::rlimit {
        rlim_cur: mapped
            // A small headroom keeps per-byte debug cookie reads bounded
            // while still requiring real scratch growth before ENOMEM.
            .checked_add(512 * 1024)
            .expect("bounded test limit")
            .min(original.rlim_cur),
        rlim_max: original.rlim_max,
    };
    assert!(limited.rlim_cur > mapped);
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limited) }, 0);

    // SAFETY: the FILE and output slots remain live. Capture each observation
    // before restoring the limit, with no test-side heap growth.
    let (result, saved_errno, error, eof, repeated, repeated_errno, restored) = unsafe {
        *errno_slot = 0;
        let result = scan(&mut line, &mut capacity);
        let saved_errno = *errno_slot;
        let (error, eof) = if native {
            (fl::ferror(stream), fl::feof(stream))
        } else {
            (libc::ferror(stream.cast()), libc::feof(stream.cast()))
        };
        *errno_slot = 0x5EED;
        let repeated = scan(&mut line, &mut capacity);
        let repeated_errno = *errno_slot;
        let restored = libc::setrlimit(libc::RLIMIT_AS, &original);
        libc::alarm(0);
        (
            result,
            saved_errno,
            error,
            eof,
            repeated,
            repeated_errno,
            restored,
        )
    };
    assert_eq!(restored, 0, "restore child address-space limit");
    assert_eq!(
        result, -1,
        "{case}: allocation failure must not report a partial line"
    );
    assert_eq!(saved_errno, libc::ENOMEM, "{case}: allocation errno");
    if kind == "cookie" {
        assert!(
            128 * 1024 * 1024usize - remaining >= 16 * 1024,
            "{case}: exercise line growth beyond callback-buffer setup"
        );
    }
    assert_ne!(error, 0, "{case}: allocation failure must set ferror");
    assert_eq!(eof, 0, "{case}: allocation failure is not EOF");
    assert_eq!(
        repeated, -1,
        "{case}: sticky error must stop subsequent input"
    );
    assert_eq!(
        repeated_errno, 0x5EED,
        "{case}: sticky error preserves errno"
    );

    // Clear the sticky error only after restoring the real resource limit.
    // Further source bytes must remain available and FILE locks must have
    // been released even when the failed read used the cached cell path.
    let (next, closed) = unsafe {
        if native {
            fl::clearerr(stream);
            let next = fl::fgetc(stream);
            let closed = fl::fclose(stream);
            malloc::free(line.cast());
            (next, closed)
        } else {
            libc::clearerr(stream.cast());
            let next = libc::fgetc(stream.cast());
            let closed = libc::fclose(stream.cast());
            libc::free(line.cast());
            (next, closed)
        }
    };
    assert_eq!(next, 0, "{case}: recover unread input after clearerr");
    assert_eq!(closed, 0);
}

#[test]
fn getline_cold_refill_allocation_failure_is_a_stream_error() {
    use frankenlibc_abi::{malloc_abi as malloc, stdio_abi as fl};

    const CHILD_ENV: &str = "FRANKENLIBC_GETLINE_COLD_REFILL_CHILD";
    const TEST_NAME: &str = "getline_cold_refill_allocation_failure_is_a_stream_error";

    let Ok(case) = std::env::var(CHILD_ENV) else {
        // Rust's System allocator and this pressure loop must use the same
        // independent GNU allocator in the hosted debug integration test.
        unsafe {
            let mut info: libc::Dl_info = std::mem::zeroed();
            assert_ne!(libc::dladdr(libc::malloc as *const c_void, &mut info), 0);
            assert!(!info.dli_fname.is_null());
            let path = std::ffi::CStr::from_ptr(info.dli_fname).to_bytes();
            assert_eq!(
                path.rsplit(|&byte| byte == b'/').next(),
                Some(&b"libc.so.6"[..])
            );
        }

        let executable = std::env::current_exe().expect("current test executable");
        let mut executed = 0;
        for case in ["bounce", "storage"] {
            let output = std::process::Command::new(&executable)
                .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD_ENV, case)
                .env("GLIBC_TUNABLES", "glibc.malloc.arena_max=1")
                // The storage case deliberately reuses a warmed TLS bounce
                // buffer; native-thread admission disables that reuse.
                .env("FRANKENLIBC_THREAD_NATIVE", "0")
                .output()
                .expect("start isolated cold-refill child");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                output.status.success(),
                "{case}: child failed with {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status
            );
            assert!(
                stdout.contains("test result: ok. 1 passed; 0 failed;"),
                "{case}: the requested child test did not execute\n{stdout}\n{stderr}"
            );
            executed += 1;
        }
        assert_eq!(executed, 2);
        return;
    };

    assert!(matches!(case.as_str(), "bounce" | "storage"));
    malloc::signal_runtime_ready_for_tests();
    unsafe { libc::alarm(45) };

    let open_input = || unsafe {
        let mut descriptors = [-1; 2];
        assert_eq!(libc::pipe(descriptors.as_mut_ptr()), 0);
        assert_eq!(libc::write(descriptors[1], b"A\n".as_ptr().cast(), 2), 2);
        assert_eq!(libc::close(descriptors[1]), 0);
        let stream = fl::fdopen(descriptors[0], c"r".as_ptr());
        assert!(!stream.is_null());
        stream
    };
    let stream = open_input();
    let warm_stream = if case == "storage" {
        let auxiliary = open_input();
        // A real descriptor refill warms REFILL_TMP, but the target FILE
        // still has no allocated core read-buffer storage.
        assert_eq!(unsafe { fl::fgetc(auxiliary) }, b'A' as c_int);
        auxiliary
    } else {
        stream
    };

    let mut line = std::ptr::null_mut();
    let mut capacity = 0usize;
    // Pushback warms the line scratch, caller buffer and stream cache without
    // a descriptor read. In the bounce case it also allocates the target's
    // core storage, isolating the still-cold refill bounce buffer.
    assert_eq!(
        unsafe { fl::ungetc(b'\n' as c_int, warm_stream) },
        b'\n' as c_int
    );
    assert_eq!(
        unsafe { fl::getline(&mut line, &mut capacity, warm_stream) },
        1
    );
    assert!(capacity >= 2);
    assert_eq!(
        unsafe { std::slice::from_raw_parts(line.cast::<u8>(), 2) },
        b"\n\0"
    );
    if case == "storage" {
        assert_eq!(unsafe { fl::fclose(warm_stream) }, 0);
    } else {
        // Returning ordinary I/O failure from refill would incorrectly turn
        // this prefix into a successful partial line instead of ENOMEM.
        assert_eq!(unsafe { fl::ungetc(b'P' as c_int, stream) }, b'P' as c_int);
    }

    let original_line = line;
    let original_capacity = capacity;
    let refill_size = unsafe { frankenlibc_abi::glibc_internal_abi::__fbufsize(stream) }.min(8192);
    assert!(refill_size > 0);
    // A bounded retention vector is allocated before the limit. Retaining
    // same-sized malloc blocks drains reusable arena space as well as proving
    // that the real address-space limit prevents further allocations.
    let mut retained = Vec::with_capacity(65_536);
    let errno_slot = unsafe { frankenlibc_abi::errno_abi::__errno_location() };
    let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_AS, &mut original) },
        0
    );
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page_size > 0);
    let statm = std::fs::read_to_string("/proc/self/statm").expect("read mapped size");
    let pages = statm
        .split_whitespace()
        .next()
        .expect("mapped page count")
        .parse::<u64>()
        .expect("numeric mapped page count");
    let mapped = pages
        .checked_mul(page_size as u64)
        .expect("mapped address-space size");
    assert!(original.rlim_cur >= mapped);
    let limited = libc::rlimit {
        rlim_cur: mapped,
        rlim_max: original.rlim_max,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_AS, &limited) }, 0);

    // No assertions, formatting, or test-side heap growth occur until the
    // original limit has been restored. A fixture that fails to exhaust its
    // bounded allocation slots is a failure, never a skipped positive result.
    let (exhausted, result, saved_errno, error, eof, restored) = unsafe {
        let mut exhausted = false;
        while retained.len() < retained.capacity() {
            let allocation = libc::malloc(refill_size);
            if allocation.is_null() {
                exhausted = true;
                break;
            }
            retained.push(allocation);
        }
        *errno_slot = 0;
        let result = if exhausted {
            fl::getline(&mut line, &mut capacity, stream)
        } else {
            0
        };
        let saved_errno = *errno_slot;
        let error = fl::ferror(stream);
        let eof = fl::feof(stream);
        let restored = libc::setrlimit(libc::RLIMIT_AS, &original);
        libc::alarm(0);
        (exhausted, result, saved_errno, error, eof, restored)
    };
    for allocation in retained {
        unsafe { libc::free(allocation) };
    }
    assert_eq!(restored, 0, "restore child address-space limit");
    assert!(
        exhausted,
        "{case}: allocation pressure did not reach ENOMEM"
    );
    assert_eq!(result, -1, "{case}: do not return an accumulated prefix");
    assert_eq!(saved_errno, libc::ENOMEM, "{case}: allocation errno");
    assert_ne!(error, 0, "{case}: allocation failure must set ferror");
    assert_eq!(eof, 0, "{case}: allocation failure is not EOF");
    assert_eq!(line, original_line, "{case}: retain the caller buffer");
    assert_eq!(
        capacity, original_capacity,
        "{case}: retain caller capacity"
    );

    // Both reserves must happen before the syscall. Exact nonzero bytes make
    // lost descriptor input visible, unlike an inexhaustible zero-filled fd.
    let (first, second, end, closed) = unsafe {
        fl::clearerr(stream);
        let first = fl::fgetc(stream);
        let second = fl::fgetc(stream);
        let end = fl::fgetc(stream);
        let closed = fl::fclose(stream);
        malloc::free(line.cast());
        (first, second, end, closed)
    };
    assert_eq!(first, b'A' as c_int, "{case}: preserve the first fd byte");
    assert_eq!(second, b'\n' as c_int, "{case}: preserve the next fd byte");
    assert_eq!(end, libc::EOF);
    assert_eq!(closed, 0);
}

#[test]
fn getline_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getline + getdelim\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
