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
fn getline_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getline + getdelim\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
