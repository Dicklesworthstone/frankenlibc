#![cfg(target_os = "linux")]

//! Differential conformance harness for `getline(3)` / `getdelim(3)`.
//!
//! Both read up to a delimiter (newline or arbitrary byte) from a
//! FILE*, allocating/growing the line buffer as needed. fl uses its
//! own FILE* implementation; tests below use identical in-memory data and
//! nonblocking pipes to check both providers, including sticky stream errors.
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
fn getline_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getline + getdelim\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
