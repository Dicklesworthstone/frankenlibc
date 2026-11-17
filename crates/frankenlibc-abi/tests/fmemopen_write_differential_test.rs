#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fmemopen oracle

//! Differential test for `fmemopen` behaviors vs host glibc that programs rely
//! on: (1) a size-0 stream is VALID (reads hit EOF immediately), (2) in write
//! mode glibc writes a terminating NUL after the data when the buffer has room,
//! and (3) the buffer contents after a write+flush match. Compares fl's
//! user-buffer outcome against glibc's for identical operations.

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn fmemopen(buf: *mut libc::c_void, size: usize, mode: *const libc::c_char) -> *mut libc::FILE;
    fn fputs(s: *const libc::c_char, stream: *mut libc::FILE) -> libc::c_int;
    fn fwrite(
        ptr: *const libc::c_void,
        size: usize,
        nmemb: usize,
        stream: *mut libc::FILE,
    ) -> usize;
    fn ftell(stream: *mut libc::FILE) -> libc::c_long;
    fn fseek(stream: *mut libc::FILE, offset: libc::c_long, whence: libc::c_int) -> libc::c_int;
    fn ferror(stream: *mut libc::FILE) -> libc::c_int;
    fn fflush(stream: *mut libc::FILE) -> libc::c_int;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
    fn fgetc(stream: *mut libc::FILE) -> libc::c_int;
    fn fread(ptr: *mut libc::c_void, size: usize, count: usize, stream: *mut libc::FILE) -> usize;
    fn fgets(
        ptr: *mut libc::c_char,
        size: libc::c_int,
        stream: *mut libc::FILE,
    ) -> *mut libc::c_char;
    fn fscanf(stream: *mut libc::FILE, format: *const libc::c_char, ...) -> libc::c_int;
    fn setvbuf(
        stream: *mut libc::FILE,
        buf: *mut libc::c_char,
        mode: libc::c_int,
        size: usize,
    ) -> libc::c_int;
    fn feof(stream: *mut libc::FILE) -> libc::c_int;
    fn ungetc(byte: libc::c_int, stream: *mut libc::FILE) -> libc::c_int;
}

// Keep each trace identical while selecting the real native or live GNU
// entrypoint. Seeking/buffering put FILE first; the readers put it last.
macro_rules! stream_call {
    ($native:expr, $stream:expr, fseek, $offset:expr, $whence:expr) => {
        if $native {
            fl::fseek($stream, $offset, $whence)
        } else {
            fseek($stream.cast(), $offset, $whence)
        }
    };
    ($native:expr, $stream:expr, setvbuf, $buf:expr, $mode:expr, $size:expr) => {
        if $native {
            fl::setvbuf($stream, $buf, $mode, $size)
        } else {
            setvbuf($stream.cast(), $buf, $mode, $size)
        }
    };
    ($native:expr, $stream:expr, $name:ident $(, $arg:expr)*) => {
        if $native {
            fl::$name($($arg,)* $stream)
        } else {
            $name($($arg,)* $stream.cast())
        }
    };
}

fn caller_buffer_transition_trace(
    native: bool,
    mode: &str,
    unbuffered: bool,
) -> (Vec<i64>, Vec<u8>) {
    let mode = CString::new(mode).unwrap();
    let mut backing = *b"12\nold\nZZZZZ";
    let mut trace = Vec::new();
    unsafe {
        let stream = if native {
            fl::fmemopen(backing.as_mut_ptr().cast(), backing.len(), mode.as_ptr())
        } else {
            fmemopen(backing.as_mut_ptr().cast(), backing.len(), mode.as_ptr()).cast()
        };
        assert!(!stream.is_null());
        if unbuffered {
            assert_eq!(
                stream_call!(
                    native,
                    stream,
                    setvbuf,
                    std::ptr::null_mut(),
                    libc::_IONBF,
                    0
                ),
                0
            );
        }
        let mut number = 0_i32;
        trace.push(if native {
            fl::fscanf(stream, c"%d".as_ptr(), &mut number as *mut i32)
        } else {
            fscanf(stream.cast(), c"%d".as_ptr(), &mut number as *mut i32)
        } as i64);
        trace.push(number as i64);
        trace.push(stream_call!(native, stream, ftell));
        trace.push(stream_call!(native, stream, fgetc) as i64);
        trace.push(stream_call!(native, stream, ungetc, b'!' as i32) as i64);
        let mut line = [0_u8; 8];
        let result = stream_call!(
            native,
            stream,
            fgets,
            line.as_mut_ptr().cast(),
            line.len() as i32
        );
        assert!(!result.is_null());
        trace.extend(line.into_iter().map(i64::from));
        trace.push(stream_call!(native, stream, fseek, 0, libc::SEEK_CUR) as i64);
        trace.push(stream_call!(native, stream, ftell));
        assert_eq!(stream_call!(native, stream, fseek, 0, libc::SEEK_SET), 0);
        backing[0] = b'Q';
        trace.push(stream_call!(native, stream, fgetc) as i64);
        backing[1] = b'R';
        trace.push(stream_call!(native, stream, fflush) as i64);
        trace.push(stream_call!(native, stream, fgetc) as i64);
        assert_eq!(stream_call!(native, stream, fseek, 0, libc::SEEK_END), 0);
        trace.push(stream_call!(native, stream, fgetc) as i64);
        trace.push(i64::from(stream_call!(native, stream, feof) != 0));
        assert_eq!(stream_call!(native, stream, fseek, 0, libc::SEEK_SET), 0);
        trace.push(i64::from(stream_call!(native, stream, feof) != 0));
        if mode.as_bytes() == b"r+" {
            assert_eq!(stream_call!(native, stream, fseek, 2, libc::SEEK_SET), 0);
            trace.push(stream_call!(native, stream, fwrite, c"UV".as_ptr().cast(), 1, 2) as i64);
            trace.push(stream_call!(native, stream, fflush) as i64);
        }
        trace.push(stream_call!(native, stream, fclose) as i64);
    }
    (trace, backing.to_vec())
}

#[test]
fn fmemopen_scan_pushback_flush_eof_and_update_transitions_match_glibc() {
    for mode in ["r", "r+"] {
        for unbuffered in [false, true] {
            assert_eq!(
                caller_buffer_transition_trace(true, mode, unbuffered),
                caller_buffer_transition_trace(false, mode, unbuffered),
                "mode={mode} unbuffered={unbuffered}"
            );
        }
    }
}

fn caller_buffer_first_read(native: bool, mode: &str, operation: usize) -> (Vec<u8>, i64, Vec<u8>) {
    let mode = CString::new(mode).unwrap();
    let mut backing = *b"12\nold\n!";
    let mut output = [0u8; 16];
    unsafe {
        let stream = if native {
            fl::fmemopen(backing.as_mut_ptr().cast(), backing.len(), mode.as_ptr())
        } else {
            fmemopen(backing.as_mut_ptr().cast(), backing.len(), mode.as_ptr()).cast()
        };
        assert!(!stream.is_null(), "fmemopen must open the real backing");
        backing[..7].copy_from_slice(b"42\nnew\n");
        let result = match operation {
            0 => vec![stream_call!(native, stream, fgetc) as u8],
            1 => {
                let n = if native {
                    fl::fread(output.as_mut_ptr().cast(), 1, 7, stream)
                } else {
                    fread(output.as_mut_ptr().cast(), 1, 7, stream.cast())
                };
                output[..n].to_vec()
            }
            2 => {
                let ptr = if native {
                    fl::fgets(output.as_mut_ptr().cast(), output.len() as i32, stream)
                } else {
                    fgets(
                        output.as_mut_ptr().cast(),
                        output.len() as i32,
                        stream.cast(),
                    )
                };
                assert!(!ptr.is_null(), "line read must succeed");
                std::ffi::CStr::from_ptr(output.as_ptr().cast())
                    .to_bytes()
                    .to_vec()
            }
            _ => {
                let mut number = 0_i32;
                let n = if native {
                    fl::fscanf(stream, c"%d".as_ptr(), &mut number as *mut i32)
                } else {
                    fscanf(stream.cast(), c"%d".as_ptr(), &mut number as *mut i32)
                };
                assert_eq!(n, 1, "numeric read must consume the real input");
                number.to_ne_bytes().to_vec()
            }
        };
        let position = stream_call!(native, stream, ftell);
        assert_eq!(stream_call!(native, stream, fclose), 0);
        (result, position, backing.to_vec())
    }
}

#[test]
fn fmemopen_first_read_observes_caller_edits_for_all_reader_paths() {
    let mut differences = Vec::new();
    for mode in ["r", "r+"] {
        for operation in 0..4 {
            let expected = caller_buffer_first_read(false, mode, operation);
            let actual = caller_buffer_first_read(true, mode, operation);
            if actual != expected {
                differences.push((mode, operation, expected, actual));
            }
        }
    }
    assert!(
        differences.is_empty(),
        "caller-backed reads differ: {differences:?}"
    );
}

fn caller_buffer_read_trace(native: bool, mode: &str, unbuffered: bool) -> (Vec<u8>, Vec<u8>) {
    let mode = CString::new(mode).unwrap();
    let mut backing = *b"abcde";
    unsafe {
        let stream = if native {
            fl::fmemopen(backing.as_mut_ptr().cast(), backing.len(), mode.as_ptr())
        } else {
            fmemopen(backing.as_mut_ptr().cast(), backing.len(), mode.as_ptr()).cast()
        };
        assert!(!stream.is_null());
        let buffering = if unbuffered {
            libc::_IONBF
        } else {
            libc::_IOFBF
        };
        assert_eq!(
            stream_call!(native, stream, setvbuf, std::ptr::null_mut(), buffering, 0),
            0
        );
        backing[0] = b'X';
        let first = stream_call!(native, stream, fgetc);
        backing[1] = b'Y';
        let second = stream_call!(native, stream, fgetc);
        assert_eq!(stream_call!(native, stream, fseek, 2, libc::SEEK_SET), 0);
        backing[2] = b'Z';
        let third = stream_call!(native, stream, fgetc);
        assert_eq!(stream_call!(native, stream, fseek, 0, libc::SEEK_SET), 0);
        backing[0] = b'Q';
        let mut bulk = [0u8; 2];
        let n = stream_call!(native, stream, fread, bulk.as_mut_ptr().cast(), 1, 2);
        assert_eq!(n, 2);
        assert_eq!(stream_call!(native, stream, fclose), 0);
        (
            vec![first as u8, second as u8, third as u8, bulk[0], bulk[1]],
            backing.to_vec(),
        )
    }
}

#[test]
fn fmemopen_buffering_and_repositioning_match_live_storage() {
    let mut differences = Vec::new();
    for mode in ["r", "r+"] {
        for unbuffered in [false, true] {
            let expected = caller_buffer_read_trace(false, mode, unbuffered);
            let actual = caller_buffer_read_trace(true, mode, unbuffered);
            if actual != expected {
                differences.push((mode, unbuffered, expected, actual));
            }
        }
    }
    assert!(
        differences.is_empty(),
        "buffer/position traces differ: {differences:?}"
    );
}

#[test]
fn fmemopen_custom_input_windows_refill_from_live_storage() {
    for window in [1, 3, 8, 16, 8192] {
        for buffering in [libc::_IOFBF, libc::_IOLBF] {
            let trace = |native: bool| unsafe {
                let mut backing = vec![b'A'; window + 2];
                let mut buffer = vec![0_i8; window];
                let stream = if native {
                    fl::fmemopen(backing.as_mut_ptr().cast(), backing.len(), c"r".as_ptr())
                } else {
                    fmemopen(backing.as_mut_ptr().cast(), backing.len(), c"r".as_ptr()).cast()
                };
                assert!(!stream.is_null());
                assert_eq!(
                    stream_call!(
                        native,
                        stream,
                        setvbuf,
                        buffer.as_mut_ptr(),
                        buffering,
                        window
                    ),
                    0
                );
                backing[0] = b'X';
                let first = stream_call!(native, stream, fgetc);
                backing[1..].fill(b'Y');
                let mut rest = vec![0_u8; window + 1];
                let read = stream_call!(
                    native,
                    stream,
                    fread,
                    rest.as_mut_ptr().cast(),
                    1,
                    rest.len()
                );
                assert_eq!(stream_call!(native, stream, fclose), 0);
                (first, read, rest)
            };
            assert_eq!(
                trace(true),
                trace(false),
                "window={window} buffering={buffering}"
            );
        }
    }
}

#[test]
fn fmemopen_global_flush_preserves_input_and_unbuffering_discards_it() {
    // `fflush(NULL)` flushes every open stream in the process. Sibling tests in
    // this binary (`fmemopen_write_nul_terminates_like_glibc` and
    // `fmemopen_write_overflow_deferred_to_flush_like_glibc`) deliberately stage
    // overflowing writes into small `fmemopen` buffers to assert `fflush == EOF`;
    // isolate `fflush(NULL)` in a clean child process so parallel scheduling
    // cannot observe their intentionally-failing staged writes.
    if std::env::var_os("FL_FMEMOPEN_ISOLATED_GLOBAL_FLUSH").is_none() {
        let status = std::process::Command::new(
            std::env::current_exe().expect("resolve current test binary"),
        )
        .args([
            "--exact",
            "fmemopen_global_flush_preserves_input_and_unbuffering_discards_it",
            "--nocapture",
        ])
        .env("FL_FMEMOPEN_ISOLATED_GLOBAL_FLUSH", "1")
        .status()
        .expect("spawn isolated global-flush child");
        assert!(
            status.success(),
            "isolated global-flush child failed: {status}"
        );
        return;
    }
    for mode in [c"r", c"r+"] {
        let mut expected = *b"abcde";
        let mut actual = expected;
        unsafe {
            let host = fmemopen(expected.as_mut_ptr().cast(), expected.len(), mode.as_ptr());
            let native = fl::fmemopen(actual.as_mut_ptr().cast(), actual.len(), mode.as_ptr());
            assert!(!host.is_null() && !native.is_null());
            assert_eq!(fl::fgetc(native), fgetc(host));
            expected[1] = b'Y';
            actual[1] = b'Y';
            assert_eq!(
                fl::fflush(std::ptr::null_mut()),
                fflush(std::ptr::null_mut())
            );
            assert_eq!(
                fl::fgetc(native),
                fgetc(host),
                "global flush keeps unread input"
            );
            expected[2] = b'Z';
            actual[2] = b'Z';
            assert_eq!(
                fl::setvbuf(native, std::ptr::null_mut(), libc::_IONBF, 0),
                setvbuf(host, std::ptr::null_mut(), libc::_IONBF, 0)
            );
            assert_eq!(
                fl::fgetc(native),
                fgetc(host),
                "unbuffering reads current storage"
            );
            assert_eq!(fl::fclose(native), fclose(host));
        }
        assert_eq!(actual, expected);
    }
}

#[test]
fn fmemopen_failed_seek_and_input_flush_preserve_status() {
    for mode in [c"r", c"r+"] {
        let trace = |native: bool| unsafe {
            let mut data = *b"abc";
            let stream = if native {
                fl::fmemopen(data.as_mut_ptr().cast(), data.len(), mode.as_ptr())
            } else {
                fmemopen(data.as_mut_ptr().cast(), data.len(), mode.as_ptr()).cast()
            };
            assert!(!stream.is_null());
            let mut trace = Vec::new();
            for _ in 0..4 {
                trace.push(stream_call!(native, stream, fgetc) as i64);
            }
            trace.push(i64::from(stream_call!(native, stream, feof) != 0));
            trace.push(stream_call!(native, stream, fflush) as i64);
            trace.push(i64::from(stream_call!(native, stream, feof) != 0));
            for (offset, whence) in [(-1, libc::SEEK_SET), (4, libc::SEEK_SET), (0, 99)] {
                trace.push(stream_call!(native, stream, fseek, offset, whence) as i64);
                trace.push(stream_call!(native, stream, ftell));
                trace.push(i64::from(stream_call!(native, stream, feof) != 0));
                trace.push(i64::from(stream_call!(native, stream, ferror) != 0));
            }
            trace.push(stream_call!(native, stream, fclose) as i64);
            trace
        };
        assert_eq!(trace(true), trace(false), "mode={mode:?}");
    }
}

#[test]
fn fmemopen_repeated_flush_and_close_preserve_edits_after_output_flush() {
    for mode in ["w+", "r+"] {
        let mode = CString::new(mode).unwrap();
        let mut expected = [b'Z'; 16];
        let mut actual = expected;
        unsafe {
            let host = fmemopen(expected.as_mut_ptr().cast(), expected.len(), mode.as_ptr());
            let native = fl::fmemopen(actual.as_mut_ptr().cast(), actual.len(), mode.as_ptr());
            assert!(!host.is_null() && !native.is_null());
            assert_eq!(fwrite(c"W".as_ptr().cast(), 1, 1, host), 1);
            assert_eq!(fl::fwrite(c"W".as_ptr().cast(), 1, 1, native), 1);
            assert_eq!(fl::fflush(native), fflush(host));
            expected[3] = b'Q';
            actual[3] = b'Q';
            assert_eq!(fl::fflush(native), fflush(host));
            assert_eq!(fl::fclose(native), fclose(host));
        }
        assert_eq!(
            actual, expected,
            "already-flushed output must not overwrite caller edits"
        );
    }
}

#[test]
fn fmemopen_large_successful_write_keeps_buffered_tail() {
    let payload = vec![b'A'; 9000];
    let mut expected = vec![b'Z'; 10000];
    let mut actual = expected.clone();
    unsafe {
        let host = fmemopen(expected.as_mut_ptr().cast(), expected.len(), c"w+".as_ptr());
        let native = fl::fmemopen(actual.as_mut_ptr().cast(), actual.len(), c"w+".as_ptr());
        assert!(!host.is_null() && !native.is_null());
        assert_eq!(
            fl::fwrite(payload.as_ptr().cast(), 1, payload.len(), native),
            fwrite(payload.as_ptr().cast(), 1, payload.len(), host)
        );
        assert_eq!(fl::ftell(native), ftell(host));
        assert_eq!(fl::fflush(native), fflush(host));
        assert_eq!(
            actual, expected,
            "full blocks and their buffered tail must land once"
        );
        assert_eq!(fl::fclose(native), fclose(host));
    }
    assert_eq!(actual, expected);
}

#[test]
fn fmemopen_append_position_after_seek_and_owned_buffer_round_trip() {
    let mut expected = *b"ab\0ZZZZZ";
    let mut actual = expected;
    unsafe {
        let host = fmemopen(expected.as_mut_ptr().cast(), expected.len(), c"a+".as_ptr());
        let native = fl::fmemopen(actual.as_mut_ptr().cast(), actual.len(), c"a+".as_ptr());
        assert!(!host.is_null() && !native.is_null());
        assert_eq!(
            fl::fseek(native, 0, libc::SEEK_SET),
            fseek(host, 0, libc::SEEK_SET)
        );
        assert_eq!(
            fl::fwrite(c"CD".as_ptr().cast(), 1, 2, native),
            fwrite(c"CD".as_ptr().cast(), 1, 2, host)
        );
        assert_eq!(fl::ftell(native), ftell(host));
        assert_eq!(fl::fflush(native), fflush(host));
        assert_eq!(fl::ftell(native), ftell(host));
        assert_eq!(fl::fclose(native), fclose(host));
        assert_eq!(actual, expected);

        let host = fmemopen(std::ptr::null_mut(), 32, c"w+".as_ptr());
        let native = fl::fmemopen(std::ptr::null_mut(), 32, c"w+".as_ptr());
        assert!(!host.is_null() && !native.is_null());
        assert_eq!(
            fl::fwrite(c"owned".as_ptr().cast(), 1, 5, native),
            fwrite(c"owned".as_ptr().cast(), 1, 5, host)
        );
        assert_eq!(
            fl::fseek(native, 0, libc::SEEK_SET),
            fseek(host, 0, libc::SEEK_SET)
        );
        let mut host_bytes = [0_u8; 8];
        let mut native_bytes = [0_u8; 8];
        assert_eq!(
            fl::fread(native_bytes.as_mut_ptr().cast(), 1, 8, native),
            fread(host_bytes.as_mut_ptr().cast(), 1, 8, host)
        );
        assert_eq!(native_bytes, host_bytes);
        assert_eq!(fl::fclose(native), fclose(host));
    }
}

#[test]
fn fmemopen_size0_read_is_valid_eof() {
    let mode = CString::new("r").unwrap();
    let mut empty = [0u8; 1]; // backing not actually read for size 0
    // glibc
    let g = unsafe { fmemopen(empty.as_mut_ptr() as *mut libc::c_void, 0, mode.as_ptr()) };
    // fl
    let f = unsafe {
        fl::fmemopen(
            empty.as_mut_ptr() as *mut libc::c_void,
            0,
            mode.as_ptr() as *const libc::c_char,
        )
    };
    assert!(!g.is_null(), "glibc fmemopen(size=0) should succeed");
    assert!(
        !f.is_null(),
        "fl fmemopen(size=0) must match glibc and return a valid (empty) stream, not NULL"
    );
    let gc = unsafe { fgetc(g) };
    let fc = unsafe { fl::fgetc(f) };
    assert_eq!(gc, libc::EOF, "glibc size-0 read should be EOF");
    assert_eq!(fc, libc::EOF, "fl size-0 read should be EOF, got {fc}");
    unsafe {
        fclose(g);
        fl::fclose(f);
    }
}

#[test]
fn fmemopen_write_nul_terminates_like_glibc() {
    let mode = CString::new("w").unwrap();
    for payload in ["abc", "", "exactlyfits!"] {
        for cap in [0usize, 1, 4, 16] {
            if cap == 0 {
                continue; // covered separately; write to 0-size is its own quirk
            }
            let cs = CString::new(payload).unwrap();

            let mut gbuf = vec![b'Z'; cap];
            let g = unsafe { fmemopen(gbuf.as_mut_ptr() as *mut libc::c_void, cap, mode.as_ptr()) };
            let gret = unsafe { fputs(cs.as_ptr(), g) };
            unsafe { fflush(g) };

            let mut fbuf = vec![b'Z'; cap];
            let f = unsafe {
                fl::fmemopen(
                    fbuf.as_mut_ptr() as *mut libc::c_void,
                    cap,
                    mode.as_ptr() as *const libc::c_char,
                )
            };
            let fret = unsafe { fl::fputs(cs.as_ptr(), f) };
            unsafe { fl::fflush(f) };

            unsafe {
                fclose(g);
                fl::fclose(f);
            }

            assert_eq!(
                fbuf, gbuf,
                "fmemopen write buffer mismatch for payload={payload:?} cap={cap}: \
                 fl={fbuf:02x?} glibc={gbuf:02x?} (fputs fl={fret} glibc={gret})"
            );
        }
    }
}

#[test]
fn fmemopen_write_overflow_deferred_to_flush_like_glibc() {
    let mode_w = CString::new("w").unwrap();
    let mode_wplus = CString::new("w+").unwrap();
    let payload = CString::new("0123456789").unwrap();

    // 1. fputs("0123456789") into cap=8: succeeds at write time (ftell=10, ferror=0),
    // fails at fflush (returns EOF, ftell=8, ferror!=0), second fflush and fclose return 0.
    unsafe {
        let mut gbuf = [b'Z'; 8];
        let mut fbuf = [b'Z'; 8];
        let g = fmemopen(gbuf.as_mut_ptr().cast(), gbuf.len(), mode_w.as_ptr());
        let f = fl::fmemopen(fbuf.as_mut_ptr().cast(), fbuf.len(), mode_w.as_ptr());

        let gw = fputs(payload.as_ptr(), g);
        let fw = fl::fputs(payload.as_ptr(), f);
        assert!(
            gw >= 0 && fw >= 0,
            "fputs must succeed before flush: gw={gw} fw={fw}"
        );
        assert_eq!(
            fl::ftell(f),
            ftell(g),
            "ftell before flush must match glibc (10)"
        );
        assert_eq!(
            fl::ferror(f) != 0,
            ferror(g) != 0,
            "ferror before flush must be 0"
        );

        assert_eq!(
            fl::fflush(f),
            fflush(g),
            "first fflush after overflow must return EOF"
        );
        assert_eq!(
            fl::ftell(f),
            ftell(g),
            "ftell after failed fflush must clamp to cap (8)"
        );
        assert_eq!(
            fl::ferror(f) != 0,
            ferror(g) != 0,
            "ferror after failed fflush must be set"
        );
        assert_eq!(fl::fflush(f), fflush(g), "second fflush must succeed");
        assert_eq!(fl::fclose(f), fclose(g), "fclose after fflush must succeed");
        assert_eq!(fbuf, gbuf);
    }

    // 2. fwrite("0123456789", 1, 10) into cap=8: returns 10, fails at fflush.
    unsafe {
        let mut gbuf = [b'Z'; 8];
        let mut fbuf = [b'Z'; 8];
        let g = fmemopen(gbuf.as_mut_ptr().cast(), gbuf.len(), mode_w.as_ptr());
        let f = fl::fmemopen(fbuf.as_mut_ptr().cast(), fbuf.len(), mode_w.as_ptr());

        let gw = fwrite(payload.as_ptr().cast(), 1, 10, g);
        let fw = fl::fwrite(payload.as_ptr().cast(), 1, 10, f);
        assert_eq!(fw, gw, "fwrite count before flush must match glibc (10)");
        assert_eq!(fl::ftell(f), ftell(g));
        assert_eq!(fl::fflush(f), fflush(g));
        assert_eq!(fl::ftell(f), ftell(g));
        assert_eq!(fl::fclose(f), fclose(g));
        assert_eq!(fbuf, gbuf);
    }

    // 3. fclose without prior fflush reports the deferred overflow error (-1).
    unsafe {
        let mut gbuf = [b'Z'; 8];
        let mut fbuf = [b'Z'; 8];
        let g = fmemopen(gbuf.as_mut_ptr().cast(), gbuf.len(), mode_w.as_ptr());
        let f = fl::fmemopen(fbuf.as_mut_ptr().cast(), fbuf.len(), mode_w.as_ptr());

        assert!(fputs(payload.as_ptr(), g) >= 0);
        assert!(fl::fputs(payload.as_ptr(), f) >= 0);
        assert_eq!(
            fl::fclose(f),
            fclose(g),
            "fclose on unflushed overflow must return EOF"
        );
        assert_eq!(fbuf, gbuf);
    }

    // 4. fseek after overflow fails on the first call (flushing the overflow) and succeeds on the second.
    unsafe {
        let mut gbuf = [b'Z'; 8];
        let mut fbuf = [b'Z'; 8];
        let g = fmemopen(gbuf.as_mut_ptr().cast(), gbuf.len(), mode_wplus.as_ptr());
        let f = fl::fmemopen(fbuf.as_mut_ptr().cast(), fbuf.len(), mode_wplus.as_ptr());

        assert!(fputs(payload.as_ptr(), g) >= 0);
        assert!(fl::fputs(payload.as_ptr(), f) >= 0);
        assert_eq!(fl::fseek(f, 2, libc::SEEK_SET), fseek(g, 2, libc::SEEK_SET));
        assert_eq!(fl::ftell(f), ftell(g));
        assert_eq!(fl::fseek(f, 2, libc::SEEK_SET), fseek(g, 2, libc::SEEK_SET));
        assert_eq!(fl::ftell(f), ftell(g));
        assert_eq!(fl::fclose(f), fclose(g));
        assert_eq!(fbuf, gbuf);
    }

    // 5. Write exceeding BUFSIZ (9000 bytes) fails immediately at the write call.
    unsafe {
        let big = CString::new(vec![b'A'; 9000]).unwrap();
        let mut gbuf = [b'Z'; 8];
        let mut fbuf = [b'Z'; 8];
        let g = fmemopen(gbuf.as_mut_ptr().cast(), gbuf.len(), mode_w.as_ptr());
        let f = fl::fmemopen(fbuf.as_mut_ptr().cast(), fbuf.len(), mode_w.as_ptr());

        assert_eq!(fl::fputs(big.as_ptr(), f), fputs(big.as_ptr(), g));
        assert_eq!(fl::ftell(f), ftell(g));
        assert_eq!(fl::ferror(f) != 0, ferror(g) != 0);
        assert_eq!(fl::fflush(f), fflush(g));
        assert_eq!(fl::fclose(f), fclose(g));
        assert_eq!(fbuf, gbuf);
    }
}

#[test]
fn fmemopen_repeated_lifecycle_and_multithreaded_flockfile_reuse_match_glibc() {
    // 1. Repeated lifecycle reuse on one thread: verifies STATIC_SLOT_LOCKS,
    // FGETC_MEM_PTR_CACHE pre-population, set_eof(false) fast guard, and
    // FIXED_MEM_INPUT_POOL buffer recycling never leak stale bytes or EOF flags.
    for cycle in 0..32u8 {
        let mut g_data = vec![0u8; 4096];
        for (i, b) in g_data.iter_mut().enumerate() {
            *b = cycle.wrapping_mul(37).wrapping_add((i % 251) as u8);
        }
        let mut fl_data = g_data.clone();
        unsafe {
            let g_fp = fmemopen(g_data.as_mut_ptr().cast(), g_data.len(), c"r".as_ptr());
            let fl_fp = fl::fmemopen(fl_data.as_mut_ptr().cast(), fl_data.len(), c"r".as_ptr());
            assert!(!g_fp.is_null() && !fl_fp.is_null());

            let mut g_chunk = [0u8; 64];
            let mut fl_chunk = [0u8; 64];
            for step in 0..64 {
                let gn = fread(g_chunk.as_mut_ptr().cast(), 1, 64, g_fp);
                let fn_ = fl::fread(fl_chunk.as_mut_ptr().cast(), 1, 64, fl_fp);
                assert_eq!((fn_, fl_chunk), (gn, g_chunk), "cycle={cycle} step={step}");
                assert_eq!(fl::feof(fl_fp) != 0, feof(g_fp) != 0);
            }
            // Exhausted read sets EOF; seek(0) clears EOF on both handle _flags and cursor.
            assert_eq!(fl::fread(fl_chunk.as_mut_ptr().cast(), 1, 64, fl_fp), 0);
            assert_eq!(fread(g_chunk.as_mut_ptr().cast(), 1, 64, g_fp), 0);
            assert_eq!(fl::feof(fl_fp) != 0, feof(g_fp) != 0);
            assert_eq!(
                fl::fseek(fl_fp, 0, libc::SEEK_SET),
                fseek(g_fp, 0, libc::SEEK_SET)
            );
            assert_eq!(fl::feof(fl_fp) != 0, feof(g_fp) != 0);
            assert_eq!(fl::fclose(fl_fp), fclose(g_fp));
        }
    }

    // 2. Concurrent multi-threaded open/flockfile/fread/fclose across shared static slots.
    std::thread::scope(|s| {
        for tid in 0..4u8 {
            s.spawn(move || {
                for iter in 0..24u8 {
                    let mut data = vec![0u8; 1024];
                    for (i, b) in data.iter_mut().enumerate() {
                        *b = tid
                            .wrapping_mul(53)
                            .wrapping_add(iter.wrapping_mul(11))
                            .wrapping_add((i & 0xff) as u8);
                    }
                    let expected = data.clone();
                    let mut out = vec![0u8; 1024];
                    unsafe {
                        let fp = fl::fmemopen(data.as_mut_ptr().cast(), data.len(), c"r".as_ptr());
                        assert!(!fp.is_null());
                        fl::flockfile(fp);
                        assert_eq!(fl::ftrylockfile(fp), 0);
                        let mut pos = 0usize;
                        while pos < out.len() {
                            let n = fl::fread(out[pos..].as_mut_ptr().cast(), 1, 64, fp);
                            assert_eq!(n, 64);
                            pos += n;
                        }
                        fl::funlockfile(fp);
                        fl::funlockfile(fp);
                        assert_eq!(fl::fclose(fp), 0);
                    }
                    assert_eq!(out, expected);
                }
            });
        }
    });

    // 3. Unmatched explicit `flockfile`/`ftrylockfile` across `fclose` must reset
    // the reusable static-slot lock (`_IO_lock_fini` semantics) so a subsequent
    // thread reusing that slot never deadlocks on stale owner_tid/recursion_depth.
    let reused_slot_addr = std::thread::spawn(|| unsafe {
        let mut buf = [b'Q'; 64];
        let fp = fl::fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"r".as_ptr());
        assert!(!fp.is_null());
        fl::flockfile(fp);
        assert_eq!(fl::ftrylockfile(fp), 0);
        // Intentionally unlock only once before fclose (leaving depth == 1).
        fl::funlockfile(fp);
        assert_eq!(fl::fclose(fp), 0);
        fp as usize
    })
    .join()
    .expect("first thread panicked");

    std::thread::spawn(move || unsafe {
        let mut buf = [b'R'; 64];
        let fp = fl::fmemopen(buf.as_mut_ptr().cast(), buf.len(), c"r".as_ptr());
        assert!(!fp.is_null());
        assert_eq!(fp as usize, reused_slot_addr, "expected static slot reuse");
        assert_eq!(fl::ftrylockfile(fp), 0, "reused slot lock must be unowned");
        let mut out = [0u8; 64];
        assert_eq!(fl::fread(out.as_mut_ptr().cast(), 1, 64, fp), 64);
        assert_eq!(out, buf);
        fl::funlockfile(fp);
        assert_eq!(fl::fclose(fp), 0);
    })
    .join()
    .expect("second thread panicked");
}

#[test]
fn fmemopen_readonly_object_pool_reuse_and_pushback_seek_freopen_parity() {
    unsafe {
        // 1. Repeated read-only `fmemopen -> fread -> fclose` across varying sizes
        // and NULL-owned buffers must never leak stale buffered bytes or EOF flags.
        for (len, seed) in [(4096usize, 11u8), (37, 73), (0, 0), (512, 199), (13, 41)] {
            let mut host_buf: Vec<u8> =
                (0..len).map(|i| seed.wrapping_add((i * 7) as u8)).collect();
            let mut fl_buf = host_buf.clone();
            let h = fmemopen(host_buf.as_mut_ptr().cast(), len, c"r".as_ptr());
            let f = fl::fmemopen(fl_buf.as_mut_ptr().cast(), len, c"r".as_ptr());
            assert!(!h.is_null() && !f.is_null());

            let mut h_out = vec![0xa5u8; len + 8];
            let mut f_out = vec![0xa5u8; len + 8];
            let hn = fread(h_out.as_mut_ptr().cast(), 1, h_out.len(), h);
            let fn_ = fl::fread(f_out.as_mut_ptr().cast(), 1, f_out.len(), f);
            assert_eq!(fn_, hn);
            assert_eq!(f_out, h_out);
            assert_eq!(fl::feof(f) != 0, feof(h) != 0);
            assert_eq!(fl::fclose(f), fclose(h));
        }

        // 2. Owned `fmemopen(NULL, 64, "r")` reads all zeros and recycles cleanly.
        let f_owned = fl::fmemopen(std::ptr::null_mut(), 64, c"r".as_ptr());
        assert!(!f_owned.is_null());
        let mut z = [0xffu8; 64];
        assert_eq!(fl::fread(z.as_mut_ptr().cast(), 1, 64, f_owned), 64);
        assert_eq!(z, [0u8; 64]);
        assert_eq!(fl::fclose(f_owned), 0);

        // 3. `ungetc` and `fseek` after fast `fread` must retire `TLS_FAST_MEM_READ`
        // and match glibc byte-for-byte.
        let mut g_src = *b"abcdefghij";
        let mut f_src = g_src;
        let g = fmemopen(g_src.as_mut_ptr().cast(), g_src.len(), c"r".as_ptr());
        let f = fl::fmemopen(f_src.as_mut_ptr().cast(), f_src.len(), c"r".as_ptr());
        let mut g_head = [0u8; 4];
        let mut f_head = [0u8; 4];
        assert_eq!(fread(g_head.as_mut_ptr().cast(), 1, 4, g), 4);
        assert_eq!(fl::fread(f_head.as_mut_ptr().cast(), 1, 4, f), 4);
        assert_eq!(f_head, g_head);
        assert_eq!(
            fl::ungetc(b'Z' as libc::c_int, f),
            ungetc(b'Z' as libc::c_int, g)
        );
        let mut g_mid = [0u8; 3];
        let mut f_mid = [0u8; 3];
        assert_eq!(fread(g_mid.as_mut_ptr().cast(), 1, 3, g), 3);
        assert_eq!(fl::fread(f_mid.as_mut_ptr().cast(), 1, 3, f), 3);
        assert_eq!(f_mid, g_mid);
        assert_eq!(fl::fseek(f, 2, libc::SEEK_SET), fseek(g, 2, libc::SEEK_SET));
        let mut g_tail = [0u8; 8];
        let mut f_tail = [0u8; 8];
        assert_eq!(
            fl::fread(f_tail.as_mut_ptr().cast(), 1, 8, f),
            fread(g_tail.as_mut_ptr().cast(), 1, 8, g)
        );
        assert_eq!(f_tail, g_tail);
        assert_eq!(fl::fclose(f), fclose(g));
    }
}

#[test]
fn fmemopen_preserves_single_threaded_fast_path_until_second_thread_enters() {
    if std::env::var_os("FL_FMEMOPEN_ISOLATED_ST_GUARD").is_none() {
        let output = std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .env("FL_FMEMOPEN_ISOLATED_ST_GUARD", "1")
            .args([
                "--exact",
                "fmemopen_preserves_single_threaded_fast_path_until_second_thread_enters",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .expect("spawn isolated single-threaded guard test");
        assert!(
            output.status.success(),
            "isolated ST guard test failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    use std::sync::atomic::Ordering;
    assert_eq!(
        frankenlibc_abi::glibc_internal_abi::__libc_single_threaded.load(Ordering::Acquire),
        1,
        "fresh single-threaded process must start with __libc_single_threaded == 1"
    );

    let mut data = [0u8; 4096];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    for _ in 0..8 {
        unsafe {
            let fp = fl::fmemopen(data.as_mut_ptr().cast(), data.len(), c"r".as_ptr());
            assert!(!fp.is_null());
            let mut chunk = [0u8; 64];
            for step in 0..64 {
                assert_eq!(fl::fread(chunk.as_mut_ptr().cast(), 1, 64, fp), 64);
                assert_eq!(chunk[0], ((step * 64) % 251) as u8);
            }
            assert_eq!(fl::fclose(fp), 0);
        }
    }
    assert_eq!(
        frankenlibc_abi::glibc_internal_abi::__libc_single_threaded.load(Ordering::Acquire),
        1,
        "repeated single-threaded fmemopen+fread+fclose must preserve __libc_single_threaded == 1"
    );

    let st_fp_raw = unsafe { fl::fmemopen(data.as_mut_ptr().cast(), data.len(), c"r".as_ptr()) };
    assert!(!st_fp_raw.is_null());
    unsafe {
        let mut chunk = [0u8; 64];
        assert_eq!(fl::fread(chunk.as_mut_ptr().cast(), 1, 64, st_fp_raw), 64);
    }
    let st_fp_addr = st_fp_raw as usize;

    std::thread::spawn(move || unsafe {
        assert_eq!(fl::fclose(st_fp_addr as *mut libc::c_void), 0);
    })
    .join()
    .expect("join second thread closing ST-opened fmemopen stream");

    assert_eq!(
        frankenlibc_abi::glibc_internal_abi::__libc_single_threaded.load(Ordering::Acquire),
        0,
        "second host thread entering fclose must clear __libc_single_threaded to 0"
    );
}

#[test]
fn fmemopen_fast_close_flushes_published_write_window() {
    let mut fl_buf = [0xffu8; 32];
    let mut lc_buf = [0xffu8; 32];
    unsafe {
        let fl_fp = fl::fmemopen(fl_buf.as_mut_ptr().cast(), fl_buf.len(), c"w".as_ptr());
        let lc_fp = fmemopen(lc_buf.as_mut_ptr().cast(), lc_buf.len(), c"w".as_ptr());
        assert!(!fl_fp.is_null() && !lc_fp.is_null());

        assert_eq!(fl::fputc(b'A' as i32, fl_fp), b'A' as i32);
        assert_eq!(libc::fputc(b'A' as i32, lc_fp), b'A' as i32);
        assert_eq!(fl::fflush(fl_fp), 0);
        assert_eq!(fflush(lc_fp), 0);

        // Second fputc writes into the published _IO_write_ptr/_IO_write_end window;
        // fclose must absorb and flush that window + NUL terminator before retiring.
        assert_eq!(fl::fputc(b'B' as i32, fl_fp), b'B' as i32);
        assert_eq!(libc::fputc(b'B' as i32, lc_fp), b'B' as i32);
        assert_eq!(fl::fclose(fl_fp), 0);
        assert_eq!(fclose(lc_fp), 0);
    }
    assert_eq!(&fl_buf[..3], b"AB\0");
    assert_eq!(&fl_buf[..3], &lc_buf[..3]);
}

#[test]
fn fmemopen_null_backing_huge_size_returns_enomem_without_leaking_slots() {
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
        let huge = fl::fmemopen(std::ptr::null_mut(), 1usize << 61, c"r".as_ptr());
        assert!(
            huge.is_null(),
            "oversized NULL-backed fmemopen must fail cleanly"
        );
        assert_eq!(
            *frankenlibc_abi::errno_abi::__errno_location(),
            libc::ENOMEM
        );

        // Verify static slots were not leaked on ENOMEM failure.
        for _ in 0..300 {
            let mut small = *b"ok";
            let fp = fl::fmemopen(small.as_mut_ptr().cast(), small.len(), c"r".as_ptr());
            assert!(!fp.is_null());
            assert_eq!(fl::fclose(fp), 0);
        }
    }
}

#[test]
fn freopen_on_fopencookie_clears_cookie_metadata_and_failed_freopen_reclaims_slot() {
    unsafe extern "C-unwind" fn cookie_read(
        _cookie: *mut libc::c_void,
        buf: *mut libc::c_char,
        size: usize,
    ) -> isize {
        if size == 0 {
            return 0;
        }
        unsafe { *buf = b'C' as libc::c_char };
        1
    }

    let tmp_path = std::env::temp_dir().join(format!(
        "fl_freopen_cookie_{}_{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&tmp_path, b"FILE").expect("write temp file");
    let c_path = CString::new(tmp_path.to_str().unwrap()).unwrap();

    unsafe {
        let funcs = fl::CookieIoFuncs {
            read: Some(cookie_read),
            write: None,
            seek: None,
            close: None,
        };
        let fp = fl::fopencookie(std::ptr::null_mut(), c"r".as_ptr(), funcs);
        assert!(!fp.is_null());
        assert_eq!(fl::fgetc(fp), b'C' as i32);

        let reopened = fl::freopen(c_path.as_ptr(), c"r".as_ptr(), fp);
        assert_eq!(reopened, fp, "freopen on cookie stream should reuse handle");
        let mut out = [0u8; 4];
        assert_eq!(fl::fread(out.as_mut_ptr().cast(), 1, 4, reopened), 4);
        assert_eq!(
            &out, b"FILE",
            "reopened fd stream must not read stale cookie"
        );

        let bad_path = c"/definitely/nonexistent/frankenlibc_freopen_missing_file";
        let failed = fl::freopen(bad_path.as_ptr(), c"r".as_ptr(), reopened);
        assert!(failed.is_null());
    }
    let _ = std::fs::remove_file(&tmp_path);
}
