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
    fn fgets(ptr: *mut libc::c_char, size: libc::c_int, stream: *mut libc::FILE) -> *mut libc::c_char;
    fn fscanf(stream: *mut libc::FILE, format: *const libc::c_char, ...) -> libc::c_int;
    fn setvbuf(
        stream: *mut libc::FILE,
        buf: *mut libc::c_char,
        mode: libc::c_int,
        size: usize,
    ) -> libc::c_int;
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
            0 => vec![if native { fl::fgetc(stream) } else { fgetc(stream.cast()) } as u8],
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
                    fgets(output.as_mut_ptr().cast(), output.len() as i32, stream.cast())
                };
                assert!(!ptr.is_null(), "line read must succeed");
                std::ffi::CStr::from_ptr(output.as_ptr().cast()).to_bytes().to_vec()
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
        let position = if native { fl::ftell(stream) } else { ftell(stream.cast()) };
        assert_eq!(if native { fl::fclose(stream) } else { fclose(stream.cast()) }, 0);
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
    assert!(differences.is_empty(), "caller-backed reads differ: {differences:?}");
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
        let buffering = if unbuffered { libc::_IONBF } else { libc::_IOFBF };
        assert_eq!(if native {
            fl::setvbuf(stream, std::ptr::null_mut(), buffering, 0)
        } else {
            setvbuf(stream.cast(), std::ptr::null_mut(), buffering, 0)
        }, 0);
        backing[0] = b'X';
        let first = if native { fl::fgetc(stream) } else { fgetc(stream.cast()) };
        backing[1] = b'Y';
        let second = if native { fl::fgetc(stream) } else { fgetc(stream.cast()) };
        assert_eq!(if native { fl::fseek(stream, 2, libc::SEEK_SET) }
                   else { fseek(stream.cast(), 2, libc::SEEK_SET) }, 0);
        backing[2] = b'Z';
        let third = if native { fl::fgetc(stream) } else { fgetc(stream.cast()) };
        assert_eq!(if native { fl::fseek(stream, 0, libc::SEEK_SET) }
                   else { fseek(stream.cast(), 0, libc::SEEK_SET) }, 0);
        backing[0] = b'Q';
        let mut bulk = [0u8; 2];
        let n = if native { fl::fread(bulk.as_mut_ptr().cast(), 1, 2, stream) }
                else { fread(bulk.as_mut_ptr().cast(), 1, 2, stream.cast()) };
        assert_eq!(n, 2);
        assert_eq!(if native { fl::fclose(stream) } else { fclose(stream.cast()) }, 0);
        (vec![first as u8, second as u8, third as u8, bulk[0], bulk[1]], backing.to_vec())
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
    assert!(differences.is_empty(), "buffer/position traces differ: {differences:?}");
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
        assert_eq!(actual, expected, "already-flushed output must not overwrite caller edits");
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
