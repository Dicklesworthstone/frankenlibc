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
    fn fflush(stream: *mut libc::FILE) -> libc::c_int;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
    fn fgetc(stream: *mut libc::FILE) -> libc::c_int;
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
    let fc = unsafe { fl::fgetc(f as *mut libc::c_void) };
    assert_eq!(gc, libc::EOF, "glibc size-0 read should be EOF");
    assert_eq!(fc, libc::EOF, "fl size-0 read should be EOF, got {fc}");
    unsafe {
        fclose(g);
        fl::fclose(f as *mut libc::c_void);
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
            let fret = unsafe { fl::fputs(cs.as_ptr(), f as *mut libc::c_void) };
            unsafe { fl::fflush(f as *mut libc::c_void) };

            unsafe {
                fclose(g);
                fl::fclose(f as *mut libc::c_void);
            }

            assert_eq!(
                fbuf, gbuf,
                "fmemopen write buffer mismatch for payload={payload:?} cap={cap}: \
                 fl={fbuf:02x?} glibc={gbuf:02x?} (fputs fl={fret} glibc={gret})"
            );
        }
    }
}
