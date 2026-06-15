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
    const VIEW: usize = 8;
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
    let snapshot = |ptr: *mut libc::c_char, _sz: usize| -> Vec<u8> {
        if ptr.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(ptr as *const u8, VIEW) }.to_vec()
    };

    flush();
    log.push(("empty", sz, snapshot(ptr, sz)));
    puts(b"abc\0");
    flush();
    log.push(("abc", sz, snapshot(ptr, sz)));
    seek(6);
    putc(b'X' as i32);
    flush();
    log.push(("hole+X", sz, snapshot(ptr, sz)));
    seek(1);
    putc(b'Z' as i32);
    flush();
    log.push(("mid-Z", sz, snapshot(ptr, sz)));

    if engine_glibc {
        unsafe { fclose(stream) };
    } else {
        unsafe { fl::fclose(stream as *mut libc::c_void) };
    }
    log.push(("closed", sz, Vec::new()));
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
