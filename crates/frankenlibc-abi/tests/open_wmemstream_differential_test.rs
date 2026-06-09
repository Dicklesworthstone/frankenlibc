#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc open_wmemstream oracle

//! Differential test for `open_wmemstream` vs host glibc, mirroring the narrow
//! `open_memstream` test. ASCII-only content is used so fl's byte-based `fseek`
//! offset coincides with glibc's wide-character position (1 byte == 1 wchar),
//! isolating the `*sizeloc` semantics from the separate byte-vs-wchar `fseek`
//! question. Validates that `*sizeloc` is the SMALLER of the content length and
//! the current position (both in wide chars), so a backward seek + write shrinks
//! the reported size while the tail wchars + NUL terminator survive.

use frankenlibc_abi::wchar_abi as fl;
use frankenlibc_abi::stdio_abi as flio;

unsafe extern "C" {
    fn open_wmemstream(bufp: *mut *mut libc::wchar_t, sizep: *mut usize) -> *mut libc::FILE;
    fn fputws(ws: *const libc::wchar_t, stream: *mut libc::FILE) -> libc::c_int;
    fn fputwc(wc: libc::wchar_t, stream: *mut libc::FILE) -> u32;
    fn fseek(stream: *mut libc::FILE, off: libc::c_long, whence: libc::c_int) -> libc::c_int;
    fn fflush(stream: *mut libc::FILE) -> libc::c_int;
    fn fclose(stream: *mut libc::FILE) -> libc::c_int;
}

fn wide(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

fn run(glibc: bool) -> Vec<(&'static str, usize, Vec<u32>)> {
    const VIEW: usize = 8;
    let mut ptr: *mut libc::wchar_t = std::ptr::null_mut();
    let mut sz: usize = 999;
    let mut log = Vec::new();

    let stream: *mut libc::FILE = if glibc {
        unsafe { open_wmemstream(&mut ptr, &mut sz) }
    } else {
        unsafe { fl::open_wmemstream(&mut ptr as *mut *mut libc::wchar_t as *mut *mut u32, &mut sz) as *mut libc::FILE }
    };
    assert!(!stream.is_null(), "open_wmemstream failed (glibc={glibc})");

    let puts = |s: &[libc::wchar_t]| {
        if glibc {
            unsafe { fputws(s.as_ptr(), stream) };
        } else {
            unsafe { fl::fputws(s.as_ptr(), stream as *mut libc::c_void) };
        }
    };
    let putc = |c: libc::wchar_t| {
        if glibc {
            unsafe { fputwc(c, stream) };
        } else {
            unsafe { fl::fputwc(c as u32, stream as *mut libc::c_void) };
        }
    };
    let seek = |off: i64| {
        if glibc {
            unsafe { fseek(stream, off as libc::c_long, libc::SEEK_SET) };
        } else {
            unsafe { flio::fseek(stream as *mut libc::c_void, off as libc::c_long, libc::SEEK_SET) };
        }
    };
    let flush = || {
        if glibc {
            unsafe { fflush(stream) };
        } else {
            unsafe { flio::fflush(stream as *mut libc::c_void) };
        }
    };
    // Read only `len` wchars (the buffer is allocated as content_extent+1, so
    // reading the fixed VIEW past a small buffer would be out of bounds).
    let snap = |p: *mut libc::wchar_t, len: usize| -> Vec<u32> {
        if p.is_null() {
            return Vec::new();
        }
        unsafe { std::slice::from_raw_parts(p as *const u32, len.min(VIEW)) }.to_vec()
    };

    let abc = wide("abc");
    puts(&abc[..3]);
    flush();
    log.push(("abc", sz, snap(ptr, 4))); // content extent 3 + NUL
    seek(6);
    putc('X' as i32 as libc::wchar_t);
    flush();
    log.push(("hole+X", sz, snap(ptr, 8))); // extent 7 + NUL
    seek(1);
    putc('Z' as i32 as libc::wchar_t);
    flush();
    log.push(("mid-Z", sz, snap(ptr, 8))); // extent 7 + NUL

    if glibc {
        unsafe { fclose(stream) };
    } else {
        unsafe { flio::fclose(stream as *mut libc::c_void) };
    }
    log.push(("closed", sz, Vec::new()));
    log
}

#[test]
fn open_wmemstream_sizeloc_matches_glibc() {
    let fl_log = run(false);
    let lc_log = run(true);
    assert_eq!(
        fl_log, lc_log,
        "open_wmemstream diverged from glibc:\n  fl   ={fl_log:x?}\n  glibc={lc_log:x?}"
    );
}
