#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // live host-glibc __fpurge oracle + real FILE* streams

//! Differential gate for __fpurge (bd-k3hkhg). __fpurge discards a stream's
//! buffered (unflushed) output without writing it. fl's was a no-op, so
//! buffered bytes survived to the file on close. This gate writes to a
//! full-buffered stream, calls __fpurge, then closes — the purged bytes must
//! NOT reach the file (0 bytes), and __fpending must read 0 after the purge,
//! matching host glibc. No mocks.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type File = c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(p: *const c_char, m: *const c_char) -> *mut File;
        pub fn fclose(f: *mut File) -> c_int;
        pub fn setvbuf(f: *mut File, b: *mut c_char, mode: c_int, size: usize) -> c_int;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut File) -> usize;
        pub fn __fpurge(f: *mut File);
        pub fn __fpending(f: *mut File) -> usize;
        pub fn __fbufsize(f: *mut File) -> usize;
        pub fn __flbf(f: *mut File) -> c_int;
        pub fn __freadable(f: *mut File) -> c_int;
        pub fn __fwritable(f: *mut File) -> c_int;
        pub fn __freading(f: *mut File) -> c_int;
        pub fn __fwriting(f: *mut File) -> c_int;
        pub fn fgetc(f: *mut File) -> c_int;
        pub fn fputc(c: c_int, f: *mut File) -> c_int;
    }
}
use frankenlibc_abi::glibc_internal_abi as fle;
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn temp_path(tag: &str) -> (std::path::PathBuf, std::ffi::CString) {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-fpurge-{}-{}-{}", std::process::id(), tag, n));
    let c = std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap();
    (p, c)
}

/// Returns (pending_after_purge, file_len_after_close) for one implementation.
fn run_purge_glibc(buf: &mut [u8]) -> (usize, u64) {
    let (path, cpath) = temp_path("g");
    let s = unsafe { g::fopen(cpath.as_ptr(), c"w".as_ptr()) };
    assert!(!s.is_null());
    unsafe { g::setvbuf(s, buf.as_mut_ptr() as *mut c_char, libc::_IOFBF, buf.len()) };
    let data = b"buffered-output-bytes";
    unsafe { g::fwrite(data.as_ptr().cast(), 1, data.len(), s) };
    unsafe { g::__fpurge(s) };
    let pending = unsafe { g::__fpending(s) };
    unsafe { g::fclose(s) };
    let len = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX);
    let _ = std::fs::remove_file(&path);
    (pending, len)
}

fn run_purge_fl(buf: &mut [u8]) -> (usize, u64) {
    let (path, cpath) = temp_path("f");
    let s = unsafe {
        fl::fopen(
            cpath.as_ptr().cast::<c_char>(),
            c"w".as_ptr().cast::<c_char>(),
        )
    };
    assert!(!s.is_null());
    unsafe { fl::setvbuf(s, buf.as_mut_ptr() as *mut c_char, libc::_IOFBF, buf.len()) };
    let data = b"buffered-output-bytes";
    unsafe { fl::fwrite(data.as_ptr().cast(), 1, data.len(), s) };
    unsafe { fle::__fpurge(s) };
    let pending = unsafe { fle::__fpending(s) };
    unsafe { fl::fclose(s) };
    let len = std::fs::metadata(&path)
        .map(|m| m.len())
        .unwrap_or(u64::MAX);
    let _ = std::fs::remove_file(&path);
    (pending, len)
}

#[test]
fn fpurge_discards_buffered_output_like_glibc() {
    let mut gbuf = vec![0u8; 4096];
    let mut fbuf = vec![0u8; 4096];
    let (g_pending, g_len) = run_purge_glibc(&mut gbuf);
    let (f_pending, f_len) = run_purge_fl(&mut fbuf);

    assert_eq!(g_pending, 0, "glibc: __fpending after __fpurge must be 0");
    assert_eq!(
        f_pending, g_pending,
        "fl __fpending after purge {f_pending} != glibc {g_pending}"
    );
    assert_eq!(g_len, 0, "glibc: purged bytes must not reach the file");
    assert_eq!(
        f_len, g_len,
        "fl file length after purge+close {f_len} != glibc {g_len}"
    );
}

/// Exercise a mixed-provider process: glibc owns the actual buffer, while
/// the application's stdio_ext calls resolve to FrankenLibC.
#[test]
fn host_owned_stream_extensions_use_the_original_buffer() {
    let (path, cpath) = temp_path("mixed");
    let mut buf = [0u8; 1024];
    unsafe {
        let fp = g::fopen(cpath.as_ptr(), c"w".as_ptr());
        assert!(!fp.is_null());
        assert_eq!(
            g::setvbuf(fp, buf.as_mut_ptr().cast(), libc::_IOLBF, buf.len()),
            0
        );
        assert_eq!(g::fputc(65, fp), 65);
        assert_eq!(g::__fpending(fp), 1);
        assert_eq!(fle::__fpending(fp), g::__fpending(fp));
        assert_eq!(fle::__fbufsize(fp), g::__fbufsize(fp));
        assert_eq!(fle::__flbf(fp), g::__flbf(fp));
        assert_eq!(fle::__freadable(fp), g::__freadable(fp));
        assert_eq!(fle::__fwritable(fp), g::__fwritable(fp));
        assert_eq!(fle::__freading(fp), g::__freading(fp));
        assert_eq!(fle::__fwriting(fp), g::__fwriting(fp));
        fle::__fpurge(fp);
        assert_eq!(g::__fpending(fp), 0);
        assert_eq!(g::fclose(fp), 0);
    }
    assert!(std::fs::read(&path).unwrap().is_empty());

    std::fs::write(&path, b"abcdef").unwrap();
    unsafe {
        let fp = g::fopen(cpath.as_ptr(), c"r".as_ptr());
        assert!(!fp.is_null());
        assert_eq!(
            g::setvbuf(fp, buf.as_mut_ptr().cast(), libc::_IOFBF, buf.len()),
            0
        );
        assert_eq!(g::fgetc(fp), i32::from(b'a'));
        assert_eq!(fle::__fwritable(fp), g::__fwritable(fp));
        assert_eq!(fle::__freading(fp), g::__freading(fp));
        assert_eq!(fl::fpurge(fp), 0);
        assert_eq!(g::fgetc(fp), libc::EOF);
        assert_eq!(g::fclose(fp), 0);
    }
    std::fs::remove_file(path).unwrap();
}
