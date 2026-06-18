#![cfg(all(target_os = "linux", not(feature = "standalone")))]
#![allow(unsafe_code)] // live host-glibc stdio_ext.h oracle + real FILE* streams

//! Differential gate for the stdio_ext.h introspection family (bd-bap2cl).
//! __freadable / __fwritable / __flbf / __fbufsize / __fpending previously
//! discarded the FILE* and returned constants (readable=1, writable=1, lbf=0,
//! bufsize=BUFSIZ, pending=0), so e.g. __fwritable on a read-only stream was
//! wrong. They now read fl's actual stream state. This gate opens the SAME mode
//! with fl and with host glibc and asserts the introspection agrees. No mocks.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicU64, Ordering};

type File = c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn fopen(path: *const c_char, mode: *const c_char) -> *mut File;
        pub fn fclose(f: *mut File) -> c_int;
        pub fn setvbuf(f: *mut File, buf: *mut c_char, mode: c_int, size: usize) -> c_int;
        pub fn fwrite(p: *const c_void, sz: usize, n: usize, f: *mut File) -> usize;
        pub fn fflush(f: *mut File) -> c_int;
        pub fn __freadable(f: *mut File) -> c_int;
        pub fn __fwritable(f: *mut File) -> c_int;
        pub fn __flbf(f: *mut File) -> c_int;
        pub fn __fpending(f: *mut File) -> usize;
    }
}

use frankenlibc_abi::glibc_internal_abi as fle; // fl's __f* entry points
use frankenlibc_abi::stdio_abi as fl;

static CNT: AtomicU64 = AtomicU64::new(0);
fn temp_path(tag: &str) -> std::ffi::CString {
    let n = CNT.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("fl-stdioext-{}-{}-{}", std::process::id(), tag, n));
    // ensure the file exists (needed for "r"/"r+")
    std::fs::write(&p, b"seed-data\n").unwrap();
    std::ffi::CString::new(p.to_string_lossy().as_bytes()).unwrap()
}

#[test]
fn freadable_fwritable_match_glibc_per_mode() {
    for mode in ["r", "w", "a", "r+", "w+", "a+"] {
        let cm = std::ffi::CString::new(mode).unwrap();
        let gp = temp_path(&format!("g{mode}"));
        let fp = temp_path(&format!("f{mode}"));

        let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
        let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
        assert!(!gs.is_null() && !fs.is_null(), "fopen({mode}) failed");

        let gr = unsafe { g::__freadable(gs) } != 0;
        let fr = unsafe { fle::__freadable(fs) } != 0;
        assert_eq!(fr, gr, "__freadable mode={mode}: fl={fr} glibc={gr}");

        let gw = unsafe { g::__fwritable(gs) } != 0;
        let fw = unsafe { fle::__fwritable(fs) } != 0;
        assert_eq!(fw, gw, "__fwritable mode={mode}: fl={fw} glibc={gw}");

        // Sanity vs the spec: "r" is read-only, "w"/"a" write-only.
        match mode {
            "r" => assert!(fr && !fw, "r must be read-only"),
            "w" | "a" => assert!(!fr && fw, "{mode} must be write-only"),
            _ => assert!(fr && fw, "{mode} must be read+write"),
        }

        unsafe {
            g::fclose(gs);
            fl::fclose(fs);
        }
    }
}

#[test]
fn flbf_matches_glibc_after_setvbuf() {
    // _IOLBF -> line-buffered (nonzero); _IOFBF/_IONBF -> not line-buffered.
    for (vmode, want_lbf) in [(libc::_IOLBF, true), (libc::_IOFBF, false), (libc::_IONBF, false)] {
        let cm = c"w";
        let gp = temp_path("glbf");
        let fp = temp_path("flbf");
        let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
        let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
        unsafe {
            g::setvbuf(gs, std::ptr::null_mut(), vmode, 0);
            fl::setvbuf(fs, std::ptr::null_mut(), vmode, 0);
        }
        let glbf = unsafe { g::__flbf(gs) } != 0;
        let flbf = unsafe { fle::__flbf(fs) } != 0;
        assert_eq!(flbf, glbf, "__flbf vmode={vmode}: fl={flbf} glibc={glbf}");
        assert_eq!(flbf, want_lbf, "__flbf vmode={vmode} expected {want_lbf}");
        unsafe {
            g::fclose(gs);
            fl::fclose(fs);
        }
    }
}

#[test]
fn fpending_matches_glibc_for_buffered_writes() {
    // Full-buffered stream: a small write stays pending until flush.
    let cm = c"w";
    let gp = temp_path("gpend");
    let fp = temp_path("fpend");
    let gs = unsafe { g::fopen(gp.as_ptr(), cm.as_ptr()) };
    let fs = unsafe { fl::fopen(fp.as_ptr().cast::<c_char>(), cm.as_ptr().cast::<c_char>()) };
    // Force full buffering on both so the bytes are retained.
    let gbuf = vec![0u8; 4096];
    let fbuf = vec![0u8; 4096];
    unsafe {
        g::setvbuf(gs, gbuf.as_ptr() as *mut c_char, libc::_IOFBF, 4096);
        fl::setvbuf(fs, fbuf.as_ptr() as *mut c_char, libc::_IOFBF, 4096);
    }

    let data = b"hello stdio_ext";
    unsafe {
        g::fwrite(data.as_ptr().cast(), 1, data.len(), gs);
        fl::fwrite(data.as_ptr().cast(), 1, data.len(), fs);
    }
    let gp_n = unsafe { g::__fpending(gs) };
    let fp_n = unsafe { fle::__fpending(fs) };
    assert_eq!(fp_n, gp_n, "__fpending after write: fl={fp_n} glibc={gp_n}");
    assert_eq!(fp_n, data.len(), "__fpending must equal buffered byte count");

    // After flush, nothing pending.
    unsafe {
        g::fflush(gs);
        fl::fflush(fs);
    }
    let gp0 = unsafe { g::__fpending(gs) };
    let fp0 = unsafe { fle::__fpending(fs) };
    assert_eq!(fp0, gp0, "__fpending after flush: fl={fp0} glibc={gp0}");
    assert_eq!(fp0, 0, "__fpending must be 0 after flush");

    // keep the static buffers alive until both streams are closed
    unsafe {
        g::fclose(gs);
        fl::fclose(fs);
    }
    drop(gbuf);
    drop(fbuf);
}
