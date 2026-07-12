//! Differential gate: posix_madvise(POSIX_MADV_DONTNEED) is non-destructive,
//! matching live host glibc.
//!
//! Linux MADV_DONTNEED zero-fills private anonymous pages; POSIX_MADV_DONTNEED is
//! advisory. glibc ignores it (returns 0, no syscall). fl previously passed it to
//! the kernel and DESTROYED the caller's data. We write a marker to a private
//! anon page, advise DONTNEED via fl and glibc, and require the data survives
//! (and rc==0), plus a bogus-address DONTNEED returns 0 (no syscall). glibc via
//! dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        off: i64,
    ) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
}
type MadvFn = unsafe extern "C" fn(*mut c_void, usize, c_int) -> c_int;

const PROT_RW: c_int = 3;
const MAP_PRIVATE: c_int = 2;
const MAP_ANON: c_int = 0x20;
const PS: usize = 4096;
const POSIX_MADV_DONTNEED: c_int = 4;
const POSIX_MADV_WILLNEED: c_int = 3;
const MARKER: u32 = 0xDEAD_BEEF;

fn glibc_posix_madvise() -> MadvFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"posix_madvise".as_ptr()))
    }
}

/// Map a private-anon page, write MARKER, advise DONTNEED via `f`, return
/// (rc, value-after).
fn cycle(f: MadvFn) -> (c_int, u32) {
    unsafe {
        let p = mmap(
            std::ptr::null_mut(),
            PS,
            PROT_RW,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );
        assert!(p as isize != -1, "mmap failed");
        *(p as *mut u32) = MARKER;
        let rc = f(p, PS, POSIX_MADV_DONTNEED);
        let after = *(p as *const u32);
        munmap(p, PS);
        (rc, after)
    }
}

#[test]
fn posix_madvise_dontneed_is_nondestructive_like_glibc() {
    let g = glibc_posix_madvise();
    let gc = cycle(g);
    let fc = cycle(fl::posix_madvise);
    assert_eq!(gc.0, 0, "glibc posix_madvise(DONTNEED) rc");
    assert_eq!(gc.1, MARKER, "glibc must not destroy the page");
    assert_eq!(fc.0, gc.0, "rc: glibc={} fl={}", gc.0, fc.0);
    assert_eq!(
        fc.1, MARKER,
        "fl posix_madvise(DONTNEED) destroyed the page (was the bug)"
    );

    // A bogus address with DONTNEED must still return 0 (glibc issues no syscall).
    unsafe {
        let bogus = 0x1000 as *mut c_void;
        assert_eq!(g(bogus, PS, POSIX_MADV_DONTNEED), 0, "glibc bogus DONTNEED");
        assert_eq!(
            fl::posix_madvise(bogus, PS, POSIX_MADV_DONTNEED),
            0,
            "fl bogus DONTNEED should be 0 (no syscall)"
        );
    }

    // A non-DONTNEED advice on a valid mapping still succeeds on both.
    unsafe {
        let p = mmap(
            std::ptr::null_mut(),
            PS,
            PROT_RW,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );
        assert!(p as isize != -1);
        assert_eq!(
            g(p, PS, POSIX_MADV_WILLNEED),
            fl::posix_madvise(p, PS, POSIX_MADV_WILLNEED),
            "WILLNEED rc parity"
        );
        munmap(p, PS);
    }
}
