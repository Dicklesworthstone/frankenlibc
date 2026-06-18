#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc mempcpy/rawmemchr oracle + raw buffers

//! Differential gate for the GNU mempcpy + rawmemchr (bd-t9e3fc). mempcpy copies
//! n bytes and returns dst+n (a pointer to the END of the copy, unlike memcpy).
//! rawmemchr searches for byte c with NO length bound (the caller guarantees c
//! is present) and returns a pointer to the first match. For each scenario fl
//! must agree with host glibc on the returned offset and (mempcpy) the copied
//! bytes. No mocks.

use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn mempcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void;
    fn rawmemchr(s: *const c_void, c: c_int) -> *mut c_void;
}

const FILL: u8 = 0x3c;

fn off(ret: *mut c_void, base: *const u8) -> isize {
    (ret as isize) - (base as isize)
}

#[test]
fn mempcpy_matches_glibc() {
    let src: Vec<u8> = (0..32u8).collect();
    for n in [0usize, 1, 5, 16, 31, 32] {
        let mut gd = [FILL; 40];
        let mut fd = [FILL; 40];
        let rg = unsafe { mempcpy(gd.as_mut_ptr() as *mut c_void, src.as_ptr() as *const c_void, n) };
        let rf = unsafe {
            frankenlibc_abi::string_abi::mempcpy(
                fd.as_mut_ptr() as *mut c_void,
                src.as_ptr() as *const c_void,
                n,
            )
        };
        assert_eq!(off(rf, fd.as_ptr()), off(rg, gd.as_ptr()), "mempcpy(n={n}) return");
        assert_eq!(off(rg, gd.as_ptr()), n as isize, "mempcpy must return dst+n");
        assert_eq!(fd, gd, "mempcpy(n={n}) buffer");
    }
}

#[test]
fn rawmemchr_matches_glibc() {
    // Each buffer is guaranteed to contain the search byte (rawmemchr is
    // unbounded and must not be called otherwise).
    let buf = b"the quick brown fox\0jumps";
    for c in [b't', b'q', b'x', b' ', b'\0', b'e', b'j'] {
        let rg = unsafe { rawmemchr(buf.as_ptr() as *const c_void, c as c_int) };
        let rf = unsafe {
            frankenlibc_abi::string_abi::rawmemchr(buf.as_ptr() as *const c_void, c as c_int)
        };
        assert_eq!(
            off(rf, buf.as_ptr()),
            off(rg, buf.as_ptr()),
            "rawmemchr(c={c}) offset"
        );
    }
}

#[test]
fn rawmemchr_finds_first_occurrence() {
    let buf = b"aabbaa\0";
    // 'a' first at index 0, 'b' first at index 2, NUL at index 6.
    let expect = [(b'a', 0isize), (b'b', 2), (0u8, 6)];
    for (c, want) in expect {
        let rf = unsafe {
            frankenlibc_abi::string_abi::rawmemchr(buf.as_ptr() as *const c_void, c as c_int)
        };
        assert_eq!(off(rf, buf.as_ptr()), want, "rawmemchr(c={c}) first-match");
    }
}
