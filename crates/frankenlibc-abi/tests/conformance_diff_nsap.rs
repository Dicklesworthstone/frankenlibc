//! Differential gate: inet_nsap_addr / inet_nsap_ntoa vs glibc.
//!
//! These OSI NSAP hex converters are file-independent and exported by glibc,
//! so they can be compared directly (via dlsym, bypassing fl's no_mangle
//! interposition). inet_nsap_addr reads hex digit *pairs*, allowing the
//! separators `.`/`+`/`/` only at byte boundaries (a separator mid-byte, an
//! odd nibble count, whitespace, or any non-hex byte all return 0); a leading
//! `0x` is therefore rejected (the `x` is not a hex digit). inet_nsap_ntoa
//! renders uppercase hex with glibc's 1+2+2+... dot grouping. fl already
//! matches; this pins it against the live host.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::ffi::{CString, c_char, c_int, c_uint, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type AddrFn = extern "C" fn(*const c_char, *mut u8, c_int) -> c_uint;
type NtoaFn = extern "C" fn(c_int, *const u8, *mut c_char) -> *mut c_char;

fn fl_addr(cp: *const c_char, buf: *mut c_void, len: c_int) -> c_uint {
    unsafe { frankenlibc_abi::glibc_internal_abi::inet_nsap_addr(cp, buf, len) }
}

#[test]
fn inet_nsap_addr_matches_glibc() {
    let g: AddrFn = unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null());
        std::mem::transmute::<*mut c_void, AddrFn>(dlsym(lib, c"inet_nsap_addr".as_ptr()))
    };

    let cases = [
        "1234abcd",
        "0x1234",
        "0x12.34.56",
        "ab/cd",
        "1.2",
        "123",
        "1234",
        "12 34",
        "1+2+3+4",
        "",
        "...",
        "g",
        "12.3",
        "0xAB.CD",
        "deadbeef",
        "DE.AD.BE.EF",
        "ff",
        "f",
        "00112233445566778899aabbccddeeff",
    ];

    let mut mismatches = Vec::new();
    for &s in &cases {
        let cs = CString::new(s).unwrap();
        let mut gb = [0u8; 64];
        let gn = g(cs.as_ptr(), gb.as_mut_ptr(), 64);
        let mut fb = [0u8; 64];
        let fn_ = fl_addr(cs.as_ptr(), fb.as_mut_ptr() as *mut c_void, 64);
        // On success compare written bytes; on 0 only the count is defined.
        let ok = gn == fn_ && (gn == 0 || gb[..gn as usize] == fb[..fn_ as usize]);
        if !ok {
            mismatches.push(format!(
                "{s:?}: glibc=({gn},{:02x?}) fl=({fn_},{:02x?})",
                &gb[..gn as usize],
                &fb[..fn_ as usize]
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "inet_nsap_addr diverged:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn inet_nsap_ntoa_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null());
    let g: NtoaFn = unsafe {
        std::mem::transmute::<*mut c_void, NtoaFn>(dlsym(lib, c"inet_nsap_ntoa".as_ptr()))
    };

    let inputs: &[&[u8]] = &[
        &[0x12, 0x34, 0xab, 0xcd],
        &[0xde, 0xad, 0xbe, 0xef],
        &[0x00],
        &[0xff],
        &[0x01, 0x02, 0x03],
        &[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        &[],
    ];

    let mut mismatches = Vec::new();
    for &inp in inputs {
        let mut gout = [0u8; 256];
        let gp = g(
            inp.len() as c_int,
            inp.as_ptr(),
            gout.as_mut_ptr() as *mut c_char,
        );
        let gs = if gp.is_null() {
            Vec::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(gp) }.to_bytes().to_vec()
        };

        let mut fout = [0u8; 256];
        let fp = unsafe {
            frankenlibc_abi::glibc_internal_abi::inet_nsap_ntoa(
                inp.len() as c_int,
                inp.as_ptr() as *const c_void,
                fout.as_mut_ptr() as *mut c_char,
            )
        };
        let fs = if fp.is_null() {
            Vec::new()
        } else {
            unsafe { std::ffi::CStr::from_ptr(fp) }.to_bytes().to_vec()
        };

        if gs != fs {
            mismatches.push(format!(
                "{inp:02x?}: glibc={:?} fl={:?}",
                String::from_utf8_lossy(&gs),
                String::from_utf8_lossy(&fs)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "inet_nsap_ntoa diverged:\n{}",
        mismatches.join("\n")
    );
}
