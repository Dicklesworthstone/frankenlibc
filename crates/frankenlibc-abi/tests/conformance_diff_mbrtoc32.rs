#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc mbrtoc32 oracle

//! Differential gate for mbrtoc32 (bd-0n4ayg). mbrtoc32 was the only C11
//! char-conversion with no differential coverage (only fl-internal
//! wchar_abi_test). fl delegates to mbrtowc with a wchar_t/char32_t cast; this
//! pins that bridge against glibc over the full UTF-8 range — ASCII, 2/3/4-byte
//! sequences (incl. code points above the BMP, e.g. U+1F600), incomplete tails,
//! invalid lead bytes, the embedded NUL, and n==0. Asserts the (return value,
//! *pc32) pair matches glibc byte-for-byte. Requires a UTF-8 locale. No mocks.

use std::ffi::{CString, c_char, c_void};

unsafe extern "C" {
    fn mbrtoc32(pc32: *mut u32, s: *const c_char, n: usize, ps: *mut c_void) -> usize;
    fn setlocale(category: i32, locale: *const c_char) -> *mut c_char;
}

const LC_ALL: i32 = 6;

fn run_glibc(bytes: &[u8], n: usize) -> (usize, u32) {
    let mut c32: u32 = 0xAAAA_AAAA;
    let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        mbrtoc32(
            &mut c32,
            bytes.as_ptr() as *const c_char,
            n,
            &mut st as *mut _ as *mut c_void,
        )
    };
    (r, c32)
}

fn run_fl(bytes: &[u8], n: usize) -> (usize, u32) {
    let mut c32: u32 = 0xAAAA_AAAA;
    let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let r = unsafe {
        frankenlibc_abi::wchar_abi::mbrtoc32(
            &mut c32,
            bytes.as_ptr() as *const c_char,
            n,
            &mut st as *mut _ as *mut c_void,
        )
    };
    (r, c32)
}

#[test]
fn mbrtoc32_matches_glibc() {
    // Put glibc into a UTF-8 locale so mbrtoc32 decodes UTF-8.
    let utf8 = CString::new("C.UTF-8").unwrap();
    unsafe { setlocale(LC_ALL, utf8.as_ptr()) };

    let cases: &[(&[u8], usize)] = &[
        (b"A", 1),            // ASCII
        (b"\x00", 1),         // embedded NUL -> 0
        ("é".as_bytes(), 2),  // U+00E9, 2-byte
        ("€".as_bytes(), 3),  // U+20AC, 3-byte
        ("😀".as_bytes(), 4), // U+1F600, 4-byte (above BMP)
        ("😀".as_bytes(), 2), // incomplete 4-byte (only 2 of 4 bytes) -> (size_t)-2
        (&[0xFF], 1),         // invalid lead byte -> (size_t)-1
        (&[0xC3], 1),         // incomplete 2-byte -> (size_t)-2
        (&[0xE2, 0x82], 2),   // incomplete 3-byte -> (size_t)-2
        (b"A", 0),            // n==0 -> (size_t)-2
        (&[0x80], 1),         // stray continuation byte -> (size_t)-1
    ];

    for &(bytes, n) in cases {
        let g = run_glibc(bytes, n);
        let f = run_fl(bytes, n);
        // For error/incomplete returns ((size_t)-1, (size_t)-2) glibc leaves
        // *pc32 untouched; only compare the code point when a character was
        // actually produced (ret is the byte count 0..=4; errors are huge).
        let produced = g.0 <= 4;
        assert_eq!(
            f.0, g.0,
            "mbrtoc32({bytes:02x?}, {n}) ret: fl={} glibc={}",
            f.0 as isize, g.0 as isize
        );
        if produced {
            assert_eq!(
                f.1, g.1,
                "mbrtoc32({bytes:02x?}, {n}) *pc32: fl={:#x} glibc={:#x}",
                f.1, g.1
            );
        }
    }
}
