//! Differential gate for wide printf `%n` counting wide characters vs glibc.
//!
//! For wide-stream output the C standard says `%n` stores the number of WIDE
//! CHARACTERS written so far. fl accumulates output as UTF-8 internally and the
//! `%n` handler returned `buf.len()` (the byte count) unconditionally, so any
//! multibyte content inflated the count: swprintf(L"ééé%n") stored 6 (bytes)
//! instead of 3 (wide chars). ASCII hid it (byte count == char count).
//!
//! fl is called via its Rust swprintf path; glibc via dlsym on libc.so.6.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::wchar_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn setlocale(category: c_int, locale: *const c_char) -> *mut c_char;
}
type SwprintfFn =
    unsafe extern "C" fn(*mut libc::wchar_t, usize, *const libc::wchar_t, ...) -> c_int;

fn wide(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

#[test]
fn wide_printf_n_counts_wide_chars_like_glibc() {
    unsafe { setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    let h = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!h.is_null());
    let gp = unsafe { dlsym(h, c"swprintf".as_ptr()) };
    assert!(!gp.is_null(), "missing swprintf");
    let g_swprintf: SwprintfFn = unsafe { core::mem::transmute(gp) };

    // (format, the wide-char count %n should report). Each format takes exactly
    // one vararg — the `int*` for %n — so the call shape is uniform.
    let cases = [
        ("ééé%n", 3),       // 2 UTF-8 bytes each
        ("中中%n", 2),       // 3 UTF-8 bytes each
        ("abc%n", 3),        // ASCII (regression guard)
        ("a😀b%n", 3),       // 4-byte emoji + 2 ASCII
        ("mix€é%n", 5),      // ASCII + 3-byte euro + 2-byte é
        ("%n", 0),           // count at offset 0
    ];

    let mut div = Vec::new();
    for (f, expect) in cases {
        let wf = wide(f);
        let mut fbuf = [0 as libc::wchar_t; 64];
        let mut gbuf = [0 as libc::wchar_t; 64];
        let mut fn_n: c_int = -1;
        let mut g_n: c_int = -1;
        unsafe {
            fl::swprintf(fbuf.as_mut_ptr(), 64, wf.as_ptr(), &mut fn_n as *mut c_int);
            g_swprintf(gbuf.as_mut_ptr(), 64, wf.as_ptr(), &mut g_n as *mut c_int);
        }
        if fn_n != g_n || g_n != expect {
            div.push(format!("{f:?}: fl_n={fn_n} glibc_n={g_n} expect={expect}"));
        }
    }
    assert!(div.is_empty(), "wide %n divergences ({}):\n  {}", div.len(), div.join("\n  "));
}
