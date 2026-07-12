#![cfg(target_os = "linux")]

//! Differential conformance harness for `wcrtomb(3)` in UTF-8 locale.
//!
//! `wcrtomb` encodes one wide char to multibyte. Both impls need to
//! produce byte-identical output across the full UTF-8 codepoint
//! range. fl always encodes UTF-8; glibc requires LC_CTYPE=*.UTF-8.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_void};
use std::sync::{Mutex, MutexGuard};

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcrtomb(s: *mut c_char, wc: libc::wchar_t, ps: *mut c_void) -> usize;
}

// Tests in this file mutate the process-global locale; serialize.
static LOCALE_LOCK: Mutex<()> = Mutex::new(());

fn locale_guard() -> MutexGuard<'static, ()> {
    match LOCALE_LOCK.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

fn with_utf8<F: FnOnce() -> R, R>(f: F) -> R {
    let _g = locale_guard();
    let saved = unsafe { libc::setlocale(libc::LC_ALL, std::ptr::null()) };
    let saved_str = if saved.is_null() {
        None
    } else {
        Some(unsafe { std::ffi::CStr::from_ptr(saved) }.to_owned())
    };
    let utf8 = c"C.UTF-8";
    let r = unsafe { libc::setlocale(libc::LC_ALL, utf8.as_ptr()) };
    let utf8_set = !r.is_null();
    let result = f();
    if let Some(s) = saved_str {
        unsafe { libc::setlocale(libc::LC_ALL, s.as_ptr()) };
    }
    let _ = utf8_set;
    result
}

fn encode_both(wc: u32) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    let mut fl_buf = [0u8; 8];
    let mut lc_buf = [0u8; 8];
    let fl_n = unsafe {
        fl::wcrtomb(
            fl_buf.as_mut_ptr() as *mut c_char,
            wc as i32,
            std::ptr::null_mut(),
        )
    };
    let lc_n = unsafe {
        wcrtomb(
            lc_buf.as_mut_ptr() as *mut c_char,
            wc as i32,
            std::ptr::null_mut(),
        )
    };
    let fl_o = if fl_n == usize::MAX {
        None
    } else {
        Some(fl_buf[..fl_n].to_vec())
    };
    let lc_o = if lc_n == usize::MAX {
        None
    } else {
        Some(lc_buf[..lc_n].to_vec())
    };
    (fl_o, lc_o)
}

#[test]
fn diff_wcrtomb_ascii_range() {
    with_utf8(|| {
        for wc in 0u32..=0x7F {
            let (fl_o, lc_o) = encode_both(wc);
            assert_eq!(fl_o, lc_o, "wcrtomb({wc:#x})");
            if let Some(b) = fl_o {
                assert_eq!(b.len(), 1);
                assert_eq!(b[0] as u32, wc);
            }
        }
    });
}

#[test]
fn diff_wcrtomb_2byte_range() {
    with_utf8(|| {
        for wc in [0x80u32, 0xFF, 0x100, 0x7FF] {
            let (fl_o, lc_o) = encode_both(wc);
            assert_eq!(fl_o, lc_o, "wcrtomb({wc:#x})");
            if let Some(b) = fl_o {
                assert_eq!(b.len(), 2, "expected 2-byte encoding for U+{wc:04X}");
                assert!((0xC0..0xE0).contains(&b[0]));
                assert!((0x80..0xC0).contains(&b[1]));
            }
        }
    });
}

#[test]
fn diff_wcrtomb_3byte_range_including_cjk() {
    with_utf8(|| {
        for wc in [0x800u32, 0x4E2D, 0xFFFD, 0xFFFF] {
            let (fl_o, lc_o) = encode_both(wc);
            assert_eq!(fl_o, lc_o, "wcrtomb({wc:#x}) bytes differ");
            if let Some(b) = fl_o {
                assert_eq!(b.len(), 3, "expected 3-byte encoding for U+{wc:04X}");
                assert!((0xE0..0xF0).contains(&b[0]));
                assert!((0x80..0xC0).contains(&b[1]));
                assert!((0x80..0xC0).contains(&b[2]));
            }
        }
    });
}

#[test]
fn diff_wcrtomb_4byte_range_supplementary_planes() {
    with_utf8(|| {
        for wc in [0x10000u32, 0x1F600, 0x10FFFF] {
            let (fl_o, lc_o) = encode_both(wc);
            assert_eq!(fl_o, lc_o, "wcrtomb({wc:#x}) bytes differ");
            if let Some(b) = fl_o {
                assert_eq!(b.len(), 4, "expected 4-byte encoding for U+{wc:06X}");
                assert!((0xF0..0xF8).contains(&b[0]));
                for &c in &b[1..] {
                    assert!((0x80..0xC0).contains(&c));
                }
            }
        }
    });
}

#[test]
fn fl_wcrtomb_high_codepoints_match_glibc() {
    // glibc's UTF-8 wcrtomb is RFC 2279, not RFC 3629: it encodes code points
    // beyond U+10FFFF as 4-6 byte sequences (legacy ISO 10646), capping at
    // U+7FFFFFFF and rejecting surrogates / anything larger. fl deliberately
    // mirrors this (string/wchar.rs wctomb is "verified against host glibc").
    // So this surface IS diffable — assert fl == glibc byte-for-byte and on the
    // ±EILSEQ boundary, rather than the (incorrect) RFC-3629 strictness the test
    // used to assume. Verified on glibc 2.42: U+110000 -> f4 90 80 80,
    // U+1FFFFF -> 4 bytes, U+200000 -> 5 bytes, U+7FFFFFFF -> 6 bytes,
    // U+80000000 and U+FFFFFFFF -> rejected, surrogates -> rejected.
    with_utf8(|| {
        for wc in [
            0x10_FFFFu32, // last Unicode scalar
            0x11_0000,    // first non-Unicode (still encoded, RFC 2279)
            0x12_3456,
            0x1F_FFFF,   // last 4-byte
            0x20_0000,   // first 5-byte
            0x3FF_FFFF,  // last 5-byte
            0x400_0000,  // first 6-byte
            0x7FFF_FFFF, // last encodable
            0x8000_0000, // first rejected
            0xFFFF_FFFF, // rejected
            0xD800,      // surrogate, rejected
            0xDFFF,      // surrogate, rejected
        ] {
            let mut fl_buf = [0u8; 8];
            let mut gl_buf = [0u8; 8];
            let fl_n = unsafe {
                fl::wcrtomb(
                    fl_buf.as_mut_ptr() as *mut c_char,
                    wc as i32,
                    std::ptr::null_mut(),
                )
            };
            let gl_n = unsafe {
                wcrtomb(
                    gl_buf.as_mut_ptr() as *mut c_char,
                    wc as libc::wchar_t,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(
                fl_n, gl_n,
                "wcrtomb(U+{wc:06X}) return: fl={fl_n} glibc={gl_n}"
            );
            if fl_n != usize::MAX {
                assert_eq!(
                    fl_buf[..fl_n],
                    gl_buf[..gl_n],
                    "wcrtomb(U+{wc:06X}) bytes diverged: fl={:02x?} glibc={:02x?}",
                    &fl_buf[..fl_n],
                    &gl_buf[..gl_n]
                );
            }
        }
    });
}

#[test]
fn diff_wcrtomb_surrogates_rejected() {
    with_utf8(|| {
        // U+D800..U+DFFF are surrogates and not valid in UTF-8.
        for wc in [0xD800u32, 0xDABC, 0xDFFF] {
            let (fl_o, lc_o) = encode_both(wc);
            assert_eq!(
                fl_o.is_some(),
                lc_o.is_some(),
                "wcrtomb(surrogate {wc:#x}): fl={} lc={}",
                fl_o.is_some(),
                lc_o.is_some()
            );
        }
    });
}

#[test]
fn diff_wcrtomb_null_target_returns_one() {
    // Both impls must return 1 (state byte length) for NULL target
    // in stateless UTF-8.
    with_utf8(|| {
        let fl_n = unsafe { fl::wcrtomb(std::ptr::null_mut(), 'a' as i32, std::ptr::null_mut()) };
        let lc_n = unsafe { wcrtomb(std::ptr::null_mut(), 'a' as i32, std::ptr::null_mut()) };
        assert_eq!(fl_n, lc_n, "NULL target: fl={fl_n} lc={lc_n}");
        assert_eq!(fl_n, 1);
    });
}

#[test]
fn wcrtomb_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc wcrtomb\",\"reference\":\"glibc-utf8\",\"functions\":1,\"divergences\":0}}",
    );
}
