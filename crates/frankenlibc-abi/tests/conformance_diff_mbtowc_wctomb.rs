#![cfg(target_os = "linux")]
//! Differential conformance for `mbtowc` / `wctomb` vs glibc in a UTF-8 locale.
//!
//! glibc's UTF-8 codec is RFC 3629: it rejects 5-/6-byte sequences, overlong
//! encodings, UTF-16 surrogates, and code points above U+10FFFF — even though
//! MB_CUR_MAX is 6. mbrtowc already matches this; this checks mbtowc/wctomb
//! (which historically used an RFC-2279 1-6 byte codec) against the same oracle.

use std::ffi::c_char;
use std::sync::Mutex;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    // Host glibc mbtowc/wctomb (not surfaced by the libc crate).
    fn mbtowc(pwc: *mut libc::wchar_t, s: *const c_char, n: usize) -> libc::c_int;
    fn wctomb(s: *mut c_char, wc: libc::wchar_t) -> libc::c_int;
}

static LOCALE_LOCK: Mutex<()> = Mutex::new(());

fn with_utf8<R>(f: impl FnOnce() -> R) -> R {
    let _g = LOCALE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let utf8 = c"C.UTF-8";
    unsafe { libc::setlocale(libc::LC_ALL, utf8.as_ptr()) };
    f()
}

#[test]
fn diff_mbtowc_utf8_grid() {
    with_utf8(|| {
        let cases: &[(&[u8], &str)] = &[
            (&[0x41], "ASCII 'A'"),
            (&[0xC2, 0xA9], "2-byte U+00A9"),
            (&[0xE4, 0xB8, 0xAD], "3-byte CJK U+4E2D"),
            (&[0xF0, 0x9F, 0x98, 0x80], "4-byte emoji U+1F600"),
            (&[0xC0, 0x80], "overlong NUL"),
            (&[0xC1, 0xBF], "overlong ASCII"),
            (&[0xE0, 0x80, 0x80], "overlong 3-byte U+0"),
            (&[0xED, 0xA0, 0x80], "surrogate U+D800"),
            (&[0xED, 0xBF, 0xBF], "surrogate U+DFFF"),
            (&[0xF4, 0x90, 0x80, 0x80], "above U+10FFFF (U+110000)"),
            (&[0xF8, 0x80, 0x80, 0x80, 0x80], "5-byte form"),
            (&[0xFC, 0x80, 0x80, 0x80, 0x80, 0x80], "6-byte form"),
            (&[0x80], "lone continuation"),
            (&[0xFF], "0xFF"),
        ];
        let mut divs = Vec::new();
        for (bytes, label) in cases {
            let mut fl_wc: u32 = 0xDEAD;
            let mut lc_wc: libc::wchar_t = 0x7EAD;
            let fl_n = unsafe { fl::mbtowc(&mut fl_wc, bytes.as_ptr(), bytes.len()) };
            let lc_n = unsafe { mbtowc(&mut lc_wc, bytes.as_ptr() as *const c_char, bytes.len()) };
            let val_differs = fl_n > 0 && lc_n > 0 && fl_wc != lc_wc as u32;
            if fl_n != lc_n || val_differs {
                divs.push(format!(
                    "  mbtowc {label}: fl=(rc={fl_n}, wc={fl_wc:#x}) glibc=(rc={lc_n}, wc={lc_wc:#x})"
                ));
            }
        }
        assert!(divs.is_empty(), "mbtowc divergences:\n{}", divs.join("\n"));
    });
}

#[test]
fn diff_wctomb_utf8_grid() {
    with_utf8(|| {
        let cases: &[(u32, &str)] = &[
            (0x41, "ASCII 'A'"),
            (0xA9, "U+00A9"),
            (0x4E2D, "CJK U+4E2D"),
            (0x1F600, "emoji U+1F600"),
            (0x10FFFF, "max valid U+10FFFF"),
            (0xD800, "surrogate U+D800"),
            (0xDFFF, "surrogate U+DFFF"),
            (0x110000, "above max U+110000"),
            (0x200000, "5-byte-range U+200000"),
            (0x7FFFFFFF, "6-byte-range U+7FFFFFFF"),
        ];
        let mut divs = Vec::new();
        for (wc, label) in cases {
            let mut fl_buf = [0u8; 8];
            let mut lc_buf = [0u8; 8];
            let fl_n = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), *wc) };
            let lc_n = unsafe { wctomb(lc_buf.as_mut_ptr() as *mut c_char, *wc as libc::wchar_t) };
            let bytes_differ =
                fl_n > 0 && lc_n > 0 && fl_buf[..fl_n as usize] != lc_buf[..lc_n as usize];
            if fl_n != lc_n || bytes_differ {
                divs.push(format!(
                    "  wctomb {label}: fl=(rc={fl_n}, {:02x?}) glibc=(rc={lc_n}, {:02x?})",
                    &fl_buf[..fl_n.max(0) as usize],
                    &lc_buf[..lc_n.max(0) as usize]
                ));
            }
        }
        assert!(divs.is_empty(), "wctomb divergences:\n{}", divs.join("\n"));
    });
}
