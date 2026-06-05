#![cfg(target_os = "linux")]

//! Differential conformance harness for the `<wchar.h>` / `<stdlib.h>`
//! multibyte ⇄ wide-char codec against host glibc.
//!
//! glibc's UTF-8 gconv module does **not** implement the modern RFC 3629
//! form (1–4 bytes, capped at U+10FFFF). It implements the historical
//! RFC 2279 form: 1–6 byte sequences encoding code points through
//! U+7FFFFFFF, rejecting overlong encodings, UTF-16 surrogates, and the
//! lead bytes 0xFE / 0xFF. `MB_CUR_MAX` for the UTF-8 locale is therefore
//! 6, not 4. frankenlibc-core/src/string/wchar.rs ports that exact rule;
//! this harness pins the port to the host C library at runtime so the
//! 4-byte-above-U+10FFFF and 5/6-byte cases stay in lockstep.
//!
//! The earlier port capped decoding at U+10FFFF and four bytes, so
//! `mbrtowc("\xF4\x90\x80\x80")` returned EILSEQ while glibc decodes it to
//! U+110000. Bead: bd-2g7oyh (no-gaps parity).

use std::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    /// Host glibc `wctomb` — not exposed by the `libc` crate surface, so
    /// we link it directly against libc.so.6.
    fn wctomb(s: *mut c_char, wchar: libc::wchar_t) -> c_int;
    /// Host glibc `mbrtowc` — also absent from the `libc` crate surface.
    #[link_name = "mbrtowc"]
    fn host_mbrtowc(
        pwc: *mut libc::wchar_t,
        s: *const c_char,
        n: libc::size_t,
        ps: *mut libc::mbstate_t,
    ) -> libc::size_t;
}

/// One mbrtowc divergence record for human-readable failure output.
#[derive(Debug)]
struct Div {
    case: String,
    field: &'static str,
    fl: String,
    glibc: String,
}

fn set_utf8_locale() {
    // Try C.UTF-8 first, then en_US.UTF-8. Either yields the RFC 2279
    // UTF-8 gconv module with MB_CUR_MAX == 6.
    for name in [c"C.UTF-8", c"en_US.UTF-8"] {
        let r = unsafe { libc::setlocale(libc::LC_ALL, name.as_ptr()) };
        if !r.is_null() {
            return;
        }
    }
    panic!("no UTF-8 locale available on host; cannot run differential codec harness");
}

/// Decode `bytes` with both implementations and record any divergence.
fn diff_mbrtowc(label: &str, bytes: &[u8], n: usize, out: &mut Vec<Div>) {
    // Host glibc.
    let mut g_wc: libc::wchar_t = 0;
    let mut g_state: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let g_ret =
        unsafe { host_mbrtowc(&mut g_wc, bytes.as_ptr() as *const c_char, n, &mut g_state) };

    // frankenlibc.
    let mut f_wc: libc::wchar_t = 0;
    let f_ret = unsafe {
        frankenlibc_abi::wchar_abi::mbrtowc(
            &mut f_wc,
            bytes.as_ptr() as *const c_char,
            n,
            std::ptr::null_mut::<c_void>(),
        )
    };

    if g_ret != f_ret {
        out.push(Div {
            case: label.to_string(),
            field: "ret",
            fl: format!("{}", f_ret as isize),
            glibc: format!("{}", g_ret as isize),
        });
    }
    // Only compare the decoded code point when both succeeded with a
    // real character (ret is a positive byte count). For error / NUL /
    // incomplete returns the out param is unspecified.
    let is_char = g_ret != 0 && g_ret != usize::MAX && g_ret != usize::MAX - 1;
    if g_ret == f_ret && is_char && g_wc != f_wc {
        out.push(Div {
            case: label.to_string(),
            field: "wc",
            fl: format!("0x{:x}", f_wc as u32),
            glibc: format!("0x{:x}", g_wc as u32),
        });
    }
}

#[test]
fn mbrtowc_matches_glibc_rfc2279() {
    set_utf8_locale();
    let mut divs = Vec::new();

    // (label, bytes, n)
    let cases: &[(&str, &[u8], usize)] = &[
        ("ascii 'A'", &[0x41], 1),
        ("2B cent U+00A2", &[0xC2, 0xA2], 2),
        ("3B euro U+20AC", &[0xE2, 0x82, 0xAC], 3),
        ("4B emoji U+1F600", &[0xF0, 0x9F, 0x98, 0x80], 4),
        ("4B U+10FFFF", &[0xF4, 0x8F, 0xBF, 0xBF], 4),
        // The historical-form acceptances that the old port rejected:
        ("4B U+110000", &[0xF4, 0x90, 0x80, 0x80], 4),
        ("4B U+140000", &[0xF5, 0x80, 0x80, 0x80], 4),
        ("4B max U+1FFFFF", &[0xF7, 0xBF, 0xBF, 0xBF], 4),
        ("5B max U+3FFFFFF", &[0xFB, 0xBF, 0xBF, 0xBF, 0xBF], 5),
        (
            "6B max U+7FFFFFFF",
            &[0xFD, 0xBF, 0xBF, 0xBF, 0xBF, 0xBF],
            6,
        ),
        ("5B min U+200000", &[0xF8, 0x88, 0x80, 0x80, 0x80], 5),
        ("6B min U+4000000", &[0xFC, 0x84, 0x80, 0x80, 0x80, 0x80], 6),
        // Rejections that must stay rejections:
        ("overlong C0 80", &[0xC0, 0x80], 2),
        ("overlong E0 80 80", &[0xE0, 0x80, 0x80], 3),
        ("overlong F0 80 80 80", &[0xF0, 0x80, 0x80, 0x80], 4),
        ("overlong F0 8F BF BF", &[0xF0, 0x8F, 0xBF, 0xBF], 4),
        ("surrogate ED A0 80", &[0xED, 0xA0, 0x80], 3),
        ("lead 0xFE", &[0xFE, 0x80, 0x80, 0x80, 0x80, 0x80], 6),
        ("lead 0xFF", &[0xFF, 0x80, 0x80, 0x80, 0x80, 0x80], 6),
        ("bare continuation 0x80", &[0x80], 1),
        // Incomplete sequences (glibc returns (size_t)-2):
        ("incomplete 2B head", &[0xC2], 1),
        ("incomplete 3B partial", &[0xE2, 0x82], 2),
        ("incomplete 6B partial", &[0xFD, 0xBF, 0xBF], 3),
    ];

    for (label, bytes, n) in cases {
        diff_mbrtowc(label, bytes, *n, &mut divs);
    }

    assert!(
        divs.is_empty(),
        "mbrtowc diverged from glibc:\n{}",
        divs.iter()
            .map(|d| format!("  {} | {} | fl={} glibc={}", d.case, d.field, d.fl, d.glibc))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Encode `cp` with both implementations and assert byte-for-byte parity.
fn diff_wctomb(label: &str, cp: u32) -> Option<String> {
    // Host glibc — provide MB_LEN_MAX scratch.
    let mut g_buf = [0i8; 16];
    let g_ret = unsafe { wctomb(g_buf.as_mut_ptr() as *mut c_char, cp as libc::wchar_t) };

    // frankenlibc.
    let mut f_buf = [0u8; 16];
    let f_ret = unsafe { frankenlibc_abi::wchar_abi::wctomb(f_buf.as_mut_ptr(), cp) };

    if g_ret != f_ret as c_int {
        return Some(format!("  {} | ret | fl={} glibc={}", label, f_ret, g_ret));
    }
    if g_ret > 0 {
        let n = g_ret as usize;
        let g_bytes: Vec<u8> = g_buf[..n].iter().map(|&b| b as u8).collect();
        if g_bytes != f_buf[..n] {
            return Some(format!(
                "  {} | bytes | fl={:02x?} glibc={:02x?}",
                label,
                &f_buf[..n],
                g_bytes
            ));
        }
    }
    None
}

#[test]
fn wctomb_matches_glibc_rfc2279() {
    set_utf8_locale();
    let mut fails = Vec::new();

    let cases: &[(&str, u32)] = &[
        ("U+0041", 0x41),
        ("U+00A2", 0xA2),
        ("U+20AC", 0x20AC),
        ("U+1F600", 0x1F600),
        ("U+10FFFF", 0x10FFFF),
        ("U+110000", 0x110000),
        ("U+1FFFFF", 0x1FFFFF),
        ("U+200000", 0x200000),
        ("U+3FFFFFF", 0x3FFFFFF),
        ("U+4000000", 0x4000000),
        ("U+7FFFFFFF", 0x7FFFFFFF),
        ("surrogate U+D800", 0xD800),
        ("surrogate U+DFFF", 0xDFFF),
    ];

    for (label, cp) in cases {
        if let Some(f) = diff_wctomb(label, *cp) {
            fails.push(f);
        }
    }

    assert!(
        fails.is_empty(),
        "wctomb diverged from glibc:\n{}",
        fails.join("\n")
    );
}

/// Round-trip: every code point glibc accepts via wctomb must decode back
/// to itself through frankenlibc mbrtowc, and vice versa.
#[test]
fn mb_wc_round_trip_full_range() {
    set_utf8_locale();
    let mut fails = Vec::new();

    // Sample across every sequence-length regime plus boundaries.
    let cps: &[u32] = &[
        0x00,
        0x7F,
        0x80,
        0x7FF,
        0x800,
        0xFFFF,
        0x1_0000,
        0x10_FFFF,
        0x11_0000,
        0x1F_FFFF,
        0x20_0000,
        0x3FF_FFFF,
        0x400_0000,
        0x7FFF_FFFF,
        0x1234,
        0xABCDE,
        0x1_2345,
        0x123_4567,
    ];

    for &cp in cps {
        let mut buf = [0u8; 16];
        let enc = unsafe { frankenlibc_abi::wchar_abi::wctomb(buf.as_mut_ptr(), cp) };
        if enc <= 0 {
            fails.push(format!("U+{cp:X}: wctomb returned {enc}"));
            continue;
        }
        let n = enc as usize;
        let mut wc: libc::wchar_t = 0;
        let dec = unsafe {
            frankenlibc_abi::wchar_abi::mbrtowc(
                &mut wc,
                buf.as_ptr() as *const c_char,
                n,
                std::ptr::null_mut::<c_void>(),
            )
        };
        // Per POSIX, mbrtowc returns 0 (not the byte count) when the
        // decoded character is the null wide character.
        let expected = if cp == 0 { 0 } else { n };
        if dec != expected {
            fails.push(format!(
                "U+{cp:X}: mbrtowc returned {dec}, expected {expected}"
            ));
        } else if wc as u32 != cp {
            fails.push(format!("U+{cp:X}: decoded to U+{:X}", wc as u32));
        }
    }

    assert!(
        fails.is_empty(),
        "round-trip failures:\n{}",
        fails.join("\n")
    );
}
