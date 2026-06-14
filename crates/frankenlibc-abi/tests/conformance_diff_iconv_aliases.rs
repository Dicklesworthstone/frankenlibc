//! Conformance gate: iconv charset-name aliases that glibc accepts and fl now
//! also accepts, each mapping to a codec fl already implements. Verifies both
//! iconv_open success AND byte-exact conversion vs host glibc (so the alias
//! resolves to the CORRECT codec/endianness, not merely "opens").
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use std::os::raw::{c_char, c_void};
unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(
        cd: *mut c_void,
        i: *mut *mut c_char,
        il: *mut usize,
        o: *mut *mut c_char,
        ol: *mut usize,
    ) -> usize;
    fn iconv_close(cd: *mut c_void) -> i32;
}
use frankenlibc_abi::iconv_abi as fl;
fn conv(host: bool, from: &str, to: &str, src: &[u8]) -> Option<Vec<u8>> {
    let cf = std::ffi::CString::new(from).unwrap();
    let ct = std::ffi::CString::new(to).unwrap();
    let cd = if host {
        unsafe { iconv_open(ct.as_ptr(), cf.as_ptr()) }
    } else {
        unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) }
    };
    if cd as isize == -1 {
        return None;
    }
    let mut out = vec![0u8; 256];
    let mut ip = src.as_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = if host {
        unsafe { iconv(cd, &mut ip, &mut il, &mut op, &mut ol) }
    } else {
        unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) }
    };
    if host {
        unsafe {
            iconv_close(cd);
        }
    } else {
        unsafe {
            fl::iconv_close(cd);
        }
    }
    if r == usize::MAX {
        return Some(vec![0xde, 0xad]);
    } // mark error distinctly but comparably
    let n = out.len() - ol;
    out.truncate(n);
    Some(out)
}
#[test]
fn iconv_aliases_open_and_convert_like_glibc() {
    // (alias, sample-utf8 representable in the target)
    let cases: &[(&str, &str)] = &[
        ("L1", "caf\u{e9}"),
        ("L2", "a\u{105}"),
        ("L5", "\u{11e}z"),
        ("ANSI_X3.4", "hello"),
        ("iso-ir-6", "ABC"),
        ("MS_KANJI", "\u{3042}A"), // Hiragana A + ASCII
        ("UNICODELITTLE", "A\u{e9}"),
        ("UNICODEBIG", "A\u{e9}"),
        ("csUnicode", "A\u{e9}"),
        ("WCHAR_T", "A\u{e9}"),
        // ISO-8859-N underscore forms glibc accepts (the dead "8859_N" aliases
        // never matched before — they normalize to "8859N").
        ("8859_1", "caf\u{e9}"),
        ("8859_2", "a\u{105}"),
        ("8859_5", "\u{416}"),
        ("8859_7", "\u{3b1}"),
        ("8859_9", "\u{11e}"),
        // L6 -> ISO-8859-10, L7 -> ISO-8859-13, ISO-10646/UTF-8 -> UTF-8.
        ("L6", "\u{100}z"),
        ("L7", "\u{104}z"),
        ("ISO-10646/UTF-8", "caf\u{e9}\u{4e2d}"),
    ];
    let mut fails = Vec::new();
    for &(alias, sample) in cases {
        let bytes = sample.as_bytes();
        // fl must open the alias at all
        let cn = std::ffi::CString::new(alias).unwrap();
        let to = std::ffi::CString::new("UTF-8").unwrap();
        let cd = unsafe { fl::iconv_open(to.as_ptr(), cn.as_ptr()) };
        if cd as isize == -1 {
            fails.push(format!("{alias}: fl iconv_open FAILED"));
            continue;
        }
        unsafe { fl::iconv_close(cd) };
        // encode UTF-8 -> alias, both engines
        let h = conv(true, "UTF-8", alias, bytes);
        let f = conv(false, "UTF-8", alias, bytes);
        if h != f {
            fails.push(format!(
                "encode {alias} {sample:?}: host={h:02x?} fl={f:02x?}"
            ));
        }
        // decode alias -> UTF-8 (round-trip the glibc encoding)
        if let Some(enc) = h {
            let hd = conv(true, alias, "UTF-8", &enc);
            let fd = conv(false, alias, "UTF-8", &enc);
            if hd != fd {
                fails.push(format!("decode {alias}: host={hd:02x?} fl={fd:02x?}"));
            }
        }
    }
    assert!(
        fails.is_empty(),
        "iconv alias mismatch vs glibc:\n{}",
        fails.join("\n")
    );
}
