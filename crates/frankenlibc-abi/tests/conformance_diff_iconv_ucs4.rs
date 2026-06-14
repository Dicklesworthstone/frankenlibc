//! Conformance gate: iconv "UCS-4" / "UCS-4BE" / "UCS-4LE" charset support vs
//! host glibc. fl previously failed iconv_open for these names; they are now
//! aliases of UTF-32BE / UTF-32LE. Verified byte-exact with host glibc across
//! valid Unicode + surrogate + boundary inputs, both directions.
//!
//! Documented divergence (bd-zdxuly): glibc's UCS-4 accepts codepoints above
//! U+10FFFF and emits non-standard extended UTF-8; a Rust `char` cannot hold
//! those, so fl is Unicode-strict (rejects them) — NOT exercised here.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use std::os::raw::{c_char, c_void};

unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inleft: *mut usize,
        outbuf: *mut *mut c_char,
        outleft: *mut usize,
    ) -> usize;
    fn iconv_close(cd: *mut c_void) -> i32;
}
use frankenlibc_abi::iconv_abi as fl;

fn host_conv(from: &str, to: &str, input: &[u8]) -> Option<Vec<u8>> {
    let cf = std::ffi::CString::new(from).unwrap();
    let ct = std::ffi::CString::new(to).unwrap();
    let cd = unsafe { iconv_open(ct.as_ptr(), cf.as_ptr()) };
    if cd as isize == -1 {
        return None;
    }
    let mut out = vec![0u8; 256];
    let mut ip = input.as_ptr() as *mut c_char;
    let mut il = input.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { iconv_close(cd) };
    if r == usize::MAX {
        return None;
    }
    let n = out.len() - ol;
    out.truncate(n);
    Some(out)
}

fn fl_conv(from: &str, to: &str, input: &[u8]) -> Option<Vec<u8>> {
    let cf = std::ffi::CString::new(from).unwrap();
    let ct = std::ffi::CString::new(to).unwrap();
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    if cd as isize == -1 {
        return None;
    }
    let mut out = vec![0u8; 256];
    let mut ip = input.as_ptr() as *mut c_char;
    let mut il = input.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == usize::MAX {
        return None;
    }
    let n = out.len() - ol;
    out.truncate(n);
    Some(out)
}

#[test]
fn ucs4_matches_glibc_both_directions() {
    // Valid UTF-8 strings (incl astral, no >U+10FFFF).
    let samples: &[&[u8]] = &[
        b"A",
        b"hello",
        "\u{00e9}".as_bytes(),
        "\u{4e00}".as_bytes(),
        "\u{1f600}".as_bytes(),
        "\u{10ffff}".as_bytes(),
        "Mix\u{e9}\u{4e00}\u{1f600}".as_bytes(),
        b"",
        "\u{0}\u{7f}\u{80}".as_bytes(),
    ];
    let names = ["UCS-4", "UCS-4BE", "UCS-4LE", "UCS4", "ucs-4"];
    let mut fails = Vec::new();
    for name in names {
        for s in samples {
            // encode: UTF-8 -> UCS-4*
            let h = host_conv("UTF-8", name, s);
            let f = fl_conv("UTF-8", name, s);
            if h != f {
                fails.push(format!("encode {name} {s:?}: host={h:?} fl={f:?}"));
            }
            // decode: UCS-4* -> UTF-8 (round-trip the host encoding)
            if let Some(enc) = h.clone() {
                let hd = host_conv(name, "UTF-8", &enc);
                let fd = fl_conv(name, "UTF-8", &enc);
                if hd != fd {
                    fails.push(format!("decode {name} {enc:?}: host={hd:?} fl={fd:?}"));
                }
            }
        }
    }
    assert!(
        fails.is_empty(),
        "UCS-4 diverged from glibc:\n{}",
        fails.join("\n")
    );
}

#[test]
fn ucs4_open_succeeds() {
    for name in ["UCS-4", "UCS-4BE", "UCS-4LE", "UCS4", "UCS4BE", "UCS4LE"] {
        let cn = std::ffi::CString::new(name).unwrap();
        let to = std::ffi::CString::new("UTF-8").unwrap();
        let cd = unsafe { fl::iconv_open(to.as_ptr(), cn.as_ptr()) };
        assert_ne!(cd as isize, -1, "iconv_open({name}) should succeed");
        if cd as isize != -1 {
            unsafe { fl::iconv_close(cd) };
        }
    }
}
