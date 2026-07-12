//! Differential gate: ISO-2022-KR iconv codec vs glibc (both directions).
//!
//! ISO-2022-KR (RFC 1557): `ESC $ ) C` designator at stream start, SO (0x0E)
//! shifts into KSC 5601 double-byte (= EUC-KR with the high bit cleared), SI
//! (0x0F) returns to ASCII; the reset call (NULL inbuf) emits a trailing SI if
//! still shifted. fl previously had no codec for this name (iconv_open failed).
//! glibc is reached via dlsym so its symbols bypass fl's no_mangle interposition.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::iconv_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type OpenFn = extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type ConvFn =
    extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;
type CloseFn = extern "C" fn(*mut c_void) -> c_int;

struct Glibc {
    open: OpenFn,
    conv: ConvFn,
    close: CloseFn,
}

fn glibc() -> Glibc {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!h.is_null());
        Glibc {
            open: std::mem::transmute(dlsym(h, c"iconv_open".as_ptr())),
            conv: std::mem::transmute(dlsym(h, c"iconv".as_ptr())),
            close: std::mem::transmute(dlsym(h, c"iconv_close".as_ptr())),
        }
    }
}

const INVALID: usize = usize::MAX;

/// Full conversion via glibc: open, iconv the whole input, then flush (NULL).
fn g_convert(g: &Glibc, to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let ct = CString::new(to).unwrap();
    let cf = CString::new(from).unwrap();
    let cd = (g.open)(ct.as_ptr(), cf.as_ptr());
    if cd as usize == INVALID {
        return None;
    }
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 1024];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = (g.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    if r == INVALID {
        (g.close)(cd);
        return None;
    }
    // flush
    let r2 = (g.conv)(
        cd,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut op,
        &mut ol,
    );
    (g.close)(cd);
    if r2 == INVALID {
        return None;
    }
    let written = out.len() - ol;
    Some(out[..written].to_vec())
}

/// Full conversion via fl.
fn f_convert(to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let ct = CString::new(to).unwrap();
    let cf = CString::new(from).unwrap();
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    if cd as usize == INVALID || cd.is_null() {
        return None;
    }
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 1024];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    if r == INVALID {
        unsafe { fl::iconv_close(cd) };
        return None;
    }
    let r2 = unsafe {
        fl::iconv(
            cd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut op,
            &mut ol,
        )
    };
    unsafe { fl::iconv_close(cd) };
    if r2 == INVALID {
        return None;
    }
    let written = out.len() - ol;
    Some(out[..written].to_vec())
}

#[test]
fn iso2022kr_matches_glibc_both_directions() {
    let g = glibc();

    // UTF-8 sample strings (ASCII, Korean, mixed, punctuation, empty).
    let samples: &[&str] = &[
        "",
        "Hello, world!",
        "한국어",
        "A한B국C어D",
        "가나다라마바사",
        "안녕하세요",
        "Mix 한 123 글 ABC",
        "줄1\n줄2",
        "끝",
    ];

    let mut mismatches = Vec::new();

    for s in samples {
        let u = s.as_bytes();
        // ENCODE: UTF-8 -> ISO-2022-KR.
        let ge = g_convert(&g, "ISO-2022-KR", "UTF-8", u);
        let fe = f_convert("ISO-2022-KR", "UTF-8", u);
        if ge != fe {
            mismatches.push(format!("ENC {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
        }
        // DECODE: take glibc's ISO-2022-KR bytes, decode via both -> UTF-8.
        if let Some(enc) = ge {
            let gd = g_convert(&g, "UTF-8", "ISO-2022-KR", &enc);
            let fd = f_convert("UTF-8", "ISO-2022-KR", &enc);
            if gd != fd {
                mismatches.push(format!(
                    "DEC {s:?} (bytes {enc:02x?}): glibc={gd:02x?} fl={fd:02x?}"
                ));
            }
            // round-trip must recover the original UTF-8.
            if fd.as_deref() != Some(u) {
                mismatches.push(format!("ROUNDTRIP {s:?}: fl decoded={fd:02x?}"));
            }
        }
    }

    // Alias names must also open and convert identically.
    for alias in ["CSISO2022KR", "ISO2022KR"] {
        let fe = f_convert(alias, "UTF-8", "한".as_bytes());
        let ge = g_convert(&g, "ISO-2022-KR", "UTF-8", "한".as_bytes());
        if fe != ge {
            mismatches.push(format!("ALIAS {alias}: fl={fe:02x?} glibc={ge:02x?}"));
        }
    }

    assert!(
        mismatches.is_empty(),
        "ISO-2022-KR diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
