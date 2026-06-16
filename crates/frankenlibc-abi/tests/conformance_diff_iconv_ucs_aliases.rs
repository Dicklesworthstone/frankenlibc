//! Differential gate: ISO-10646 / UCS charset-name aliases glibc accepts for
//! codecs fl already implements (UCS-4 == UTF-32BE, ISO-10646/UCS2 == UCS-2LE),
//! probe-verified byte-identical in both directions. Each must open on fl and
//! convert (UTF-8 -> alias and alias -> UTF-8) byte-for-byte like the live host
//! glibc.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::iconv_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const INVALID: usize = usize::MAX;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type OpenFn = extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type CloseFn = extern "C" fn(*mut c_void) -> c_int;
type ConvFn =
    extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;

struct G { open: OpenFn, close: CloseFn, conv: ConvFn }
fn g() -> G {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!h.is_null());
        G {
            open: std::mem::transmute(dlsym(h, c"iconv_open".as_ptr())),
            close: std::mem::transmute(dlsym(h, c"iconv_close".as_ptr())),
            conv: std::mem::transmute(dlsym(h, c"iconv".as_ptr())),
        }
    }
}
fn conv(open: OpenFn, close: CloseFn, c: ConvFn, to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = open(ct.as_ptr(), cf.as_ptr());
    if cd as usize == INVALID { return None; }
    let mut src = input.to_vec();
    let mut out = vec![0u8; 256];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = c(cd, &mut ip, &mut il, &mut op, &mut ol);
    close(cd);
    if r == INVALID || il != 0 { return Some(vec![0xDE, 0xAD]); } // sentinel for error
    let n = out.len() - ol;
    out.truncate(n);
    Some(out)
}
fn gconv(gg: &G, to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    conv(gg.open, gg.close, gg.conv, to, from, input)
}
// fl side via direct iconv_abi
fn flconv(to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    if cd as usize == INVALID || cd.is_null() { return None; }
    let mut src = input.to_vec();
    let mut out = vec![0u8; 256];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == INVALID || il != 0 { return Some(vec![0xDE, 0xAD]); }
    let n = out.len() - ol;
    out.truncate(n);
    Some(out)
}

// (alias, has_astral) — UTF-32BE aliases handle astral; UCS-2 is BMP-only.
const ALIASES: &[(&str, bool)] = &[
    ("CSUCS4", true),
    ("10646-1:1993", true),
    ("10646-1:1993/UCS4", true),
    ("ISO-10646/UCS4", true),
    ("ISO-10646", true),
    ("ISO-10646/UCS2", false),
];

#[test]
fn ucs_aliases_match_glibc_both_directions() {
    let gg = g();
    for &(alias, astral) in ALIASES {
        // glibc must accept it (sanity) and fl must now too.
        let probe = CString::new(alias).unwrap();
        let fcd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), probe.as_ptr()) };
        assert!(fcd as usize != INVALID && !fcd.is_null(), "fl rejects {alias}");
        unsafe { fl::iconv_close(fcd) };

        let sample: &[u8] = if astral { "Aé€😀z".as_bytes() } else { "Aé€z".as_bytes() };
        // encode UTF-8 -> alias
        assert_eq!(
            flconv(alias, "UTF-8", sample),
            gconv(&gg, alias, "UTF-8", sample),
            "encode UTF-8->{alias} differs from glibc"
        );
        // decode alias -> UTF-8 (use glibc's own encoding of the sample as input)
        if let Some(enc) = gconv(&gg, alias, "UTF-8", sample) {
            assert_eq!(
                flconv("UTF-8", alias, &enc),
                gconv(&gg, "UTF-8", alias, &enc),
                "decode {alias}->UTF-8 differs from glibc"
            );
        }
    }
}
