//! Differential gate: charset-name aliases glibc accepts that fl previously
//! rejected (for already-implemented codecs): L3->ISO-8859-3, L4->ISO-8859-4,
//! ISO_8859-1:1987->ISO-8859-1. Each must open AND convert identically to glibc.
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
type ConvFn =
    extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;

fn g_funcs() -> (OpenFn, ConvFn) {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!h.is_null());
        (
            std::mem::transmute(dlsym(h, c"iconv_open".as_ptr())),
            std::mem::transmute(dlsym(h, c"iconv".as_ptr())),
        )
    }
}
fn decode_all(open: OpenFn, conv: ConvFn, name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = open(c"UTF-32LE".as_ptr(), cn.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {name}");
    (0u16..256)
        .map(|b| {
            let mut inb = [b as u8];
            let mut out = [0u8; 4];
            let mut ip = inb.as_mut_ptr() as *mut c_char;
            let mut il = 1usize;
            let mut op = out.as_mut_ptr() as *mut c_char;
            let mut ol = 4usize;
            let r = conv(cd, &mut ip, &mut il, &mut op, &mut ol);
            if r == INVALID || il != 0 {
                None
            } else {
                Some(out[0] as u32 | (out[1] as u32) << 8 | (out[2] as u32) << 16)
            }
        })
        .collect()
}
fn fl_decode_all(name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    (0u16..256)
        .map(|b| {
            let mut inb = [b as u8];
            let mut out = [0u8; 4];
            let mut ip = inb.as_mut_ptr() as *mut c_char;
            let mut il = 1usize;
            let mut op = out.as_mut_ptr() as *mut c_char;
            let mut ol = 4usize;
            let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
            if r == INVALID || il != 0 {
                None
            } else {
                Some(out[0] as u32 | (out[1] as u32) << 8 | (out[2] as u32) << 16)
            }
        })
        .collect()
}

#[test]
fn latin_aliases_open_and_match_glibc() {
    let (gopen, gconv) = g_funcs();
    for name in ["L3", "L4", "ISO_8859-1:1987"] {
        let g = decode_all(gopen, gconv, name);
        let f = fl_decode_all(name);
        assert_eq!(f, g, "alias {name} decodes differently from glibc");
    }
}
