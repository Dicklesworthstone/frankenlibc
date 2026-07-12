//! Differential gate: single-byte codecs must return EILSEQ (not a U+FFFD
//! substitution) for undefined bytes, matching glibc's gconv without //TRANSLIT.
//! Several SBCS decoders had a leftover `if cp == 0xFFFF { Ok(U+FFFD) }` special
//! case that reported success for undefined bytes; CP1008/CP1046 (Arabic) byte
//! 0xFF is the witness — glibc returns EILSEQ there. This pins the corrected
//! behaviour: full 0x00..=0xFF decode is byte-identical to the live host glibc.
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

struct G {
    open: OpenFn,
    close: CloseFn,
    conv: ConvFn,
}
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
fn g_decode(gg: &G, name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(c"UTF-32LE".as_ptr(), cn.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {name}");
    let v = (0u16..256)
        .map(|b| {
            let mut inb = [b as u8];
            let mut out = [0u8; 8];
            let mut ip = inb.as_mut_ptr() as *mut c_char;
            let mut il = 1usize;
            let mut op = out.as_mut_ptr() as *mut c_char;
            let mut ol = 8usize;
            let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
            if r == INVALID || il != 0 {
                None
            } else {
                Some(u32::from_le_bytes([out[0], out[1], out[2], out[3]]))
            }
        })
        .collect();
    (gg.close)(cd);
    v
}
fn fl_decode(name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    let v = (0u16..256)
        .map(|b| {
            let mut inb = [b as u8];
            let mut out = [0u8; 8];
            let mut ip = inb.as_mut_ptr() as *mut c_char;
            let mut il = 1usize;
            let mut op = out.as_mut_ptr() as *mut c_char;
            let mut ol = 8usize;
            let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
            if r == INVALID || il != 0 {
                None
            } else {
                Some(u32::from_le_bytes([out[0], out[1], out[2], out[3]]))
            }
        })
        .collect();
    unsafe { fl::iconv_close(cd) };
    v
}

#[test]
fn undefined_bytes_eilseq_match_glibc() {
    let gg = g();
    // CP1008 / CP1046: byte 0xFF is undefined -> EILSEQ on glibc (was U+FFFD on fl).
    for name in ["CP1008", "CP1046"] {
        let fd = fl_decode(name);
        assert_eq!(fd, g_decode(&gg, name), "{name} decode differs from glibc");
        assert_eq!(
            fd[0xFF], None,
            "{name} byte 0xFF must be EILSEQ, not a substitution"
        );
    }
}
