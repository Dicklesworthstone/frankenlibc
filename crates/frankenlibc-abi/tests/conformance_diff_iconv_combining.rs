//! Differential gate: combining-aware single-byte codecs CP1255 (Hebrew), TCVN
//! and CP1258 (Vietnamese). glibc's DECODE for these BUFFERS a base letter until
//! flush (pending a possible following combining mark) but emits in input order
//! WITHOUT reordering — so fl's stateless per-byte decode is byte-exact for
//! streams. glibc's ENCODE decomposes precomposed code points into multi-byte
//! (base + combining) sequences, handled by encode_sbcs_mb. This gate flushes the
//! glibc side (NULL inbuf) so the buffered output is observable, then asserts fl
//! matches glibc byte-for-byte in both directions.
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

// glibc decode of one byte to UTF-32LE, WITH a final flush (NULL inbuf) so any
// buffered code points are emitted. Returns the produced code points.
fn g_decode_byte(gg: &G, name: &str, b: u8) -> Vec<u32> {
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(c"UTF-32LE".as_ptr(), cn.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {name}");
    let mut inb = [b];
    let mut out = [0u8; 64];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = 1usize;
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 64usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    // flush
    let mut np: *mut c_char = std::ptr::null_mut();
    let _ = (gg.conv)(cd, &mut np, &mut 0usize, &mut op, &mut ol);
    (gg.close)(cd);
    if r == INVALID && il != 0 {
        return vec![]; // EILSEQ / EINVAL on the byte itself
    }
    let n = 64 - ol;
    (0..n / 4).map(|i| u32::from_le_bytes([out[i*4], out[i*4+1], out[i*4+2], out[i*4+3]])).collect()
}
fn fl_decode_byte(name: &str, b: u8) -> Vec<u32> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    let mut inb = [b];
    let mut out = [0u8; 64];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = 1usize;
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 64usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == INVALID && il != 0 {
        return vec![];
    }
    let n = 64 - ol;
    (0..n / 4).map(|i| u32::from_le_bytes([out[i*4], out[i*4+1], out[i*4+2], out[i*4+3]])).collect()
}

fn g_encode(gg: &G, name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(cn.as_ptr(), c"UTF-8".as_ptr());
    assert!(cd as usize != INVALID);
    let mut src = c.to_string().into_bytes();
    let mut out = [0u8; 16];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 16usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    let mut np: *mut c_char = std::ptr::null_mut();
    let _ = (gg.conv)(cd, &mut np, &mut 0usize, &mut op, &mut ol);
    (gg.close)(cd);
    (r != INVALID && il == 0).then(|| out[..16 - ol].to_vec())
}
fn fl_encode(name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(cn.as_ptr(), c"UTF-8".as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null());
    let mut src = c.to_string().into_bytes();
    let mut out = [0u8; 16];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 16usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    (r != INVALID && il == 0).then(|| out[..16 - ol].to_vec())
}

const CODECS: &[&str] = &["CP1255", "TCVN", "CP1258"];

#[test]
fn combining_codecs_decode_match_glibc() {
    let gg = g();
    for &name in CODECS {
        for b in 0u16..256 {
            assert_eq!(
                fl_decode_byte(name, b as u8),
                g_decode_byte(&gg, name, b as u8),
                "{name} decode byte {b:#04x} differs from glibc"
            );
        }
    }
}

#[test]
fn combining_codecs_encode_match_glibc() {
    let gg = g();
    for &name in CODECS {
        for cp in 0u32..=0xFFFF {
            if (0xD800..=0xDFFF).contains(&cp) {
                continue;
            }
            assert_eq!(
                fl_encode(name, cp),
                g_encode(&gg, name, cp),
                "{name} encode U+{cp:04X} differs from glibc"
            );
        }
    }
}
