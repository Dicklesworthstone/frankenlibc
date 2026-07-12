//! Differential gate: batch C of newly-added ASCII-compatible single-byte codecs
//! (bd-4tgqly) — CP904, CP922, CP4909, CP5347 — plus their
//! name aliases, each byte-exact vs the live host glibc in both directions:
//!   * decode every input byte 0x00..=0xFF -> UTF-32LE;
//!   * encode every codepoint that decoded -> back to the codec.
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

fn g_encode(gg: &G, name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(cn.as_ptr(), c"UTF-8".as_ptr());
    assert!(cd as usize != INVALID);
    let mut src = c.to_string().into_bytes();
    let mut out = [0u8; 8];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 8usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    (gg.close)(cd);
    (r != INVALID && il == 0).then(|| out[..8 - ol].to_vec())
}
fn fl_encode(name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(cn.as_ptr(), c"UTF-8".as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null());
    let mut src = c.to_string().into_bytes();
    let mut out = [0u8; 8];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 8usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    (r != INVALID && il == 0).then(|| out[..8 - ol].to_vec())
}

// (canonical, [aliases]) for each new batch-A codec.
const CODECS: &[(&str, &[&str])] = &[
    ("CP904", &["904", "IBM904", "CSIBM904"]),
    ("CP922", &["IBM922", "CSIBM922"]),
    ("CP4909", &["IBM4909", "CSIBM4909"]),
    ("CP5347", &["IBM5347", "CSIBM5347"]),
];

#[test]
fn sbcs_batch_c_decode_encode_matches_glibc() {
    let gg = g();
    for (canon, aliases) in CODECS {
        let gd = g_decode(&gg, canon);
        let fd = fl_decode(canon);
        assert_eq!(fd, gd, "{canon} decode differs from glibc");
        // Encode every reachable codepoint.
        for cp in gd.iter().flatten().copied() {
            if cp < 0x80 {
                continue;
            }
            assert_eq!(
                fl_encode(canon, cp),
                g_encode(&gg, canon, cp),
                "{canon} encode U+{cp:04X} differs from glibc"
            );
        }
        // Each alias opens on fl and decodes byte-identically to glibc + canonical.
        for &a in *aliases {
            assert_eq!(
                fl_decode(a),
                gd,
                "alias {a} decodes differently from {canon}"
            );
            assert_eq!(fl_decode(a), g_decode(&gg, a), "alias {a} vs glibc");
        }
    }
}
