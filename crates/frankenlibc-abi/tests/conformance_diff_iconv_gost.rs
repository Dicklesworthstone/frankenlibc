//! Differential gate: GOST 19768-74 (ISO-IR-153 / ST SEV 358-88) single-byte
//! Cyrillic codec, byte-exact vs the live host glibc. glibc supports it but fl
//! previously rejected it. Verified over the full byte range in both directions
//! plus the documented name aliases.
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

fn g_encode(gg: &G, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cd = (gg.open)(c"GOST_19768-74".as_ptr(), c"UTF-8".as_ptr());
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
fn fl_encode(cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cd = unsafe { fl::iconv_open(c"GOST_19768-74".as_ptr(), c"UTF-8".as_ptr()) };
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

#[test]
fn gost_decode_matches_glibc() {
    let gg = g();
    assert_eq!(fl_decode("GOST_19768-74"), g_decode(&gg, "GOST_19768-74"));
}

#[test]
fn gost_encode_matches_glibc() {
    let gg = g();
    // Cover the Cyrillic block + the few sparse cells + a swath of BMP.
    for cp in 0u32..=0x500 {
        assert_eq!(fl_encode(cp), g_encode(&gg, cp), "encode U+{cp:04X}");
    }
    for &cp in &[0x2116u32, 0x00AD, 0x00A0, 0x0451, 0x0401, 0x20AC, 0xFFFF] {
        assert_eq!(fl_encode(cp), g_encode(&gg, cp), "encode U+{cp:04X}");
    }
}

#[test]
fn gost_aliases_resolve_and_match() {
    let gg = g();
    let canon = fl_decode("GOST_19768-74");
    for name in [
        "GOST_19768-74",
        "GOST_19768",
        "ISO-IR-153",
        "ST_SEV_358-88",
        "CSISO153GOST1976874",
    ] {
        let cn = CString::new(name).unwrap();
        let cd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), cn.as_ptr()) };
        assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
        unsafe { fl::iconv_close(cd) };
        assert_eq!(fl_decode(name), canon, "alias {name} decodes differently");
        // and must match glibc for that exact spelling
        assert_eq!(fl_decode(name), g_decode(&gg, name), "alias {name} vs glibc");
    }
}
