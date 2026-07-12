//! Differential gate: ISO-6937 / T.61 family combining-prefix 2-byte codecs
//! (ISO_6937, ISO_6937-2, T.61, ANSI_X3.110). glibc DECODE buffers a lone accent
//! prefix (0xC1-0xCF) until the next byte, so the gate flushes the glibc side;
//! a (prefix, letter) pair decodes to one precomposed code point and glibc ENCODE
//! decomposes precomposed cps back to prefix+letter. fl handles both via the
//! shared 2-byte DBCS primitives. Verified byte-for-byte vs the live host glibc:
//! all 256 single bytes, all 0xC0-0xCF prefix pairs (decode), and every reachable
//! code point (encode).
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
// glibc decode of a byte slice -> Vec<cp>, with a final flush.
fn gdec(gg: &G, name: &str, bytes: &[u8]) -> Vec<u32> {
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(c"UTF-32LE".as_ptr(), cn.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {name}");
    let mut src = bytes.to_vec();
    let mut out = [0u8; 64];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 64usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    let mut np: *mut c_char = std::ptr::null_mut();
    let _ = (gg.conv)(cd, &mut np, &mut 0usize, &mut op, &mut ol);
    (gg.close)(cd);
    if r == INVALID && il != 0 {
        return vec![u32::MAX];
    } // error marker
    let n = 64 - ol;
    (0..n / 4)
        .map(|i| u32::from_le_bytes([out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3]]))
        .collect()
}
fn fdec(name: &str, bytes: &[u8]) -> Vec<u32> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    let mut src = bytes.to_vec();
    let mut out = [0u8; 64];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 64usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == INVALID && il != 0 {
        return vec![u32::MAX];
    }
    let n = 64 - ol;
    (0..n / 4)
        .map(|i| u32::from_le_bytes([out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3]]))
        .collect()
}
fn genc(gg: &G, name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(cn.as_ptr(), c"UTF-8".as_ptr());
    assert!(cd as usize != INVALID);
    let mut s = c.to_string().into_bytes();
    let mut o = [0u8; 16];
    let mut ip = s.as_mut_ptr() as *mut c_char;
    let mut il = s.len();
    let mut op = o.as_mut_ptr() as *mut c_char;
    let mut ol = 16usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    let mut np: *mut c_char = std::ptr::null_mut();
    let _ = (gg.conv)(cd, &mut np, &mut 0usize, &mut op, &mut ol);
    (gg.close)(cd);
    (r != INVALID && il == 0).then(|| o[..16 - ol].to_vec())
}
fn fenc(name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(cn.as_ptr(), c"UTF-8".as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null());
    let mut s = c.to_string().into_bytes();
    let mut o = [0u8; 16];
    let mut ip = s.as_mut_ptr() as *mut c_char;
    let mut il = s.len();
    let mut op = o.as_mut_ptr() as *mut c_char;
    let mut ol = 16usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    (r != INVALID && il == 0).then(|| o[..16 - ol].to_vec())
}
const CODECS: &[&str] = &["ISO_6937", "ISO_6937-2", "T.61", "ANSI_X3.110"];
#[test]
fn iso6937_family_match_glibc() {
    let gg = g();
    for &name in CODECS {
        let mut cps = std::collections::BTreeSet::new();
        // single bytes
        for b in 0u16..256 {
            let inp = [b as u8];
            assert_eq!(
                fdec(name, &inp),
                gdec(&gg, name, &inp),
                "{name} decode {b:#04x}"
            );
            for &c in &gdec(&gg, name, &inp) {
                if c != u32::MAX && c >= 0x80 {
                    cps.insert(c);
                }
            }
        }
        // prefix pairs 0xC0-0xCF x 0..256
        for p in 0xC0u16..=0xCF {
            for l in 0u16..256 {
                let inp = [p as u8, l as u8];
                assert_eq!(
                    fdec(name, &inp),
                    gdec(&gg, name, &inp),
                    "{name} pair {p:#04x},{l:#04x}"
                );
                for &c in &gdec(&gg, name, &inp) {
                    if c != u32::MAX && c >= 0x80 {
                        cps.insert(c);
                    }
                }
            }
        }
        for cp in cps {
            assert_eq!(
                fenc(name, cp),
                genc(&gg, name, cp),
                "{name} encode U+{cp:04X}"
            );
        }
    }
}
