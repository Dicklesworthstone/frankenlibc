//! Differential gate: IBM-943 (CSIBM943) codec, byte-exact vs the live host
//! glibc. IBM-943 is a Shift_JIS variant glibc supports but fl previously
//! rejected; it is DISTINCT from CP932 (e.g. 0x8160 -> U+301C wave dash, not
//! U+FF5E). Verified over the FULL range in both directions:
//!   * decode: every 1-byte (0x00..=0xFF) and 2-byte (lead 0x80..=0xFF) input
//!     -> UTF-32LE, comparing decoded unit AND incomplete/EILSEQ classification;
//!   * encode: every BMP scalar -> IBM-943 bytes.
//! Also asserts the IBM943/IBM-943/CSIBM943 spellings all resolve, and that
//! IBM-943 genuinely diverges from CP932 (the 0x8160 discriminator).
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

fn dec_inputs() -> Vec<Vec<u8>> {
    let mut v = Vec::with_capacity(256 + 128 * 256);
    for b in 0u16..256 {
        v.push(vec![b as u8]);
    }
    for b0 in 0x80u16..=0xFF {
        for b1 in 0u16..256 {
            v.push(vec![b0 as u8, b1 as u8]);
        }
    }
    v
}

fn g_decode(gg: &G, name: &str, ins: &[Vec<u8>]) -> Vec<(u8, u32)> {
    let cn = CString::new(name).unwrap();
    ins.iter()
        .map(|inp| {
            let cd = (gg.open)(c"UTF-32LE".as_ptr(), cn.as_ptr());
            assert!(cd as usize != INVALID, "glibc rejects {name}");
            let mut src = inp.clone();
            let mut buf = [0u8; 16];
            let mut ip = src.as_mut_ptr() as *mut c_char;
            let mut il = src.len();
            let mut op = buf.as_mut_ptr() as *mut c_char;
            let mut ol = 16usize;
            let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
            (gg.close)(cd);
            if r != INVALID && 16 - ol == 4 && il == 0 {
                (1, u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
            } else {
                (0, il as u32)
            }
        })
        .collect()
}
fn fl_decode(name: &str, ins: &[Vec<u8>]) -> Vec<(u8, u32)> {
    let cn = CString::new(name).unwrap();
    ins.iter()
        .map(|inp| {
            let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
            assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
            let mut src = inp.clone();
            let mut buf = [0u8; 16];
            let mut ip = src.as_mut_ptr() as *mut c_char;
            let mut il = src.len();
            let mut op = buf.as_mut_ptr() as *mut c_char;
            let mut ol = 16usize;
            let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
            unsafe { fl::iconv_close(cd) };
            if r != INVALID && 16 - ol == 4 && il == 0 {
                (1, u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
            } else {
                (0, il as u32)
            }
        })
        .collect()
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

#[test]
fn ibm943_decode_matches_glibc() {
    let gg = g();
    let ins = dec_inputs();
    let gd = g_decode(&gg, "IBM943", &ins);
    let fd = fl_decode("IBM943", &ins);
    assert_eq!(fd, gd, "IBM943 decode map differs from glibc");
}

#[test]
fn ibm943_encode_matches_glibc() {
    let gg = g();
    for cp in 0u32..=0xFFFF {
        let ge = g_encode(&gg, "IBM943", cp);
        let fe = fl_encode("IBM943", cp);
        assert_eq!(fe, ge, "IBM943 encode of U+{cp:04X} differs from glibc");
    }
}

#[test]
fn ibm943_aliases_resolve_and_diverge_from_cp932() {
    // All three glibc spellings open on fl.
    for name in ["IBM943", "IBM-943", "CSIBM943"] {
        let cn = CString::new(name).unwrap();
        let cd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), cn.as_ptr()) };
        assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
        unsafe { fl::iconv_close(cd) };
    }
    // 0x8160 is the discriminator: IBM-943 -> U+301C, CP932 -> U+FF5E.
    let dec_one = |name: &str, bytes: &[u8]| -> Option<u32> {
        let cn = CString::new(name).unwrap();
        let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
        assert!(cd as usize != INVALID && !cd.is_null());
        let mut src = bytes.to_vec();
        let mut out = [0u8; 8];
        let mut ip = src.as_mut_ptr() as *mut c_char;
        let mut il = src.len();
        let mut op = out.as_mut_ptr() as *mut c_char;
        let mut ol = 8usize;
        let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
        unsafe { fl::iconv_close(cd) };
        (r != INVALID).then(|| u32::from_le_bytes([out[0], out[1], out[2], out[3]]))
    };
    assert_eq!(dec_one("IBM943", &[0x81, 0x60]), Some(0x301C));
    assert_eq!(dec_one("CP932", &[0x81, 0x60]), Some(0xFF5E));
}
