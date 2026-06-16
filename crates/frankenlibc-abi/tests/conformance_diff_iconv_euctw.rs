//! Differential gate: EUC-TW (CNS 11643) codec, byte-exact vs the live host
//! glibc. EUC-TW is a variable-length Taiwanese codec glibc supports but fl
//! previously rejected (bd-cus379). Verified against glibc over:
//!   * decode 1-byte (0x00..=0xFF), 2-byte G1 (lead 0x80..=0xFF), and 4-byte SS2
//!     (0x8E + plane 0xA1..=0xB0 + cell pairs) — value AND incomplete/EILSEQ;
//!   * decode of truncated/malformed SS2 prefixes (the tricky incomplete-vs-
//!     EILSEQ boundary: bad plane -> EILSEQ at 2 bytes, but cells deferred to 4);
//!   * encode every BMP + SIP (0..=0x2FFFF) scalar back to EUC-TW bytes.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::iconv_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const INVALID: usize = usize::MAX;
const NAME: &[u8] = b"EUC-TW\0";

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

// (1, cp) for one decoded unit; (0, remaining_input_bytes) otherwise — the
// remaining count distinguishes incomplete (all consumed-so-far) from EILSEQ.
fn g_dec(gg: &G, bytes: &[u8]) -> (u8, u32) {
    let cd = (gg.open)(c"UTF-32LE".as_ptr(), NAME.as_ptr() as *const c_char);
    assert!(cd as usize != INVALID, "glibc rejects EUC-TW");
    let mut src = bytes.to_vec();
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
}
fn fl_dec(bytes: &[u8]) -> (u8, u32) {
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), NAME.as_ptr() as *const c_char) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects EUC-TW");
    let mut src = bytes.to_vec();
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
}

fn g_enc(gg: &G, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cd = (gg.open)(NAME.as_ptr() as *const c_char, c"UTF-8".as_ptr());
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
fn fl_enc(cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cd = unsafe { fl::iconv_open(NAME.as_ptr() as *const c_char, c"UTF-8".as_ptr()) };
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
fn euctw_decode_1and2_byte_matches_glibc() {
    let gg = g();
    for b in 0u16..256 {
        let inp = [b as u8];
        assert_eq!(fl_dec(&inp), g_dec(&gg, &inp), "1-byte {b:#04x}");
    }
    for b0 in 0x80u16..=0xFF {
        for b1 in 0u16..256 {
            let inp = [b0 as u8, b1 as u8];
            assert_eq!(fl_dec(&inp), g_dec(&gg, &inp), "2-byte {b0:#04x},{b1:#04x}");
        }
    }
}

#[test]
fn euctw_decode_4byte_ss2_matches_glibc() {
    let gg = g();
    // Full SS2 cell space for every plane byte 0xA1..=0xB0.
    for pb in 0xA1u16..=0xB0 {
        for c1 in 0xA1u16..=0xFE {
            for c2 in 0xA1u16..=0xFE {
                let inp = [0x8E, pb as u8, c1 as u8, c2 as u8];
                assert_eq!(
                    fl_dec(&inp),
                    g_dec(&gg, &inp),
                    "SS2 {pb:#04x},{c1:#04x},{c2:#04x}"
                );
            }
        }
    }
}

#[test]
fn euctw_incomplete_and_malformed_edges_match_glibc() {
    let gg = g();
    // SS2 prefixes & malformed planes/cells: probe every plane byte at 1..=4 len
    // plus some malformed cell bytes, comparing the incomplete/EILSEQ outcome.
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for pb in 0u16..256 {
        cases.push(vec![0x8E]);
        cases.push(vec![0x8E, pb as u8]);
        for c1 in [0x20u8, 0xA1, 0xFE, 0xFF] {
            cases.push(vec![0x8E, pb as u8, c1]);
            for c2 in [0x20u8, 0xA1, 0xFE, 0xFF] {
                cases.push(vec![0x8E, pb as u8, c1, c2]);
            }
        }
    }
    // G1 lead truncation / malformed trail.
    for b0 in 0x80u16..256 {
        cases.push(vec![b0 as u8]);
        for b1 in [0x20u8, 0xA1, 0xFE, 0xFF] {
            cases.push(vec![b0 as u8, b1]);
        }
    }
    for inp in &cases {
        assert_eq!(fl_dec(inp), g_dec(&gg, inp), "edge {inp:02x?}");
    }
}

#[test]
fn euctw_encode_bmp_and_sip_matches_glibc() {
    let gg = g();
    for cp in 0u32..=0x2FFFF {
        if (0xD800..=0xDFFF).contains(&cp) {
            continue; // surrogates are not scalars
        }
        assert_eq!(fl_enc(cp), g_enc(&gg, cp), "encode U+{cp:04X}");
    }
}

#[test]
fn euctw_aliases_resolve() {
    for name in ["EUC-TW", "EUCTW", "eucTW", "CSEUCTW"] {
        let cn = CString::new(name).unwrap();
        let cd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), cn.as_ptr()) };
        assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
        unsafe { fl::iconv_close(cd) };
    }
}
