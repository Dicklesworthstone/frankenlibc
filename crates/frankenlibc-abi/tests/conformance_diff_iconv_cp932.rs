//! Differential gate: CP932 iconv codec must be byte-exact with glibc over the
//! FULL range, both directions.
//!
//! glibc's CP932/WINDOWS-31J/MS932 is the Microsoft Shift_JIS superset (NEC/IBM
//! extension rows, U+FF5E->0x8160, 0x5C->U+005C). fl previously aliased CP932
//! onto its pure-JIS ShiftJis codec, which rejects those. fl now has a dedicated
//! CP932 codec built from the host glibc tables; this verifies it matches glibc
//! decode (every single byte + every lead/trail pair) and encode (every BMP
//! scalar). glibc is reached via dlsym so its symbols bypass fl's interposition.
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

/// One conversion on a reusable (stateless) descriptor. Returns Some(output)
/// when fully converted with no error, None on any error/unconverted tail.
fn conv_g(conv: ConvFn, cd: *mut c_void, input: &[u8]) -> Option<Vec<u8>> {
    let mut inb = input.to_vec();
    let mut out = [0u8; 16];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = conv(cd, &mut ip, &mut il, &mut op, &mut ol);
    if r == INVALID || il != 0 {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}
fn conv_f(cd: *mut c_void, input: &[u8]) -> Option<Vec<u8>> {
    let mut inb = input.to_vec();
    let mut out = [0u8; 16];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    if r == INVALID || il != 0 {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}

#[test]
fn cp932_decode_matches_glibc_full_range() {
    let (gopen, gconv) = g_funcs();
    let gcd = gopen(c"UTF-8".as_ptr(), c"CP932".as_ptr());
    assert!(gcd as usize != INVALID, "glibc iconv_open CP932 failed");
    let fcd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), c"CP932".as_ptr()) };
    assert!(
        fcd as usize != INVALID && !fcd.is_null(),
        "fl iconv_open CP932 failed"
    );

    let mut mism = 0u64;
    let mut first = String::new();
    // Single bytes.
    for b in 0u16..256 {
        let inp = [b as u8];
        let g = conv_g(gconv, gcd, &inp);
        let f = conv_f(fcd, &inp);
        if g != f {
            mism += 1;
            if first.is_empty() {
                first = format!("byte {b:#04x}: glibc={g:02x?} fl={f:02x?}");
            }
        }
    }
    // Lead/trail pairs.
    for lead in 0x81u16..=0xFC {
        for trail in 0u16..256 {
            let inp = [lead as u8, trail as u8];
            let g = conv_g(gconv, gcd, &inp);
            let f = conv_f(fcd, &inp);
            // Note: glibc may treat a non-lead `lead` as single byte + leftover;
            // conv_* returns None unless the WHOLE 2 bytes convert, so both must
            // agree on full-pair conversion.
            if g != f {
                mism += 1;
                if first.is_empty() {
                    first = format!("pair {lead:#04x},{trail:#04x}: glibc={g:02x?} fl={f:02x?}");
                }
            }
        }
    }
    assert_eq!(
        mism, 0,
        "CP932 decode diverged from glibc ({mism}); first: {first}"
    );
}

#[test]
fn cp932_encode_matches_glibc_full_range() {
    let (gopen, gconv) = g_funcs();
    let gcd = gopen(c"CP932".as_ptr(), c"UTF-8".as_ptr());
    assert!(gcd as usize != INVALID);
    let fcd = unsafe { fl::iconv_open(c"CP932".as_ptr(), c"UTF-8".as_ptr()) };
    assert!(fcd as usize != INVALID && !fcd.is_null());

    let mut mism = 0u64;
    let mut first = String::new();
    for cp in 0u32..0x10000 {
        if (0xD800..=0xDFFF).contains(&cp) {
            continue; // surrogates are not scalars
        }
        let ch = char::from_u32(cp).unwrap();
        let mut buf = [0u8; 4];
        let utf8 = ch.encode_utf8(&mut buf).as_bytes();
        let g = conv_g(gconv, gcd, utf8);
        let f = conv_f(fcd, utf8);
        if g != f {
            mism += 1;
            if first.is_empty() {
                first = format!("U+{cp:04X}: glibc={g:02x?} fl={f:02x?}");
            }
        }
    }
    assert_eq!(
        mism, 0,
        "CP932 encode diverged from glibc ({mism}); first: {first}"
    );
}

#[test]
fn cp932_aliases_open() {
    for name in ["CP932", "MS932", "WINDOWS-31J", "SJIS-WIN"] {
        let cn = CString::new(name).unwrap();
        let cd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), cn.as_ptr()) };
        assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
        unsafe { fl::iconv_close(cd) };
    }
    // The pure-JIS names must NOT map U+FF5E (stay on Shift_JIS).
    let sj = unsafe { fl::iconv_open(c"SHIFT_JIS".as_ptr(), c"UTF-8".as_ptr()) };
    assert!(sj as usize != INVALID && !sj.is_null());
    let r = conv_f(sj, "～".as_bytes()); // U+FF5E
    assert!(r.is_none(), "SHIFT_JIS must reject U+FF5E (got {r:02x?})");
    unsafe { fl::iconv_close(sj) };
}
