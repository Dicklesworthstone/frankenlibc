//! Differential gate: pure TIS-620 iconv codec vs glibc, distinct from CP874.
//!
//! glibc's TIS-620 is the ISO Thai set (TIS 620-2533) and leaves 0x80-0xA0
//! UNDEFINED, whereas CP874/WINDOWS-874 maps the Windows extras (0x80->U+20AC,
//! 0xA0->U+00A0, ...). fl previously aliased TIS-620 onto its CP874 codec, so it
//! wrongly accepted those bytes. fl now has a dedicated TIS-620 codec; this
//! verifies it matches the live host glibc over the full byte range / BMP, both
//! directions, and that CP874 stays distinct.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::iconv_abi as fl;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const INVALID: usize = usize::MAX;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type OpenFn = extern "C" fn(*const c_char, *const c_char) -> *mut c_void;
type ConvFn = extern "C" fn(*mut c_void, *mut *mut c_char, *mut usize, *mut *mut c_char, *mut usize) -> usize;

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
fn tis620_matches_glibc_full_range() {
    let (gopen, gconv) = g_funcs();

    // Decode: every byte.
    let gcd = gopen(c"UTF-8".as_ptr(), c"TIS-620".as_ptr());
    assert!(gcd as usize != INVALID, "glibc TIS-620 open failed");
    let fcd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), c"TIS-620".as_ptr()) };
    assert!(fcd as usize != INVALID && !fcd.is_null(), "fl TIS-620 open failed");
    let mut mism = 0u64;
    let mut first = String::new();
    for b in 0u16..256 {
        let inp = [b as u8];
        let g = conv_g(gconv, gcd, &inp);
        let f = conv_f(fcd, &inp);
        if g != f {
            mism += 1;
            if first.is_empty() {
                first = format!("decode byte {b:#04x}: glibc={g:02x?} fl={f:02x?}");
            }
        }
    }
    // Encode: every BMP scalar.
    let gce = gopen(c"TIS-620".as_ptr(), c"UTF-8".as_ptr());
    let fce = unsafe { fl::iconv_open(c"TIS-620".as_ptr(), c"UTF-8".as_ptr()) };
    for cp in 0u32..0x10000 {
        if (0xD800..=0xDFFF).contains(&cp) {
            continue;
        }
        let ch = char::from_u32(cp).unwrap();
        let mut buf = [0u8; 4];
        let utf8 = ch.encode_utf8(&mut buf).as_bytes();
        let g = conv_g(gconv, gce, utf8);
        let f = conv_f(fce, utf8);
        if g != f {
            mism += 1;
            if first.is_empty() {
                first = format!("encode U+{cp:04X}: glibc={g:02x?} fl={f:02x?}");
            }
        }
    }
    assert_eq!(mism, 0, "TIS-620 diverged from glibc ({mism}); first: {first}");
}

#[test]
fn tis620_distinct_from_cp874() {
    // fl TIS-620 must REJECT 0x80 (€ in CP874) and 0xA0 (NBSP in CP874).
    let tis = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), c"TIS-620".as_ptr()) };
    assert!(tis as usize != INVALID && !tis.is_null());
    for b in [0x80u8, 0x85, 0xA0] {
        assert!(conv_f(tis, &[b]).is_none(), "TIS-620 must reject byte {b:#04x}");
    }
    // CP874 still maps them.
    let cp = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), c"CP874".as_ptr()) };
    assert!(cp as usize != INVALID && !cp.is_null());
    assert!(conv_f(cp, &[0x80]).is_some(), "CP874 must still map 0x80 (€)");
    // The shared Thai block matches.
    assert_eq!(conv_f(tis, &[0xA1]), conv_f(cp, &[0xA1]), "Thai block must agree");
}
