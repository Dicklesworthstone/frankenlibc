//! Differential gate: EUC-JISX0213 (EUC-JIS-2004) iconv codec vs glibc.
//!
//! Variable-length EUC: ASCII; SS2 (0x8E) + half-width kana; plane 1 (0xA1-0xFE
//! pairs); SS3 (0x8F) + plane 2 (astral); ~25 combining cells (two code points).
//! glibc is reached via dlsym so its symbols bypass fl's no_mangle interposition.
//!
//! Byte-for-byte against the live host glibc: decode every single byte, every
//! SS2 / plane-1 / SS3 sequence, and random multi-byte streams; encode
//! round-trip every decodable cell (astral + combining) plus curated samples.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
#![allow(dead_code)]

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
type CloseFn = extern "C" fn(*mut c_void) -> c_int;

struct Glibc {
    open: OpenFn,
    conv: ConvFn,
    close: CloseFn,
}
fn glibc() -> Glibc {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!h.is_null());
        Glibc {
            open: std::mem::transmute(dlsym(h, c"iconv_open".as_ptr())),
            conv: std::mem::transmute(dlsym(h, c"iconv".as_ptr())),
            close: std::mem::transmute(dlsym(h, c"iconv_close".as_ptr())),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Raw {
    errored: bool,
    in_left: usize,
    out: Vec<u8>,
}
fn g_raw(g: &Glibc, to: &str, from: &str, input: &[u8]) -> Raw {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = (g.open)(ct.as_ptr(), cf.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {from}->{to}");
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 8192];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = (g.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    (g.close)(cd);
    let w = out.len() - ol;
    Raw { errored: r == INVALID, in_left: il, out: out[..w].to_vec() }
}
fn f_raw(to: &str, from: &str, input: &[u8]) -> Raw {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {from}->{to}");
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 8192];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    let w = out.len() - ol;
    Raw { errored: r == INVALID, in_left: il, out: out[..w].to_vec() }
}
fn g_full(g: &Glibc, to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = (g.open)(ct.as_ptr(), cf.as_ptr());
    if cd as usize == INVALID {
        return None;
    }
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 8192];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = (g.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    if r == INVALID {
        (g.close)(cd);
        return None;
    }
    let r2 = (g.conv)(cd, std::ptr::null_mut(), std::ptr::null_mut(), &mut op, &mut ol);
    (g.close)(cd);
    if r2 == INVALID {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}
fn f_full(to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    if cd as usize == INVALID || cd.is_null() {
        return None;
    }
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 8192];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    if r == INVALID {
        unsafe { fl::iconv_close(cd) };
        return None;
    }
    let r2 = unsafe { fl::iconv(cd, std::ptr::null_mut(), std::ptr::null_mut(), &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r2 == INVALID {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}

const NAME: &str = "EUC-JISX0213";

#[test]
fn eucjisx0213_decode_matches_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    let mut cases: Vec<Vec<u8>> = Vec::new();
    for b in 0u16..256 {
        cases.push(vec![b as u8]); // single
        cases.push(vec![0x8E, b as u8]); // SS2
    }
    for b0 in 0xA1u16..=0xFE {
        for b1 in 0xA1u16..=0xFE {
            cases.push(vec![b0 as u8, b1 as u8]); // plane 1
            cases.push(vec![0x8F, b0 as u8, b1 as u8]); // SS3 plane 2
        }
    }
    for c in &cases {
        if g_raw(&g, "UTF-32LE", NAME, c) != f_raw("UTF-32LE", NAME, c) && mism.len() < 60 {
            mism.push(format!("{c:02x?}"));
        }
    }
    // random fuzz
    let mut state: u64 = 0xE_C_4a_2004;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let alpha: &[u8] = &[0x41, 0x8e, 0x8f, 0xa1, 0xa4, 0xf7, 0xfe, 0xc0, 0x40, 0x00, 0xdf];
    for _ in 0..15_000 {
        let len = 1 + next() % 8;
        let inp: Vec<u8> = (0..len)
            .map(|_| if next() & 1 == 0 { alpha[next() % alpha.len()] } else { (next() & 0xFF) as u8 })
            .collect();
        if g_raw(&g, "UTF-32LE", NAME, &inp) != f_raw("UTF-32LE", NAME, &inp) && mism.len() < 90 {
            mism.push(format!("{inp:02x?}"));
        }
    }
    assert!(mism.is_empty(), "EUC-JISX0213 decode diverged ({}): {}", mism.len(), mism.join(" "));
}

#[test]
fn eucjisx0213_encode_roundtrip_matches_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    let mut cells: Vec<Vec<u8>> = Vec::new();
    for b in 0u16..256 {
        cells.push(vec![b as u8]);
        cells.push(vec![0x8E, b as u8]);
    }
    for b0 in 0xA1u16..=0xFE {
        for b1 in 0xA1u16..=0xFE {
            cells.push(vec![b0 as u8, b1 as u8]);
            cells.push(vec![0x8F, b0 as u8, b1 as u8]);
        }
    }
    for c in &cells {
        if let Some(u) = g_full(&g, "UTF-8", NAME, c) {
            if !u.is_empty() && g_full(&g, NAME, "UTF-8", &u) != f_full(NAME, "UTF-8", &u) && mism.len() < 60 {
                mism.push(format!("re {c:02x?}"));
            }
        }
    }
    for s in ["", "Hello \u{00A5}", "日本語ｶﾅ", "\u{20089}\u{2A6B2}", "\u{304B}\u{309A}", "漢字ABC"] {
        let u = s.as_bytes();
        if g_full(&g, NAME, "UTF-8", u) != f_full(NAME, "UTF-8", u) {
            mism.push(format!("ENC {s:?}"));
        }
    }
    assert!(mism.is_empty(), "EUC-JISX0213 encode/roundtrip diverged ({}): {}", mism.len(), mism.join(" "));
}
