//! Differential gate: BIG5-HKSCS (Big5 + Hong Kong supplementary) iconv codec vs glibc.
//!
//! ASCII + half-width kana single bytes, 2-byte JIS X 0213 planes 1/2 (plane 2
//! reaches the SIP, i.e. astral code points), and ~25 cells that decode to two
//! code points (kana/letter + combining mark). glibc is reached via dlsym so its
//! symbols bypass fl's no_mangle interposition.
//!
//! Byte-for-byte against the live host glibc:
//!   * decode every single byte and every 2-byte sequence (exact output bytes +
//!     consumed-prefix length), and pseudo-random multi-byte streams;
//!   * encode round-trip every decodable cell (covers astral + combining), plus
//!     curated samples; the SHIFTJISX0213 alias opens.
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
    Raw {
        errored: r == INVALID,
        in_left: il,
        out: out[..w].to_vec(),
    }
}
fn f_raw(to: &str, from: &str, input: &[u8]) -> Raw {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    assert!(
        cd as usize != INVALID && !cd.is_null(),
        "fl rejects {from}->{to}"
    );
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 8192];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    let w = out.len() - ol;
    Raw {
        errored: r == INVALID,
        in_left: il,
        out: out[..w].to_vec(),
    }
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
    let r2 = (g.conv)(
        cd,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        &mut op,
        &mut ol,
    );
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
    let r2 = unsafe {
        fl::iconv(
            cd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut op,
            &mut ol,
        )
    };
    unsafe { fl::iconv_close(cd) };
    if r2 == INVALID {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}

const NAME: &str = "BIG5-HKSCS";

#[test]
fn big5hkscs_decode_matches_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    for b in 0u16..256 {
        let inp = [b as u8];
        if g_raw(&g, "UTF-32LE", NAME, &inp) != f_raw("UTF-32LE", NAME, &inp) && mism.len() < 30 {
            mism.push(format!("sb {b:02x}"));
        }
    }
    for b0 in 0x81u16..=0xFC {
        for b1 in 0x00u16..256 {
            let inp = [b0 as u8, b1 as u8];
            if g_raw(&g, "UTF-32LE", NAME, &inp) != f_raw("UTF-32LE", NAME, &inp) && mism.len() < 60
            {
                mism.push(format!("db {b0:02x}{b1:02x}"));
            }
        }
    }
    // random multi-byte streams
    let mut state: u64 = 0x5_4a_15_2004;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let alpha: &[u8] = &[
        0x41, 0x5c, 0x7e, 0xa1, 0xdf, 0x81, 0x82, 0x9f, 0xe0, 0xf0, 0xfc, 0x40, 0x00,
    ];
    for _ in 0..15_000 {
        let len = 1 + next() % 8;
        let inp: Vec<u8> = (0..len)
            .map(|_| {
                if next() & 1 == 0 {
                    alpha[next() % alpha.len()]
                } else {
                    (next() & 0xFF) as u8
                }
            })
            .collect();
        if g_raw(&g, "UTF-32LE", NAME, &inp) != f_raw("UTF-32LE", NAME, &inp) && mism.len() < 90 {
            mism.push(format!("{inp:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "SHIFT_JISX0213 decode diverged ({}): {}",
        mism.len(),
        mism.join(" ")
    );
}

#[test]
fn big5hkscs_encode_roundtrip_matches_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    // round-trip every decodable single byte and 2-byte cell (covers astral and
    // the combining cells).
    for b in 0u16..256 {
        let inp = [b as u8];
        if let Some(u) = g_full(&g, "UTF-8", NAME, &inp) {
            if !u.is_empty()
                && g_full(&g, NAME, "UTF-8", &u) != f_full(NAME, "UTF-8", &u)
                && mism.len() < 30
            {
                mism.push(format!("re-sb {b:02x}"));
            }
        }
    }
    for b0 in 0x81u16..=0xFC {
        for b1 in 0x40u16..=0xFE {
            let inp = [b0 as u8, b1 as u8];
            if let Some(u) = g_full(&g, "UTF-8", NAME, &inp) {
                if g_full(&g, NAME, "UTF-8", &u) != f_full(NAME, "UTF-8", &u) && mism.len() < 60 {
                    mism.push(format!("re-db {b0:02x}{b1:02x}"));
                }
            }
        }
    }
    // curated samples (ASCII, Traditional Chinese, astral HKSCS, combining).
    for s in [
        "",
        "Hello, world",
        "中文字測試",
        "\u{23ED7}\u{20547}",
        "\u{00CA}\u{0304}\u{00EA}\u{030C}",
        "ABC漢字123",
    ] {
        let u = s.as_bytes();
        let ge = g_full(&g, NAME, "UTF-8", u);
        let fe = f_full(NAME, "UTF-8", u);
        if ge != fe {
            mism.push(format!("ENC {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    let fa = f_full("UTF-8", "BIG5HKSCS", &[0xA4u8, 0x40]);
    let gc = g_full(&g, "UTF-8", NAME, &[0xA4u8, 0x40]);
    assert_eq!(fa, gc, "alias BIG5HKSCS differs");
    assert!(
        mism.is_empty(),
        "BIG5-HKSCS encode/roundtrip diverged ({}): {}",
        mism.len(),
        mism.join(" ")
    );
}
