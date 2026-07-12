//! Differential gate: ISO-2022-JP-3 (RFC 2237) iconv codec vs glibc.
//!
//! ISO-2022-JP plus JIS X 0213 plane 1 (`ESC $ ( O` / `ESC $ ( Q` for the
//! 2000/2004 editions), plane 2 (`ESC $ ( P`, astral) and half-width kana
//! (`ESC ( I`). glibc is reached via dlsym so its symbols bypass fl's no_mangle
//! interposition.
//!
//! Byte-for-byte vs live glibc: per-codepoint encode sweep (pins designator +
//! ku-ten + the 2000/2004 O/Q choice), encode + round-trip on multi-script
//! samples (lazy designation switching), exhaustive structured decode of every
//! ku-ten under each designator, and a random decode fuzz.
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

const NAME: &str = "ISO-2022-JP-3";

#[test]
fn iso2022jp3_encode_per_codepoint() {
    let g = glibc();
    let mut cps: Vec<u32> = Vec::new();
    cps.extend(0x20u32..=0x7E);
    cps.push(0x00A5);
    cps.push(0x203E);
    cps.extend(0xFF61u32..=0xFF9F); // half-width kana
    cps.extend((0x3000u32..=0x9FA0).step_by(13)); // kana/kanji/0213 sample
    cps.extend([0x4FF1, 0x3402, 0x20089, 0x2A6B2, 0x304B]); // Q-char, ext-A, astral, combining base
    cps.extend((0x20000u32..=0x2A6B0).step_by(409)); // plane-2 astral sample
    let mut mism = Vec::new();
    let mut checked = 0u32;
    for &cp in &cps {
        let Some(ch) = char::from_u32(cp) else {
            continue;
        };
        let u = ch.to_string();
        let ge = g_full(&g, NAME, "UTF-8", u.as_bytes());
        let fe = f_full(NAME, "UTF-8", u.as_bytes());
        checked += 1;
        if ge != fe && mism.len() < 60 {
            mism.push(format!("U+{cp:04X}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "JP-3 per-codepoint encode diverged ({} of {checked}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022jp3_encode_roundtrip_samples() {
    let g = glibc();
    let samples: &[&str] = &[
        "",
        "Hello \u{00A5}",
        "日本語のテキスト",
        "\u{4FF1}日\u{4FF1}",         // 2004 (Q) + 0208 lazy-stay
        "\u{304B}\u{309A}日\u{3402}", // combining + 0208 + ext-A
        "\u{20089}漢字\u{2A6B2}",     // astral plane-2 + kanji
        "ｱｲｳ kana ＡＢＣ",
        "第1章\nＡ\n\u{4FF1}",
    ];
    let mut mism = Vec::new();
    for s in samples {
        let u = s.as_bytes();
        let ge = g_full(&g, NAME, "UTF-8", u);
        let fe = f_full(NAME, "UTF-8", u);
        if ge != fe {
            mism.push(format!("ENC {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
            continue;
        }
        if let Some(enc) = ge {
            let gd = g_full(&g, "UTF-8", NAME, &enc);
            let fd = f_full("UTF-8", NAME, &enc);
            if gd != fd {
                mism.push(format!("DEC {s:?}: glibc={gd:02x?} fl={fd:02x?}"));
            }
            if fd.as_deref() != Some(u) {
                mism.push(format!("ROUNDTRIP {s:?}: fl={fd:02x?}"));
            }
        }
    }
    for alias in ["ISO2022JP3", "CSISO2022JP3"] {
        if f_full(alias, "UTF-8", "日".as_bytes()) != g_full(&g, NAME, "UTF-8", "日".as_bytes()) {
            mism.push(format!("ALIAS {alias}"));
        }
    }
    assert!(
        mism.is_empty(),
        "JP-3 encode/roundtrip diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022jp3_decode_structured_and_fuzz() {
    let g = glibc();
    let mut mism = Vec::new();
    // every ku-ten under each multibyte designator + every kana byte + roman bytes
    let two: &[(&[u8], &str)] = &[
        (&[0x1B, 0x24, 0x42], "0208"),
        (&[0x1B, 0x24, 0x28, 0x4F], "p1O"),
        (&[0x1B, 0x24, 0x28, 0x51], "p1Q"),
        (&[0x1B, 0x24, 0x28, 0x50], "p2"),
    ];
    for (desig, name) in two {
        for b0 in 0x21u8..=0x7E {
            for b1 in 0x21u8..=0x7E {
                let mut inp = desig.to_vec();
                inp.extend_from_slice(&[b0, b1, 0x1B, 0x28, 0x42]);
                if g_raw(&g, "UTF-32LE", NAME, &inp) != f_raw("UTF-32LE", NAME, &inp)
                    && mism.len() < 40
                {
                    mism.push(format!("{name} {b0:02x}{b1:02x}"));
                }
            }
        }
    }
    for b in 0u16..256 {
        let kana = [0x1B, 0x28, 0x49, b as u8];
        if g_raw(&g, "UTF-32LE", NAME, &kana) != f_raw("UTF-32LE", NAME, &kana) && mism.len() < 60 {
            mism.push(format!("kana {b:02x}"));
        }
        let roman = [0x1B, 0x28, 0x4A, b as u8];
        if g_raw(&g, "UTF-32LE", NAME, &roman) != f_raw("UTF-32LE", NAME, &roman) && mism.len() < 80
        {
            mism.push(format!("roman {b:02x}"));
        }
        let ascii = [b as u8];
        if g_raw(&g, "UTF-32LE", NAME, &ascii) != f_raw("UTF-32LE", NAME, &ascii)
            && mism.len() < 100
        {
            mism.push(format!("ascii {b:02x}"));
        }
    }
    // random escape-stream fuzz
    let alpha: &[u8] = &[
        0x1B, 0x1B, 0x28, 0x24, 0x42, 0x4A, 0x49, 0x4F, 0x50, 0x51, 0x40, 0x21, 0x30, 0x41, 0x7E,
        0x5C, 0x20, 0x0A, 0x00, 0x80, 0xFF, 0x24, 0x77,
    ];
    let mut state: u64 = 0x2022_4a_50_03;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    for _ in 0..30_000 {
        let len = 1 + next() % 14;
        let inp: Vec<u8> = (0..len).map(|_| alpha[next() % alpha.len()]).collect();
        if g_raw(&g, "UTF-32LE", NAME, &inp) != f_raw("UTF-32LE", NAME, &inp) && mism.len() < 120 {
            mism.push(format!("{inp:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "JP-3 decode diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
