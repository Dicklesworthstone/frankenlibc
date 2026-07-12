//! Differential gate vs live host glibc for three charsets fl previously
//! rejected (found by the iconv name-coverage probe):
//!   * ISO/TR_11548-1 (Unicode Braille): byte b <-> U+2800+b, all 256 bytes;
//!     encode rejects any non-Braille scalar;
//!   * UNICODE: glibc's UCS-2 + BOM charset (BMP-only — astral unrepresentable,
//!     surrogate code units illegal; LE default with BOM-resolved endianness);
//!   * OSF100203B5: an OSF registry alias for 7-bit ASCII.
//! glibc is reached via dlsym so its symbols bypass fl's no_mangle interposition.
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

/// A complete conversion (single `iconv` call): `None` if the descriptor is
/// rejected or the call signals an irreversible error (EILSEQ/EINVAL).
fn g_full(g: &Glibc, to: &str, from: &str, input: &[u8]) -> Option<Vec<u8>> {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = (g.open)(ct.as_ptr(), cf.as_ptr());
    if cd as usize == INVALID {
        return None;
    }
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 4096];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = (g.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    (g.close)(cd);
    if r == INVALID {
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
    let mut out = vec![0u8; 4096];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == INVALID {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}

#[test]
fn braille_decode_all_bytes() {
    let g = glibc();
    let mut mism = Vec::new();
    // Every single byte, plus the whole 0..256 range as one stream.
    for b in 0u16..256 {
        let inp = [b as u8];
        if g_full(&g, "UTF-32LE", "ISO/TR_11548-1", &inp)
            != f_full("UTF-32LE", "ISO/TR_11548-1", &inp)
        {
            mism.push(format!("decode byte {b:02x}"));
        }
    }
    let all: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    if g_full(&g, "UTF-32LE", "ISO/TR_11548-1", &all) != f_full("UTF-32LE", "ISO/TR_11548-1", &all)
    {
        mism.push("full 0..256 stream".into());
    }
    assert!(mism.is_empty(), "Braille decode diverged: {mism:?}");
}

#[test]
fn braille_encode_block_and_reject() {
    let g = glibc();
    let mut mism = Vec::new();
    // The entire U+2800-U+28FF Braille block, one code point at a time.
    for cp in 0x2800u32..=0x28FF {
        let s = char::from_u32(cp).unwrap().to_string();
        if g_full(&g, "ISO/TR_11548-1", "UTF-8", s.as_bytes())
            != f_full("ISO/TR_11548-1", "UTF-8", s.as_bytes())
        {
            mism.push(format!("encode U+{cp:04X}"));
        }
    }
    // The whole block as one stream.
    let block: String = (0x2800u32..=0x28FF)
        .map(|c| char::from_u32(c).unwrap())
        .collect();
    if g_full(&g, "ISO/TR_11548-1", "UTF-8", block.as_bytes())
        != f_full("ISO/TR_11548-1", "UTF-8", block.as_bytes())
    {
        mism.push("encode whole block stream".into());
    }
    // Non-Braille scalars must be rejected by both (EILSEQ -> None).
    for s in ["A", "0", "\u{27FF}", "\u{2900}", "\u{0BCD}", "\u{1F600}"] {
        let ge = g_full(&g, "ISO/TR_11548-1", "UTF-8", s.as_bytes());
        let fe = f_full("ISO/TR_11548-1", "UTF-8", s.as_bytes());
        if ge != fe {
            mism.push(format!("encode-reject {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    assert!(mism.is_empty(), "Braille encode diverged: {mism:?}");
}

#[test]
fn braille_alias_names_accepted() {
    // glibc accepts these three names for the module; fl must too (and agree).
    let g = glibc();
    let inp = [0x00u8, 0x41, 0x80, 0xFF];
    for name in ["ISO/TR_11548-1", "ISO11548-1", "ISO_11548-1"] {
        let gr = g_full(&g, "UTF-32LE", name, &inp);
        let fr = f_full("UTF-32LE", name, &inp);
        assert_eq!(gr, fr, "Braille alias {name} diverged");
        assert!(gr.is_some(), "glibc unexpectedly rejected {name}");
    }
}

#[test]
fn unicode_ucs2_bom_matches_glibc() {
    let g = glibc();
    let mut mism = Vec::new();
    // Encode side: BMP text (with BOM), empty, and astral (must be rejected by
    // both — glibc's UNICODE is UCS-2, not UTF-16).
    for s in [
        "",
        "A",
        "Hello, world!",
        "\u{20AC}\u{00FF}\u{0BCD}\u{FFFD}",
        "\u{1F600}",
        "ab\u{1F4A9}cd",
    ] {
        let ge = g_full(&g, "UNICODE", "UTF-8", s.as_bytes());
        let fe = f_full("UNICODE", "UTF-8", s.as_bytes());
        if ge != fe {
            mism.push(format!("encode {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    // Decode side: LE BOM, BE BOM, no BOM (native LE), and a lone surrogate code
    // unit (illegal in UCS-2 -> both reject).
    let cases: &[&[u8]] = &[
        &[0xFF, 0xFE, 0x41, 0x00, 0xAC, 0x20], // LE BOM + A + euro
        &[0xFE, 0xFF, 0x00, 0x41, 0x20, 0xAC], // BE BOM + A + euro
        &[0x41, 0x00, 0x42, 0x00],             // no BOM (native LE)
        &[0xFF, 0xFE, 0x3D, 0xD8, 0x00, 0xDE], // LE BOM + surrogate pair (illegal)
        &[0x3D, 0xD8],                         // lone high surrogate (illegal)
    ];
    for inp in cases {
        let gr = g_full(&g, "UTF-8", "UNICODE", inp);
        let fr = f_full("UTF-8", "UNICODE", inp);
        if gr != fr {
            mism.push(format!("decode {inp:02x?}: glibc={gr:02x?} fl={fr:02x?}"));
        }
    }
    assert!(mism.is_empty(), "UNICODE diverged: {mism:?}");
}

#[test]
fn osf100203b5_matches_ascii() {
    let g = glibc();
    let mut mism = Vec::new();
    // Decode every byte (0x80+ is illegal in 7-bit ASCII -> None on both).
    for b in 0u16..256 {
        let inp = [b as u8];
        if g_full(&g, "UTF-32LE", "OSF100203B5", &inp) != f_full("UTF-32LE", "OSF100203B5", &inp) {
            mism.push(format!("decode byte {b:02x}"));
        }
    }
    // Encode ASCII text.
    let txt = b"The quick brown fox.";
    if g_full(&g, "OSF100203B5", "UTF-8", txt) != f_full("OSF100203B5", "UTF-8", txt) {
        mism.push("encode ascii text".into());
    }
    assert!(mism.is_empty(), "OSF100203B5 diverged: {mism:?}");
}
