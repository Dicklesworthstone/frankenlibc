//! Differential gate: CP037 (IBM-037, EBCDIC US/Canada) — the first NON-ASCII-low
//! single-byte codec (bd-4m80bw). EBCDIC remaps the ENTIRE byte range (including
//! the letter/digit positions), so the normal ASCII-low encode fast path is
//! disabled and it routes through decode_sbcs_full/encode_sbcs_full. Verified
//! byte-for-byte vs the live host glibc:
//!   * decode every byte 0x00..=0xFF (incl. the low half, which is NOT ASCII);
//!   * encode every BMP codepoint reachable by decode back to its EBCDIC byte;
//!   * all glibc name spellings resolve;
//!   * spot-check: 'A' encodes to 0xC1 (not 0x41) — proves the ASCII shortcut is
//!     correctly bypassed.
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
    let cd = (gg.open)(c"CP037".as_ptr(), c"UTF-8".as_ptr());
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
    let cd = unsafe { fl::iconv_open(c"CP037".as_ptr(), c"UTF-8".as_ptr()) };
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
fn cp037_decode_full_range_matches_glibc() {
    let gg = g();
    assert_eq!(fl_decode("CP037"), g_decode(&gg, "CP037"));
}

#[test]
fn cp037_encode_matches_glibc() {
    let gg = g();
    // Every BMP scalar: most are unrepresentable, the ~256 EBCDIC ones must match.
    for cp in 0u32..=0xFFFF {
        if (0xD800..=0xDFFF).contains(&cp) {
            continue;
        }
        assert_eq!(fl_encode(cp), g_encode(&gg, cp), "encode U+{cp:04X}");
    }
}

#[test]
fn cp037_ascii_shortcut_is_bypassed() {
    // The whole point of the non-ASCII-low path: 'A' (U+0041) must encode to the
    // EBCDIC byte 0xC1, not the ASCII byte 0x41.
    assert_eq!(fl_encode(0x41), Some(vec![0xC1]));
    assert_eq!(fl_encode(0x30), Some(vec![0xF0])); // '0' -> 0xF0
    // and 0x41 decodes to U+0041? No — EBCDIC byte 0x41 is U+00A0 (nbsp).
    assert_eq!(fl_decode("CP037")[0x41], Some(0x00A0));
}

#[test]
fn cp037_aliases_resolve_and_match() {
    let gg = g();
    let canon = fl_decode("CP037");
    for name in [
        "CP037", "IBM037", "CSIBM037", "EBCDIC-CP-US", "EBCDIC-CP-CA", "EBCDIC-CP-NL",
        "EBCDIC-CP-WT",
    ] {
        let cn = CString::new(name).unwrap();
        let cd = unsafe { fl::iconv_open(c"UTF-8".as_ptr(), cn.as_ptr()) };
        assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
        unsafe { fl::iconv_close(cd) };
        assert_eq!(fl_decode(name), canon, "alias {name} differs from CP037");
        assert_eq!(fl_decode(name), g_decode(&gg, name), "alias {name} vs glibc");
    }
}

fn g_encode_n(gg: &G, name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(cn.as_ptr(), c"UTF-8".as_ptr());
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
fn fl_encode_n(name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(cn.as_ptr(), c"UTF-8".as_ptr()) };
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

// Additional EBCDIC pages on the same full-256 path as CP037.
const MORE_EBCDIC: &[(&str, &[&str])] = &[
    ("CP500", &["IBM500", "CSIBM500", "EBCDIC-CP-BE", "EBCDIC-CP-CH"]),
    ("CP1047", &["IBM1047"]),
    ("CP1140", &["IBM1140", "CSIBM1140"]),
    ("CP273", &["CSIBM273", "IBM273"]),
    ("CP278", &["CSIBM278", "EBCDIC-CP-FI", "EBCDIC-CP-SE", "IBM278"]),
    ("CP280", &["CSIBM280", "EBCDIC-CP-IT", "IBM280"]),
    ("CP284", &["CSIBM284", "EBCDIC-CP-ES", "IBM284"]),
    ("CP285", &["CSIBM285", "EBCDIC-CP-GB", "IBM285"]),
    ("CP297", &["CSIBM297", "EBCDIC-CP-FR", "IBM297"]),
    ("CP871", &["CSIBM871", "EBCDIC-CP-IS", "IBM871"]),
    ("CP870", &["CSIBM870", "EBCDIC-CP-ROECE", "EBCDIC-CP-YU", "IBM870"]),
    ("CP875", &["IBM875"]),
    ("EBCDIC-CP-DK", &["CSIBM277", "EBCDIC-CP-NO", "IBM277"]),
    ("CP1025", &["CSIBM1025", "IBM-1025", "IBM1025"]),
    ("CP1026", &["CSIBM1026", "IBM1026"]),
    ("CP420", &["CSIBM420", "EBCDIC-CP-AR1", "IBM420"]),
    ("CP424", &["CSIBM424", "EBCDIC-CP-HE", "IBM424"]),
    ("CP880", &["CSIBM880", "EBCDIC-CYRILLIC", "IBM880"]),
    ("CP1112", &["CSIBM1112", "IBM-1112", "IBM1112"]),
    ("CP1122", &["CSIBM1122", "IBM-1122", "IBM1122"]),
    ("CP1123", &["CSIBM1123", "IBM-1123", "IBM1123"]),
    ("CP1130", &["CSIBM1130", "IBM-1130", "IBM1130"]),
    ("CP1132", &["CSIBM1132", "IBM-1132", "IBM1132"]),
    ("CP1137", &["CSIBM1137", "IBM-1137", "IBM1137"]),
    ("CP1141", &["CSIBM1141", "IBM-1141", "IBM1141"]),
    ("CP1142", &["CSIBM1142", "IBM-1142", "IBM1142"]),
    ("CP1143", &["CSIBM1143", "IBM-1143", "IBM1143"]),
    ("CP1144", &["CSIBM1144", "IBM-1144", "IBM1144"]),
    ("CP1145", &["CSIBM1145", "IBM-1145", "IBM1145"]),
    ("CP1146", &["CSIBM1146", "IBM-1146", "IBM1146"]),
    ("CP1147", &["CSIBM1147", "IBM-1147", "IBM1147"]),
    ("CP1148", &["CSIBM1148", "IBM-1148", "IBM1148"]),
    ("CP1149", &["CSIBM1149", "IBM-1149", "IBM1149"]),
    ("CP12712", &["CSIBM12712", "IBM-12712", "IBM12712"]),
    ("CP16804", &["CSIBM16804", "IBM-16804", "IBM16804"]),
    ("CP4517", &["CSIBM4517", "IBM-4517", "IBM4517"]),
    ("CP4971", &["CSIBM4971", "IBM-4971", "IBM4971"]),
];

#[test]
fn more_ebcdic_pages_match_glibc() {
    let gg = g();
    for (canon, aliases) in MORE_EBCDIC {
        let gd = g_decode(&gg, canon);
        assert_eq!(fl_decode(canon), gd, "{canon} decode differs from glibc");
        for cp in 0u32..=0xFFFF {
            if (0xD800..=0xDFFF).contains(&cp) {
                continue;
            }
            assert_eq!(
                fl_encode_n(canon, cp),
                g_encode_n(&gg, canon, cp),
                "{canon} encode U+{cp:04X} differs from glibc"
            );
        }
        for &a in *aliases {
            assert_eq!(fl_decode(a), gd, "alias {a} differs from {canon}");
            assert_eq!(fl_decode(a), g_decode(&gg, a), "alias {a} vs glibc");
        }
    }
}
