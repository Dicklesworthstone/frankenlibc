//! Differential gate: ISO-646 7-bit national variants + related 7-bit/8-bit
//! SBCS codecs (DE/FR/GB/IT/ES/PT/NO/FI/JP/KSC5636/GREEK7/Braille/Sami/...),
//! newly added on the full-256 path (bd-4m80bw). Each must decode every byte
//! 0x00..=0xFF (glibc side flushed, in case of buffering) and encode every
//! reachable code point byte-for-byte vs the live host glibc.
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
fn gdb(gg: &G, name: &str, b: u8) -> Vec<u32> {
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(c"UTF-32LE".as_ptr(), cn.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {name}");
    let mut inb = [b];
    let mut out = [0u8; 64];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = 1usize;
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 64usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    let mut np: *mut c_char = std::ptr::null_mut();
    let _ = (gg.conv)(cd, &mut np, &mut 0usize, &mut op, &mut ol);
    (gg.close)(cd);
    if r == INVALID && il != 0 {
        return vec![];
    }
    let n = 64 - ol;
    (0..n / 4)
        .map(|i| u32::from_le_bytes([out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3]]))
        .collect()
}
fn fdb(name: &str, b: u8) -> Vec<u32> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    let mut inb = [b];
    let mut out = [0u8; 64];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = 1usize;
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 64usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == INVALID && il != 0 {
        return vec![];
    }
    let n = 64 - ol;
    (0..n / 4)
        .map(|i| u32::from_le_bytes([out[i * 4], out[i * 4 + 1], out[i * 4 + 2], out[i * 4 + 3]]))
        .collect()
}
fn ge(gg: &G, name: &str, cp: u32) -> Option<Vec<u8>> {
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
fn fe(name: &str, cp: u32) -> Option<Vec<u8>> {
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
const CODECS: &[&str] = &[
    "ARABIC7",
    "BRF",
    "CA",
    "CN",
    "CUBA",
    "DE",
    "DK",
    "E13B",
    "ES",
    "ES2",
    "FI",
    "FR",
    "GB",
    "GREEK7",
    "GREEK7OLD",
    "GREEKCCITT",
    "HU",
    "INIS",
    "INIS8",
    "ISO-IR-122",
    "ISO-IR-19",
    "ISO-IR-197",
    "ISO-IR-25",
    "ISO-IR-27",
    "ISO-IR-51",
    "ISO-IR-54",
    "ISO11548-1",
    "ISO_5428",
    "IT",
    "JP",
    "JP-OCR-B",
    "JS",
    "KOI-7",
    "KSC5636",
    "NATSDANO",
    "NATSSEFI",
    "NO",
    "NO2",
    "PT",
    "PT2",
    "SE2",
];
#[test]
fn iso646_family_match_glibc() {
    let gg = g();
    for &name in CODECS {
        let mut cps = std::collections::BTreeSet::new();
        for b in 0u16..256 {
            let fb = fdb(name, b as u8);
            let gb = gdb(&gg, name, b as u8);
            assert_eq!(fb, gb, "{name} decode byte {b:#04x}");
            for &cp in &gb {
                if cp >= 0x80 {
                    cps.insert(cp);
                }
            }
        }
        for cp in cps {
            assert_eq!(fe(name, cp), ge(&gg, name, cp), "{name} encode U+{cp:04X}");
        }
    }
}
