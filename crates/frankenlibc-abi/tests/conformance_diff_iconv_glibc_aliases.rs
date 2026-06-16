//! Differential gate: supplemental glibc charset-name aliases for codecs fl
//! already implements (IBM/CS/OSF/Lxx designations + ISO versioned spellings).
//! A charset-name probe (fl::iconv_open vs the live host glibc) found these names
//! glibc accepts for codecs whose full byte signature is identical to an fl codec
//! but which fl previously rejected. Each must (1) open on fl, and (2) convert
//! BYTE-FOR-BYTE identically to the live host glibc in BOTH directions:
//!   * decode: every input byte 0x00..=0xFF -> UTF-32LE
//!   * encode: every codepoint that decoded -> back to the codec
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

// Decode every byte 0x00..=0xFF of `name` to UTF-32LE via glibc.
fn g_decode(gg: &G, name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(c"UTF-32LE".as_ptr(), cn.as_ptr());
    assert!(cd as usize != INVALID, "glibc rejects {name}");
    let sig = (0u16..256)
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
                Some(
                    out[0] as u32
                        | (out[1] as u32) << 8
                        | (out[2] as u32) << 16
                        | (out[3] as u32) << 24,
                )
            }
        })
        .collect();
    (gg.close)(cd);
    sig
}
fn fl_decode(name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    let sig = (0u16..256)
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
                Some(
                    out[0] as u32
                        | (out[1] as u32) << 8
                        | (out[2] as u32) << 16
                        | (out[3] as u32) << 24,
                )
            }
        })
        .collect();
    unsafe { fl::iconv_close(cd) };
    sig
}

// Encode one codepoint (as UTF-8) to `name` via glibc; None = unrepresentable.
fn g_encode(gg: &G, name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = (gg.open)(cn.as_ptr(), c"UTF-8".as_ptr());
    assert!(cd as usize != INVALID);
    let mut s = String::new();
    s.push(c);
    let mut src = s.into_bytes();
    let mut out = [0u8; 16];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 16usize;
    let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    (gg.close)(cd);
    if r == INVALID {
        None
    } else {
        Some(out[..16 - ol].to_vec())
    }
}
fn fl_encode(name: &str, cp: u32) -> Option<Vec<u8>> {
    let c = char::from_u32(cp)?;
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(cn.as_ptr(), c"UTF-8".as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null());
    let mut s = String::new();
    s.push(c);
    let mut src = s.into_bytes();
    let mut out = [0u8; 16];
    let mut ip = src.as_mut_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = 16usize;
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r == INVALID {
        None
    } else {
        Some(out[..16 - ol].to_vec())
    }
}

// The same supplemental aliases wired into the codec (raw spellings as a program
// would pass them, not the internal normalized form).
const ALIASES: &[&str] = &[
    "OS2LATIN1",
    "CSIBM1124",
    "IBM848",
    "RUSCII",
    "CSIBM1129",
    "CSIBM11621162",
    "CSIBM1163",
    "CP9448",
    "CSIBM9448",
    "IBM-9448",
    "OSF100201B5",
    "OSF10020352",
    "OSF10020354",
    "OSF10020357",
    "OSF10020359",
    "CSPC858MULTILINGUAL",
    "CPIBM861",
    "OSF1002035D",
    "OSF1002035E",
    "OSF1002035F",
    "866NAV",
    "CP-AR",
    "OSF10020364",
    "CP-GR",
    "OSF10020365",
    "IBM874",
    "CP-HU",
    "CSDECMCS",
    "OSF10010004",
    "OSF10010001",
    "R9",
    "OSF10010006",
    "CSIBM901",
    "CSIBM902",
    "OSF00010001",
    "ISO_8859-10:1992",
    "OSF0001000A",
    "CP921",
    "CSIBM921",
    "IBM-921",
    "ISO_8859-14:1998",
    "L8",
    "ISO_8859-15:1998",
    "ISO_8859-16:2001",
    "L10",
    "ISO_8859-2:1987",
    "OSF00010002",
    "ISO_8859-3:1988",
    "OSF00010003",
    "ISO_8859-4:1988",
    "OSF00010004",
    "ISO_8859-5:1988",
    "OSF00010005",
    "ISO_8859-6:1987",
    "OSF00010006",
    "ISO_8859-7:1987",
    "ISO_8859-7:2003",
    "OSF00010007",
    "ISO_8859-8:1988",
    "OSF00010008",
    "ISO_8859-9:1989",
    "OSF00010009",
    "TS-5881",
    "CSIBM1167",
    "CP1282",
    "TIS620.2529-1",
    "TIS620.2533-0",
    "OSF0005000A",
];

#[test]
fn glibc_aliases_open_and_match_both_directions() {
    let gg = g();
    for &name in ALIASES {
        let gd = g_decode(&gg, name);
        let fd = fl_decode(name);
        assert_eq!(fd, gd, "decode signature for alias {name} differs from glibc");

        // Encode direction: every codepoint that decoded must re-encode to the
        // same bytes on fl and glibc.
        for cp in gd.iter().flatten().copied() {
            let ge = g_encode(&gg, name, cp);
            let fe = fl_encode(name, cp);
            assert_eq!(fe, ge, "encode of U+{cp:04X} for alias {name} differs from glibc");
        }
    }
}
