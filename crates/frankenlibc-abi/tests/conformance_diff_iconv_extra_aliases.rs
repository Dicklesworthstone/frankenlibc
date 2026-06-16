//! Differential gate: a batch of byte-identical charset-name aliases glibc
//! accepts for already-implemented codecs but fl rejected — ASCII / EBCDIC pages
//! / CSN_369103 / TCVN designations (IBM/CS/OSF/ISO-IR spellings). Each alias was
//! verified by a full-256 decode-signature probe to be identical to its canonical
//! under glibc. The gate asserts (1) glibc treats alias and canonical identically
//! (semantic correctness of the mapping) and (2) fl resolves the alias to the
//! same codec as the canonical. It deliberately does NOT compare fl vs glibc on
//! the canonical itself — that is the job of each codec's own conformance gate.
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

struct G { open: OpenFn, close: CloseFn, conv: ConvFn }
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
    let v = (0u16..256).map(|b| {
        let mut inb = [b as u8]; let mut out = [0u8; 8];
        let mut ip = inb.as_mut_ptr() as *mut c_char; let mut il = 1usize;
        let mut op = out.as_mut_ptr() as *mut c_char; let mut ol = 8usize;
        let r = (gg.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
        if r == INVALID || il != 0 { None } else { Some(u32::from_le_bytes([out[0],out[1],out[2],out[3]])) }
    }).collect();
    (gg.close)(cd); v
}
fn fl_decode(name: &str) -> Vec<Option<u32>> {
    let cn = CString::new(name).unwrap();
    let cd = unsafe { fl::iconv_open(c"UTF-32LE".as_ptr(), cn.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {name}");
    let v = (0u16..256).map(|b| {
        let mut inb = [b as u8]; let mut out = [0u8; 8];
        let mut ip = inb.as_mut_ptr() as *mut c_char; let mut il = 1usize;
        let mut op = out.as_mut_ptr() as *mut c_char; let mut ol = 8usize;
        let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
        if r == INVALID || il != 0 { None } else { Some(u32::from_le_bytes([out[0],out[1],out[2],out[3]])) }
    }).collect();
    unsafe { fl::iconv_close(cd) }; v
}

const ALIASES: &[(&str, &str)] = &[
    ("ANSI_X3.4-1986", "ASCII"),
    ("CP891", "ASCII"),
    ("CP903", "ASCII"),
    ("CSIBM891", "ASCII"),
    ("CSIBM903", "ASCII"),
    ("IBM891", "ASCII"),
    ("IBM903", "ASCII"),
    ("ISO_646.IRV:1991", "ASCII"),
    ("OSF00010020", "ASCII"),
    ("OSF1002037B", "ASCII"),
    ("OSF10020387", "ASCII"),
    ("CP1070", "CP037"),
    ("CP282", "CP037"),
    ("OSF10020025", "CP037"),
    ("CSIBM1008", "CP1008"),
    ("1026", "CP1026"),
    ("OSF10020402", "CP1026"),
    ("1046", "CP1046"),
    ("1047", "CP1047"),
    ("OSF10020417", "CP1047"),
    ("CSIBM1161", "CP1161"),
    ("OSF10020111", "CP273"),
    ("OSF10020116", "CP278"),
    ("OSF10020118", "CP280"),
    ("CP1079", "CP284"),
    ("OSF1002011C", "CP284"),
    ("OSF1002011D", "CP285"),
    ("CP1081", "CP297"),
    ("OSF10020129", "CP297"),
    ("OSF100201A4", "CP420"),
    ("OSF100201A8", "CP424"),
    ("500", "CP500"),
    ("500V1", "CP500"),
    ("CP1084", "CP500"),
    ("OSF100201F4", "CP500"),
    ("CSIBM856", "CP856"),
    ("OSF10020360", "CP864"),
    ("OSF10020366", "CP870"),
    ("OSF10020367", "CP871"),
    ("EBCDIC-GREEK", "CP875"),
    ("OSF1002036B", "CP875"),
    ("OSF10020370", "CP880"),
    ("OSF10020388", "CP904"),
    ("CSISO139CSN369103", "CSN_369103"),
    ("ISO-IR-139", "CSN_369103"),
    ("OSF10020115", "EBCDIC-CP-DK"),
    ("TCVN-5712", "TCVN"),
    ("TCVN5712-1:1993", "TCVN"),
];

#[test]
fn extra_aliases_resolve_to_canonical() {
    let gg = g();
    for &(alias, canon) in ALIASES {
        // glibc: alias and canonical are the same codec (semantic correctness).
        assert_eq!(g_decode(&gg, alias), g_decode(&gg, canon), "glibc: {alias} != {canon}");
        // fl: opening the alias resolves to the same codec as the canonical.
        assert_eq!(fl_decode(alias), fl_decode(canon), "fl: alias {alias} != canonical {canon}");
    }
}
