//! Differential gate: ISO-2022-CN iconv codec vs glibc (both directions).
//!
//! ISO-2022-CN (RFC 1922) is a stateful SO/SI codec. G1 (entered via SO 0x0E,
//! left via SI 0x0F) holds GB2312 (`ESC $ ) A`, the default) or CNS 11643
//! plane 1 (`ESC $ ) G`); G2 is CNS 11643 plane 2 (`ESC $ * H`, the default),
//! reached one char at a time via SS2 (`ESC N`). A newline (0x0A) resets the
//! line designations. glibc is reached through dlsym so its symbols bypass fl's
//! no_mangle interposition.
//!
//! Coverage is byte-for-byte against the live host glibc:
//!   * encode per-codepoint sweep over CJK / Traditional / ASCII — pins the
//!     GB2312 > CNS-1 > CNS-2 priority and designator choice;
//!   * encode + round-trip on multi-script samples — pins lazy G1 switching,
//!     SO/SI placement, the newline reset and the SI-on-flush behaviour;
//!   * decode exhaustive structured — every ku-ten pair under GB2312 and CNS-1
//!     (SO) and CNS-2 (SS2), every ASCII byte, the recognized designators;
//!   * decode unconstrained fuzz — pseudo-random streams biased toward the CN
//!     escape alphabet, comparing the EXACT single-call outcome (output bytes +
//!     consumed-prefix length).
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
    let mut out = vec![0u8; 4096];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = (g.conv)(cd, &mut ip, &mut il, &mut op, &mut ol);
    (g.close)(cd);
    let written = out.len() - ol;
    Raw {
        errored: r == INVALID,
        in_left: il,
        out: out[..written].to_vec(),
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
    let mut out = vec![0u8; 4096];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    let written = out.len() - ol;
    Raw {
        errored: r == INVALID,
        in_left: il,
        out: out[..written].to_vec(),
    }
}

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
    let mut out = vec![0u8; 4096];
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

#[test]
fn iso2022cn_encode_per_codepoint_matches_glibc() {
    let g = glibc();
    let mut cps: Vec<u32> = Vec::new();
    cps.extend(0x20u32..=0x7E); // ASCII
    cps.extend((0x4E00u32..=0x9FA0).step_by(7)); // CJK unified sample (GB2312/CNS)
    cps.extend((0x3400u32..=0x4DB0).step_by(31)); // CJK ext A (CNS planes)
    cps.extend([0x3000, 0x3001, 0x3002, 0xFF01, 0x2014, 0x2026, 0x00B7]);
    let mut mism = Vec::new();
    let mut checked = 0u32;
    for &cp in &cps {
        let Some(ch) = char::from_u32(cp) else {
            continue;
        };
        let u = ch.to_string();
        let ge = g_full(&g, "ISO-2022-CN", "UTF-8", u.as_bytes());
        let fe = f_full("ISO-2022-CN", "UTF-8", u.as_bytes());
        checked += 1;
        if ge != fe && mism.len() < 60 {
            mism.push(format!("U+{cp:04X}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "ISO-2022-CN per-codepoint encode diverged ({} of {checked}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022cn_encode_roundtrip_samples_match_glibc() {
    let g = glibc();
    let samples: &[&str] = &[
        "",
        "Hello, world!",
        "中文简体",
        "臺灣繁體中文",
        "GB中文 and CNS 臺灣 mixed ABC",
        "中A文B字",
        "第1行\n第2行\n第3行",
        "中\nA\n臺",
        "标点，。、；：",
    ];
    let mut mism = Vec::new();
    for s in samples {
        let u = s.as_bytes();
        let ge = g_full(&g, "ISO-2022-CN", "UTF-8", u);
        let fe = f_full("ISO-2022-CN", "UTF-8", u);
        if ge != fe {
            mism.push(format!("ENC {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
            continue;
        }
        if let Some(enc) = ge {
            let gd = g_full(&g, "UTF-8", "ISO-2022-CN", &enc);
            let fd = f_full("UTF-8", "ISO-2022-CN", &enc);
            if gd != fd {
                mism.push(format!(
                    "DEC {s:?} ({enc:02x?}): glibc={gd:02x?} fl={fd:02x?}"
                ));
            }
            if fd.as_deref() != Some(u) {
                mism.push(format!("ROUNDTRIP {s:?}: fl decoded={fd:02x?}"));
            }
        }
    }
    for alias in ["ISO2022CN", "CSISO2022CN"] {
        let fe = f_full(alias, "UTF-8", "中".as_bytes());
        let ge = g_full(&g, "ISO-2022-CN", "UTF-8", "中".as_bytes());
        if fe != ge {
            mism.push(format!("ALIAS {alias}: fl={fe:02x?} glibc={ge:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "ISO-2022-CN encode/roundtrip diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022cn_decode_exhaustive_structured() {
    let g = glibc();
    let mut mism = Vec::new();
    let mut checked = 0u32;

    // GB2312 (default G1) and CNS-1 (ESC $ ) G) via SO, then SI.
    let g1cases: &[(&[u8], &str)] = &[
        (&[0x1B, 0x24, 0x29, 0x41], "GB2312"),
        (&[0x1B, 0x24, 0x29, 0x47], "CNS1"),
    ];
    for (desig, name) in g1cases {
        for b0 in 0x21u8..=0x7E {
            for b1 in 0x21u8..=0x7E {
                let mut inp = desig.to_vec();
                inp.extend_from_slice(&[0x0E, b0, b1, 0x0F]);
                let gr = g_raw(&g, "UTF-32LE", "ISO-2022-CN", &inp);
                let fr = f_raw("UTF-32LE", "ISO-2022-CN", &inp);
                checked += 1;
                if gr != fr && mism.len() < 50 {
                    mism.push(format!("{name} {b0:02x}{b1:02x}: glibc={gr:x?} fl={fr:x?}"));
                }
            }
        }
    }
    // CNS plane 2 via SS2 (ESC N), G2 defaults to CNS-2.
    for b0 in 0x21u8..=0x7E {
        for b1 in 0x21u8..=0x7E {
            let inp = [0x1B, 0x4E, b0, b1];
            let gr = g_raw(&g, "UTF-32LE", "ISO-2022-CN", &inp);
            let fr = f_raw("UTF-32LE", "ISO-2022-CN", &inp);
            checked += 1;
            if gr != fr && mism.len() < 70 {
                mism.push(format!("CNS2 {b0:02x}{b1:02x}: glibc={gr:x?} fl={fr:x?}"));
            }
        }
    }
    // ASCII byte sweep (no shift).
    for b in 0u16..256 {
        let b = b as u8;
        let inp = [b];
        let gr = g_raw(&g, "UTF-32LE", "ISO-2022-CN", &inp);
        let fr = f_raw("UTF-32LE", "ISO-2022-CN", &inp);
        checked += 1;
        if gr != fr && mism.len() < 90 {
            mism.push(format!("ASCII {b:02x}: glibc={gr:x?} fl={fr:x?}"));
        }
    }

    assert!(
        mism.is_empty(),
        "ISO-2022-CN structured decode diverged ({} of {checked}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022cn_decode_random_fuzz() {
    let g = glibc();
    let alphabet: &[u8] = &[
        0x1B, 0x1B, 0x24, 0x29, 0x2A, 0x41, 0x47, 0x48, 0x4E, 0x0E, 0x0F, 0x0A, 0x21, 0x30, 0x41,
        0x5A, 0x7E, 0x7F, 0x20, 0x00, 0x80, 0xA1, 0xFF, 0x56, 0x50, 0x6A, 0x57,
    ];
    let mut state: u64 = 0x2022_43_4e_01_u64;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let mut mism = Vec::new();
    let iters = 30_000;
    for _ in 0..iters {
        let len = 1 + next() % 14;
        let mut inp = Vec::with_capacity(len);
        for _ in 0..len {
            inp.push(alphabet[next() % alphabet.len()]);
        }
        let gr = g_raw(&g, "UTF-32LE", "ISO-2022-CN", &inp);
        let fr = f_raw("UTF-32LE", "ISO-2022-CN", &inp);
        if gr != fr && mism.len() < 40 {
            mism.push(format!("{inp:02x?}: glibc={gr:x?} fl={fr:x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "ISO-2022-CN random decode fuzz diverged ({} cases over {iters}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
