//! Differential gate: ISO-2022-JP-2 iconv codec vs glibc (both directions).
//!
//! ISO-2022-JP-2 (RFC 1554) extends ISO-2022-JP with GB2312 (`ESC $ A`), KSC
//! 5601 (`ESC $ ( C`) and JIS X 0212 (`ESC $ ( D`) G0 sets plus an ISO-8859-1 /
//! ISO-8859-7 G2 set reached one character at a time via SS2 (`ESC N`). glibc is
//! reached through dlsym so its symbols bypass fl's no_mangle interposition.
//!
//! Coverage is byte-for-byte against the live host glibc:
//!   * encode per-codepoint sweep across ASCII / Latin-1 / Greek / CJK / Hangul
//!     — pins the set-priority order and designator choice from a fresh state;
//!   * encode + round-trip on multi-script samples — pins lazy G0 switching and
//!     G2 single-shift transitions;
//!   * decode exhaustive structured — every ku-ten pair under each multibyte
//!     designator (0208/0212/GB2312/KSC), every G2 byte under Latin-1 and Greek,
//!     every byte under ASCII / JIS-Roman, each recognized escape;
//!   * decode unconstrained fuzz — pseudo-random streams biased toward the JP-2
//!     escape alphabet, comparing the EXACT single-call outcome (output bytes +
//!     consumed-prefix length, so EINVAL/EILSEQ positions and literal-ESC
//!     recovery are all pinned).
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
    Raw { errored: r == INVALID, in_left: il, out: out[..written].to_vec() }
}
fn f_raw(to: &str, from: &str, input: &[u8]) -> Raw {
    let (ct, cf) = (CString::new(to).unwrap(), CString::new(from).unwrap());
    let cd = unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) };
    assert!(cd as usize != INVALID && !cd.is_null(), "fl rejects {from}->{to}");
    let mut inb = input.to_vec();
    let mut out = vec![0u8; 4096];
    let mut ip = inb.as_mut_ptr() as *mut c_char;
    let mut il = inb.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    let written = out.len() - ol;
    Raw { errored: r == INVALID, in_left: il, out: out[..written].to_vec() }
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
    let r2 = unsafe { fl::iconv(cd, std::ptr::null_mut(), std::ptr::null_mut(), &mut op, &mut ol) };
    unsafe { fl::iconv_close(cd) };
    if r2 == INVALID {
        return None;
    }
    Some(out[..out.len() - ol].to_vec())
}

#[test]
fn iso2022jp2_encode_per_codepoint_matches_glibc() {
    let g = glibc();
    // Representative codepoints across every set the priority order can reach.
    let mut cps: Vec<u32> = Vec::new();
    cps.extend(0x20u32..=0x7E); // ASCII graphic
    cps.push(0x00A5); // ¥ (JIS-Roman)
    cps.push(0x203E); // ‾ (JIS-Roman)
    cps.extend(0xA0u32..=0xFF); // Latin-1 high half (0212 or G2)
    cps.extend(0x0370u32..=0x03FF); // Greek (0208/0212 or G2)
    cps.extend(0x0400u32..=0x045F); // Cyrillic (0208)
    cps.extend((0x4E00u32..=0x9FA0).step_by(17)); // CJK unified sample
    cps.extend((0xAC00u32..=0xD7A3).step_by(29)); // Hangul syllables sample
    cps.extend([0x3042, 0x30A2, 0x3001, 0x3002, 0xFF21, 0x2460, 0x2170]); // kana/punct/fullwidth

    let mut mism = Vec::new();
    let mut checked = 0u32;
    for &cp in &cps {
        let Some(ch) = char::from_u32(cp) else { continue };
        let u = ch.to_string();
        let ge = g_full(&g, "ISO-2022-JP-2", "UTF-8", u.as_bytes());
        let fe = f_full("ISO-2022-JP-2", "UTF-8", u.as_bytes());
        checked += 1;
        if ge != fe && mism.len() < 60 {
            mism.push(format!("U+{cp:04X}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "ISO-2022-JP-2 per-codepoint encode diverged ({} of {checked}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022jp2_encode_roundtrip_samples_match_glibc() {
    let g = glibc();
    let samples: &[&str] = &[
        "",
        "Hello, world!",
        "日本語と漢字",
        "한국어 텍스트",
        "简体中文这爱",
        "café crème \u{00AB}guillemets\u{00BB}",
        "Ελληνικά ώمω", // greek (mostly 0208/0212) — note arabic dropped if unrep
        "Mix 日本 한국 中文 ABC \u{00A5}",
        "A\u{00AB}B\u{3042}C\u{D55C}D", // ASCII, Latin1-G2, kana, Hangul interleaved
        "\u{00A5}\u{203E}\u{00A5}",
        "行1\n한2\n中3",
    ];
    let mut mism = Vec::new();
    for s in samples {
        let u = s.as_bytes();
        let ge = g_full(&g, "ISO-2022-JP-2", "UTF-8", u);
        let fe = f_full("ISO-2022-JP-2", "UTF-8", u);
        if ge != fe {
            mism.push(format!("ENC {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
            continue;
        }
        if let Some(enc) = ge {
            let gd = g_full(&g, "UTF-8", "ISO-2022-JP-2", &enc);
            let fd = f_full("UTF-8", "ISO-2022-JP-2", &enc);
            if gd != fd {
                mism.push(format!("DEC {s:?} ({enc:02x?}): glibc={gd:02x?} fl={fd:02x?}"));
            }
            if fd.as_deref() != Some(u) {
                mism.push(format!("ROUNDTRIP {s:?}: fl decoded={fd:02x?}"));
            }
        }
    }
    for alias in ["ISO2022JP2", "CSISO2022JP2"] {
        let fe = f_full(alias, "UTF-8", "中".as_bytes());
        let ge = g_full(&g, "ISO-2022-JP-2", "UTF-8", "中".as_bytes());
        if fe != ge {
            mism.push(format!("ALIAS {alias}: fl={fe:02x?} glibc={ge:02x?}"));
        }
    }
    assert!(mism.is_empty(), "ISO-2022-JP-2 encode/roundtrip diverged ({}):\n{}", mism.len(), mism.join("\n"));
}

#[test]
fn iso2022jp2_decode_exhaustive_structured() {
    let g = glibc();
    let mut mism = Vec::new();
    let mut checked = 0u32;

    // Multibyte G0 sets: every ku-ten pair under its designator, back to ASCII.
    let sets: &[(&[u8], &str)] = &[
        (&[0x1B, 0x24, 0x42], "0208"),       // ESC $ B
        (&[0x1B, 0x24, 0x28, 0x44], "0212"), // ESC $ ( D
        (&[0x1B, 0x24, 0x41], "GB2312"),     // ESC $ A
        (&[0x1B, 0x24, 0x28, 0x43], "KSC"),  // ESC $ ( C
    ];
    for (desig, name) in sets {
        for b0 in 0x21u8..=0x7E {
            for b1 in 0x21u8..=0x7E {
                let mut inp = desig.to_vec();
                inp.extend_from_slice(&[b0, b1, 0x1B, 0x28, 0x42]);
                let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP-2", &inp);
                let fr = f_raw("UTF-32LE", "ISO-2022-JP-2", &inp);
                checked += 1;
                if gr != fr && mism.len() < 50 {
                    mism.push(format!("{name} {b0:02x}{b1:02x}: glibc={gr:x?} fl={fr:x?}"));
                }
            }
        }
    }
    // G2 single-shift: every byte under ISO-8859-1 and ISO-8859-7 designation.
    for (desig, name) in [([0x1B, 0x2E, 0x41], "Latin1"), ([0x1B, 0x2E, 0x46], "Greek")] {
        for c in 0u16..256 {
            let c = c as u8;
            let mut inp = desig.to_vec();
            inp.extend_from_slice(&[0x1B, 0x4E, c]); // SS2 + byte
            let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP-2", &inp);
            let fr = f_raw("UTF-32LE", "ISO-2022-JP-2", &inp);
            checked += 1;
            if gr != fr && mism.len() < 80 {
                mism.push(format!("G2 {name} {c:02x}: glibc={gr:x?} fl={fr:x?}"));
            }
        }
    }
    // ASCII and JIS-Roman single-byte sweeps.
    for b in 0u16..256 {
        let b = b as u8;
        for (pfx, name) in [(&[][..], "ASCII"), (&[0x1B, 0x28, 0x4A][..], "Roman")] {
            let mut inp = pfx.to_vec();
            inp.push(b);
            let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP-2", &inp);
            let fr = f_raw("UTF-32LE", "ISO-2022-JP-2", &inp);
            checked += 1;
            if gr != fr && mism.len() < 120 {
                mism.push(format!("{name} {b:02x}: glibc={gr:x?} fl={fr:x?}"));
            }
        }
    }

    assert!(
        mism.is_empty(),
        "ISO-2022-JP-2 structured decode diverged ({} of {checked}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022jp2_decode_random_fuzz() {
    let g = glibc();
    let alphabet: &[u8] = &[
        0x1B, 0x1B, 0x28, 0x24, 0x2E, 0x4E, 0x42, 0x4A, 0x40, 0x41, 0x43, 0x44, 0x46, 0x21, 0x30,
        0x41, 0x5A, 0x7E, 0x5C, 0x7F, 0x20, 0x0A, 0x00, 0x80, 0xA1, 0xFF, 0x65, 0x39, 0x55, 0x62,
    ];
    let mut state: u64 = 0x2022_4a_50_02_u64;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
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
        let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP-2", &inp);
        let fr = f_raw("UTF-32LE", "ISO-2022-JP-2", &inp);
        if gr != fr && mism.len() < 40 {
            mism.push(format!("{inp:02x?}: glibc={gr:x?} fl={fr:x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "ISO-2022-JP-2 random decode fuzz diverged ({} cases over {iters}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
