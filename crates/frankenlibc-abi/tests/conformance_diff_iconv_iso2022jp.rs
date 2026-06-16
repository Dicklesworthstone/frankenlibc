//! Differential gate: ISO-2022-JP iconv codec vs glibc (both directions).
//!
//! ISO-2022-JP (RFC 1468) is a stateful 7-bit escape codec. G0 starts in ASCII;
//! `ESC ( B` selects ASCII, `ESC ( J` JIS X 0201-Roman (0x5C => ¥, 0x7E => ‾),
//! `ESC $ @` / `ESC $ B` JIS X 0208 (1978/1983, mapped identically). fl had no
//! codec for this name before (iconv_open failed). glibc is reached via dlsym so
//! its symbols bypass fl's no_mangle interposition.
//!
//! Coverage is byte-for-byte against the live host glibc:
//!   * encode: curated UTF-8 samples (ASCII, kana, kanji, ¥/‾, mixed, newline)
//!     -> ISO-2022-JP with the trailing flush, plus round-trip back to UTF-8;
//!   * decode (exhaustive structured): every JIS X 0208 ku-ten pair, every
//!     JIS-Roman byte, every ASCII byte, and each recognized designator;
//!   * decode (unconstrained fuzz): pseudo-random byte streams biased toward ESC
//!     sequences and ku-ten ranges, comparing the EXACT outcome of a single
//!     `iconv` call — output bytes AND the consumed-prefix length (so EINVAL /
//!     EILSEQ error positions and glibc's literal-ESC recovery are all pinned).
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

/// Outcome of a SINGLE `iconv` call (no flush): did it error, how many input
/// bytes were left unconsumed, and the bytes written. This captures glibc's
/// exact error position (EINVAL/EILSEQ both report INVALID + a residual `il`).
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

/// Full conversion with a trailing flush (NULL inbuf), returning None on error.
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
fn iso2022jp_encode_and_roundtrip_match_glibc() {
    let g = glibc();
    let samples: &[&str] = &[
        "",
        "Hello, world!",
        "あいうえお",
        "日本語のテキスト",
        "Aあ1日Bz",
        "Mix 漢字 123 かな ABC",
        "￥は全角、\u{00A5}は半角円記号",
        "オーバーライン \u{203E} end",
        "行1\n行2\n行3",
        "句読点、。「」・ー",
        "ＡＢＣ１２３",
        "\u{00A5}\u{203E}\u{00A5}A",
        "tab\there\nnewline",
        "おわり",
    ];
    let mut mism = Vec::new();
    for s in samples {
        let u = s.as_bytes();
        let ge = g_full(&g, "ISO-2022-JP", "UTF-8", u);
        let fe = f_full("ISO-2022-JP", "UTF-8", u);
        if ge != fe {
            mism.push(format!("ENC {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
            continue;
        }
        if let Some(enc) = ge {
            // decode glibc's bytes through both, and confirm round-trip.
            let gd = g_full(&g, "UTF-8", "ISO-2022-JP", &enc);
            let fd = f_full("UTF-8", "ISO-2022-JP", &enc);
            if gd != fd {
                mism.push(format!("DEC {s:?} ({enc:02x?}): glibc={gd:02x?} fl={fd:02x?}"));
            }
            if fd.as_deref() != Some(u) {
                mism.push(format!("ROUNDTRIP {s:?}: fl decoded={fd:02x?}"));
            }
        }
    }
    for alias in ["ISO2022JP", "CSISO2022JP"] {
        let fe = f_full(alias, "UTF-8", "日本".as_bytes());
        let ge = g_full(&g, "ISO-2022-JP", "UTF-8", "日本".as_bytes());
        if fe != ge {
            mism.push(format!("ALIAS {alias}: fl={fe:02x?} glibc={ge:02x?}"));
        }
    }
    assert!(mism.is_empty(), "ISO-2022-JP encode/roundtrip diverged ({}):\n{}", mism.len(), mism.join("\n"));
}

#[test]
fn iso2022jp_decode_exhaustive_structured() {
    let g = glibc();
    let mut mism = Vec::new();
    let mut checked = 0u32;

    // Every JIS X 0208 ku-ten pair under ESC $ B, returned to ASCII.
    for b0 in 0x21u8..=0x7E {
        for b1 in 0x21u8..=0x7E {
            let inp = [0x1B, 0x24, 0x42, b0, b1, 0x1B, 0x28, 0x42];
            let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP", &inp);
            let fr = f_raw("UTF-32LE", "ISO-2022-JP", &inp);
            checked += 1;
            if gr != fr {
                if mism.len() < 40 {
                    mism.push(format!("0208 {b0:02x}{b1:02x}: glibc={gr:x?} fl={fr:x?}"));
                }
            }
        }
    }
    // Same pairs under ESC $ @ (JIS X 0208-1978) — must map identically.
    for b0 in 0x21u8..=0x7E {
        for b1 in 0x21u8..=0x7E {
            let inp = [0x1B, 0x24, 0x40, b0, b1, 0x1B, 0x28, 0x42];
            let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP", &inp);
            let fr = f_raw("UTF-32LE", "ISO-2022-JP", &inp);
            checked += 1;
            if gr != fr && mism.len() < 60 {
                mism.push(format!("0208@ {b0:02x}{b1:02x}: glibc={gr:x?} fl={fr:x?}"));
            }
        }
    }
    // Every byte under ASCII (default) and JIS-Roman designations.
    for b in 0u16..256 {
        let b = b as u8;
        let ascii = [b];
        let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP", &ascii);
        let fr = f_raw("UTF-32LE", "ISO-2022-JP", &ascii);
        checked += 1;
        if gr != fr && mism.len() < 80 {
            mism.push(format!("ASCII {b:02x}: glibc={gr:x?} fl={fr:x?}"));
        }
        let roman = [0x1B, 0x28, 0x4A, b];
        let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP", &roman);
        let fr = f_raw("UTF-32LE", "ISO-2022-JP", &roman);
        checked += 1;
        if gr != fr && mism.len() < 100 {
            mism.push(format!("ROMAN {b:02x}: glibc={gr:x?} fl={fr:x?}"));
        }
    }

    assert!(
        mism.is_empty(),
        "ISO-2022-JP structured decode diverged ({} of {checked} checks):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn iso2022jp_decode_random_fuzz() {
    let g = glibc();
    // Deterministic LCG; bias the byte alphabet toward ESC, designators and the
    // ku-ten / ASCII ranges so escape state machines and recovery get exercised.
    let alphabet: &[u8] = &[
        0x1B, 0x1B, 0x28, 0x24, 0x42, 0x4A, 0x40, 0x49, 0x21, 0x30, 0x41, 0x5A, 0x7E, 0x5C, 0x7F,
        0x20, 0x0A, 0x00, 0x80, 0xA1, 0xFF, 0x65, 0x39,
    ];
    let mut state: u64 = 0x2022_00_4a_50_u64;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let mut mism = Vec::new();
    let iters = 20_000;
    for _ in 0..iters {
        let len = 1 + next() % 12;
        let mut inp = Vec::with_capacity(len);
        for _ in 0..len {
            inp.push(alphabet[next() % alphabet.len()]);
        }
        let gr = g_raw(&g, "UTF-32LE", "ISO-2022-JP", &inp);
        let fr = f_raw("UTF-32LE", "ISO-2022-JP", &inp);
        if gr != fr && mism.len() < 30 {
            mism.push(format!("{inp:02x?}: glibc={gr:x?} fl={fr:x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "ISO-2022-JP random decode fuzz diverged ({} cases over {iters} iters):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
