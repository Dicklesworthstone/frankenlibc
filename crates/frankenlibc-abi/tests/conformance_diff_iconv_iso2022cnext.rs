//! Differential gate: ISO-2022-CN-EXT iconv codec vs glibc (both directions).
//!
//! ISO-2022-CN-EXT (RFC 1922) extends ISO-2022-CN with ISO-IR-165 as a G1 SO
//! charset (`ESC $ ) E`) and CNS 11643 planes 3-7 in G3 via SS3 (`ESC O`,
//! designated `ESC $ + I/J/K/L/M`). glibc's decoder treats SS2/SS3 as true
//! single shifts, while its encoder makes the shift sticky (the `set` model);
//! both directions are pinned here byte-for-byte against the live host glibc
//! (reached via dlsym so its symbols bypass fl's no_mangle interposition).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::iconv_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;
const INVALID: usize = usize::MAX;
const NAME: &str = "ISO-2022-CN-EXT";

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

#[test]
fn cnext_encode_codepoint_sweep() {
    let g = glibc();
    let mut mism = Vec::new();
    // Every BMP scalar plus a band of the SIP (CNS reaches astral planes).
    let ranges = [(0x80u32..0x10000), (0x20000..0x205B0)];
    for r in ranges {
        for cp in r {
            if (0xD800..=0xDFFF).contains(&cp) {
                continue;
            }
            let s = char::from_u32(cp).unwrap().to_string();
            let ge = g_full(&g, NAME, "UTF-8", s.as_bytes());
            let fe = f_full(NAME, "UTF-8", s.as_bytes());
            if ge != fe && mism.len() < 40 {
                mism.push(format!("encode U+{cp:04X}: glibc={ge:02x?} fl={fe:02x?}"));
            }
        }
    }
    assert!(
        mism.is_empty(),
        "CN-EXT encode sweep diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn cnext_encode_multichar_fuzz() {
    // Random code-point sequences exercise lazy-stay, set switching, SS2/SS3
    // stickiness, the newline reset and the SI-on-flush — all whole-buffer.
    let g = glibc();
    // A pool spanning GB2312, ISO-IR-165-only, CNS planes 1-7, ASCII and newline.
    let pool: Vec<u32> = (0x4E00..0x4E80)
        .chain(0x3400..0x3460) // CHK ext A -> CNS planes 3-7
        .chain([0xA2, 0xA3, 0x144, 0x251, 0x2C9, 0x2014, 0x3000, 0x4E59])
        .chain(0x20..0x30)
        .chain([0x0A, 0x41, 0x42])
        .collect();
    let mut state: u64 = 0x1505_2022_C3E7;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let mut mism = Vec::new();
    for _ in 0..40_000 {
        let len = 1 + next() % 10;
        let mut s = String::new();
        for _ in 0..len {
            if let Some(c) = char::from_u32(pool[next() % pool.len()]) {
                s.push(c);
            }
        }
        let ge = g_full(&g, NAME, "UTF-8", s.as_bytes());
        let fe = f_full(NAME, "UTF-8", s.as_bytes());
        if ge != fe && mism.len() < 40 {
            mism.push(format!("encode {s:?}: glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "CN-EXT encode fuzz diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn cnext_decode_structured() {
    let g = glibc();
    let mut mism = Vec::new();
    // Every ku-ten pair under each SO designator (GB2312/CNS-1/ISO-IR-165),
    // under SS2 (CNS plane 2) and under SS3 for each designated plane 3-7.
    let so = [
        (vec![0x1b, 0x24, 0x29, 0x41], "GB2312"),
        (vec![0x1b, 0x24, 0x29, 0x47], "CNS-1"),
        (vec![0x1b, 0x24, 0x29, 0x45], "IR165"),
    ];
    for (desig, tag) in &so {
        for c0 in 0x21u8..=0x7e {
            for c1 in 0x21u8..=0x7e {
                let mut inp = desig.clone();
                inp.extend_from_slice(&[0x0e, c0, c1, 0x0f]);
                if g_full(&g, "UTF-8", NAME, &inp) != f_full("UTF-8", NAME, &inp) && mism.len() < 40
                {
                    mism.push(format!("SO {tag} {c0:02x}{c1:02x}"));
                }
            }
        }
    }
    // SS2 (CNS plane 2) and SS3 planes 3-7.
    let ss = [
        (vec![0x1b, 0x24, 0x2a, 0x48], vec![0x1b, 0x4e], "SS2-CNS2"),
        (vec![0x1b, 0x24, 0x2b, 0x49], vec![0x1b, 0x4f], "SS3-CNS3"),
        (vec![0x1b, 0x24, 0x2b, 0x4a], vec![0x1b, 0x4f], "SS3-CNS4"),
        (vec![0x1b, 0x24, 0x2b, 0x4b], vec![0x1b, 0x4f], "SS3-CNS5"),
        (vec![0x1b, 0x24, 0x2b, 0x4c], vec![0x1b, 0x4f], "SS3-CNS6"),
        (vec![0x1b, 0x24, 0x2b, 0x4d], vec![0x1b, 0x4f], "SS3-CNS7"),
    ];
    for (desig, shift, tag) in &ss {
        for c0 in 0x21u8..=0x7e {
            for c1 in 0x21u8..=0x7e {
                let mut inp = desig.clone();
                inp.extend_from_slice(shift);
                inp.extend_from_slice(&[c0, c1]);
                if g_full(&g, "UTF-8", NAME, &inp) != f_full("UTF-8", NAME, &inp) && mism.len() < 60
                {
                    mism.push(format!("{tag} {c0:02x}{c1:02x}"));
                }
            }
        }
    }
    // Every ASCII byte on its own.
    for b in 0u16..0x80 {
        let inp = [b as u8];
        if g_full(&g, "UTF-8", NAME, &inp) != f_full("UTF-8", NAME, &inp) && mism.len() < 80 {
            mism.push(format!("ascii {b:02x}"));
        }
    }
    assert!(
        mism.is_empty(),
        "CN-EXT decode structured diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn cnext_decode_fuzz() {
    // Pseudo-random byte streams biased toward the CN-EXT escape alphabet,
    // comparing the EXACT single-call outcome (errored, consumed, output).
    let g = glibc();
    let alpha: Vec<u8> = vec![
        0x1b, 0x24, 0x29, 0x2a, 0x2b, 0x41, 0x47, 0x45, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x0e, 0x0f, 0x0a, 0x21, 0x30, 0x52, 0x3b, 0x44, 0x69, 0x7e, 0x7f, 0x41, 0x80,
    ];
    let mut state: u64 = 0x0D15_EA5E_2022;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    let mut mism = Vec::new();
    for _ in 0..60_000 {
        let len = 1 + next() % 14;
        let inp: Vec<u8> = (0..len)
            .map(|_| {
                if next() & 3 == 0 {
                    (next() & 0xFF) as u8
                } else {
                    alpha[next() % alpha.len()]
                }
            })
            .collect();
        let gr = g_raw(&g, "UTF-8", NAME, &inp);
        let fr = f_raw("UTF-8", NAME, &inp);
        if gr != fr && mism.len() < 40 {
            mism.push(format!("{inp:02x?}: glibc={gr:02x?} fl={fr:02x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "CN-EXT decode fuzz diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}

#[test]
fn cnext_roundtrip_samples() {
    // glibc-encode a multi-script sample, then both engines decode that exact
    // byte stream identically (the encoder's sticky SS forms included).
    let g = glibc();
    let samples = [
        "中文ABC\n繁體",
        "\u{00A2}\u{00A3}\u{4E00}\u{3400}",
        "a\u{4E59}\u{2014}\n\u{3000}b",
    ];
    let mut mism = Vec::new();
    for s in samples {
        if let Some(enc) = g_full(&g, NAME, "UTF-8", s.as_bytes()) {
            let gd = g_full(&g, "UTF-8", NAME, &enc);
            let fd = f_full("UTF-8", NAME, &enc);
            if gd != fd {
                mism.push(format!("decode {enc:02x?}: glibc={gd:02x?} fl={fd:02x?}"));
            }
        }
    }
    assert!(mism.is_empty(), "CN-EXT roundtrip diverged: {mism:?}");
}
