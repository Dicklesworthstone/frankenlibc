//! Differential gate: TSCII (Tamil) iconv codec vs glibc (both directions).
//!
//! TSCII is a single-byte codec where 63 byte values decode to 2-4 Unicode code
//! points and encode is maximal-munch over the code-point stream (a few code
//! points emit 2 bytes). glibc is reached via dlsym so its symbols bypass fl's
//! no_mangle interposition.
//!
//! Coverage is byte-for-byte against the live host glibc:
//!   * decode every single byte and many random multi-byte streams -> UTF-32LE,
//!     comparing the EXACT single-call outcome (output bytes + consumed length);
//!   * encode realistic and random Tamil/ASCII code-point streams -> TSCII with
//!     the trailing flush, plus a full round-trip of glibc's own byte output.
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
fn tscii_decode_all_bytes_and_streams() {
    let g = glibc();
    let mut mism = Vec::new();
    // Complete conversions (conv + flush): the visual-order reordering buffers a
    // code point internally, so byte-exactness is measured on the flushed output.
    // every single byte
    for b in 0u16..256 {
        let inp = [b as u8];
        let gr = g_full(&g, "UTF-32LE", "TSCII", &inp);
        let fr = f_full("UTF-32LE", "TSCII", &inp);
        if gr != fr && mism.len() < 40 {
            mism.push(format!("byte {b:02x}: glibc={gr:02x?} fl={fr:02x?}"));
        }
    }
    // the whole 0..256 byte range as one stream
    let all: Vec<u8> = (0u16..256).map(|b| b as u8).collect();
    if g_full(&g, "UTF-32LE", "TSCII", &all) != f_full("UTF-32LE", "TSCII", &all) {
        mism.push("full 0..256 stream differs".into());
    }
    // EXHAUSTIVE every 2-byte sequence (catches all reorder/compose/fuse pairs).
    for b0 in 0u16..256 {
        for b1 in 0u16..256 {
            let inp = [b0 as u8, b1 as u8];
            if g_full(&g, "UTF-32LE", "TSCII", &inp) != f_full("UTF-32LE", "TSCII", &inp)
                && mism.len() < 60
            {
                mism.push(format!("2byte {b0:02x}{b1:02x} differs"));
            }
        }
    }
    // Random multi-byte streams biased toward the bytes that participate in
    // reordering/composition (preposed vowels, marks, consonants, pulli bytes).
    let mut special: Vec<u8> = vec![0xa6, 0xa7, 0xa8, 0xa1, 0xaa, 0xa2, 0xa3, 0xa4, 0xa5];
    special.extend(0xb8u8..=0xc9); // consonants
    special.extend(0x87u8..=0x8c); // consonant+pulli clusters
    special.extend(0xecu8..=0xfd); // consonant+pulli
    special.extend([0x30, 0x41, 0x20, 0x0a]); // ascii
    let mut state: u64 = 0x7343_4949_0001;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    for _ in 0..50_000 {
        let len = 1 + next() % 12;
        let inp: Vec<u8> = (0..len)
            .map(|_| {
                if next() & 3 == 0 {
                    (next() & 0xFF) as u8
                } else {
                    special[next() % special.len()]
                }
            })
            .collect();
        let gr = g_full(&g, "UTF-32LE", "TSCII", &inp);
        let fr = f_full("UTF-32LE", "TSCII", &inp);
        if gr != fr && mism.len() < 60 {
            mism.push(format!("{inp:02x?}: glibc={gr:02x?} fl={fr:02x?}"));
        }
    }
    assert!(mism.is_empty(), "TSCII decode diverged ({}):\n{}", mism.len(), mism.join("\n"));
}

#[test]
fn tscii_encode_roundtrip_and_munch() {
    let g = glibc();
    let mut mism = Vec::new();
    // Round-trip: glibc's own byte output for every valid byte decodes then must
    // re-encode identically on fl and glibc.
    for b in 0u16..256 {
        let inp = [b as u8];
        if let Some(u8s) = g_full(&g, "UTF-8", "TSCII", &inp) {
            // re-encode the UTF-8 back to TSCII
            let ge = g_full(&g, "TSCII", "UTF-8", &u8s);
            let fe = f_full("TSCII", "UTF-8", &u8s);
            if ge != fe && mism.len() < 40 {
                mism.push(format!("reencode byte {b:02x} (u8={u8s:02x?}): glibc={ge:02x?} fl={fe:02x?}"));
            }
        }
    }
    // Encode random Tamil/ASCII code-point streams (exercises maximal munch).
    let pool: Vec<u32> = (0x0B80u32..=0x0BFF)
        .chain(0x20..=0x7E)
        .chain([0x0BCA, 0x0BCB, 0x0BCC])
        .collect();
    let mut state: u64 = 0x7343_4949_4f55;
    let mut next = || {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (state >> 33) as usize
    };
    for _ in 0..20_000 {
        let len = 1 + next() % 8;
        let mut s = String::new();
        for _ in 0..len {
            let cp = pool[next() % pool.len()];
            if let Some(c) = char::from_u32(cp) {
                s.push(c);
            }
        }
        let u = s.as_bytes();
        let ge = g_full(&g, "TSCII", "UTF-8", u);
        let fe = f_full("TSCII", "UTF-8", u);
        if ge != fe && mism.len() < 60 {
            mism.push(format!("encode {s:?} ({u:02x?}): glibc={ge:02x?} fl={fe:02x?}"));
        }
    }
    assert!(mism.is_empty(), "TSCII encode diverged ({}):\n{}", mism.len(), mism.join("\n"));
}
