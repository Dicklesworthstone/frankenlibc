#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc iconv oracle

//! Differential fuzz for the SIMD 2-byte UTF-8 decode fast path in
//! `frankenlibc_core::iconv` (UTF-8 -> UTF-32LE/BE).
//!
//! The fast path decodes runs of >= 8 well-formed 2-byte sequences (lead
//! 0xC2..=0xDF + continuation 0x80..=0xBF) 8 code points per 16-byte window. It
//! must be byte-for-byte identical to a scalar decode. This fuzzes 2-byte-heavy
//! UTF-8 inputs — interleaved with ASCII, 3/4-byte sequences, NUL, malformed
//! bytes, and sequences straddling the 16-byte window — converted to UTF-32LE and
//! UTF-32BE, against the LIVE host glibc `iconv` oracle, comparing the full output
//! bytes and the success/error decision.

use std::ffi::{c_char, c_void};

use frankenlibc_core::iconv::{iconv as fl_iconv, iconv_open as fl_iconv_open};

unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inb: *mut usize,
        outbuf: *mut *mut c_char,
        outb: *mut usize,
    ) -> usize;
    fn iconv_close(cd: *mut c_void) -> i32;
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

/// glibc iconv: convert `src` fully; returns the output bytes, or None if the
/// conversion errored (EILSEQ/EINVAL) partway (we compare the error decision).
fn glibc_conv(to: &[u8], src: &[u8]) -> Option<Vec<u8>> {
    let cd = unsafe {
        iconv_open(
            to.as_ptr() as *const c_char,
            b"UTF-8\0".as_ptr() as *const c_char,
        )
    };
    assert!(cd as isize != -1);
    let mut out = vec![0u8; src.len() * 4 + 16];
    let mut ip = src.as_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { iconv_close(cd) };
    if r == usize::MAX {
        None
    } else {
        let written = out.len() - ol;
        out.truncate(written);
        Some(out)
    }
}

fn fl_conv(to: &[u8], src: &[u8]) -> Option<Vec<u8>> {
    let to_fl = &to[..to.len() - 1]; // strip the NUL the C oracle needs
    let mut cd = fl_iconv_open(to_fl, b"UTF-8")?;
    let mut out = vec![0u8; src.len() * 4 + 16];
    match fl_iconv(&mut cd, Some(src), &mut out) {
        Ok(r) => {
            out.truncate(r.out_written);
            Some(out)
        }
        Err(_) => None,
    }
}

fn check(to: &[u8], src: &[u8], divs: &mut Vec<String>) {
    let fl = fl_conv(to, src);
    let gl = glibc_conv(to, src);
    if fl != gl && divs.len() < 20 {
        divs.push(format!(
            "to={} src_len={} fl_ok={} glibc_ok={} (fl_len={:?} gl_len={:?})",
            String::from_utf8_lossy(&to[..to.len() - 1]),
            src.len(),
            fl.is_some(),
            gl.is_some(),
            fl.as_ref().map(|v| v.len()),
            gl.as_ref().map(|v| v.len())
        ));
    }
}

#[test]
fn iconv_utf8_to_utf32_simd_matches_glibc() {
    let mut r = Lcg(0x0bad_c0de_1234_5678);
    let mut compared = 0u64;
    let mut divs = Vec::new();

    for _ in 0..120_000 {
        let mut s: Vec<u8> = Vec::new();
        let segs = r.below(18);
        for _ in 0..segs {
            match r.below(10) {
                0..=5 => {
                    // 2-byte run (the SIMD path).
                    for _ in 0..(1 + r.below(12)) {
                        s.push(0xC2 + r.below(0xDF - 0xC2 + 1) as u8);
                        s.push(0x80 + r.below(0x40) as u8);
                    }
                }
                6 => {
                    for _ in 0..(1 + r.below(8)) {
                        s.push(1 + r.below(0x7F) as u8); // ASCII (no NUL)
                    }
                }
                7 => {
                    // 3-byte (well-formed, non-surrogate)
                    s.push(0xE1);
                    s.push(0x80 + r.below(0x40) as u8);
                    s.push(0x80 + r.below(0x40) as u8);
                }
                8 => {
                    // 4-byte astral
                    s.push(0xF0);
                    s.push(0x9F);
                    s.push(0x98);
                    s.push(0x80 + r.below(0x40) as u8);
                }
                _ => s.push((0xC2u16 + r.below(0x3e) as u16) as u8), // lone byte
            }
        }
        // No trailing NUL: iconv converts the whole byte slice (glibc uses il).
        for to in [
            &b"UTF-32LE\0"[..],
            &b"UTF-32BE\0"[..],
            &b"UTF-16LE\0"[..],
            &b"UTF-16BE\0"[..],
        ] {
            check(to, &s, &mut divs);
            compared += 1;
        }
    }

    assert!(
        divs.is_empty(),
        "iconv UTF-8->UTF-32 SIMD path diverged from glibc on some of {compared} cases (up to 20):\n{}",
        divs.join("\n")
    );
}

// ---- Encode direction: UTF-32LE/BE -> UTF-8 (the SIMD encode fast path) ----

fn glibc_conv_from(from: &[u8], to: &[u8], src: &[u8]) -> Option<Vec<u8>> {
    let cd = unsafe { iconv_open(to.as_ptr() as *const c_char, from.as_ptr() as *const c_char) };
    assert!(cd as isize != -1);
    let mut out = vec![0u8; src.len() * 2 + 16];
    let mut ip = src.as_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = unsafe { iconv(cd, &mut ip, &mut il, &mut op, &mut ol) };
    unsafe { iconv_close(cd) };
    if r == usize::MAX {
        None
    } else {
        let w = out.len() - ol;
        out.truncate(w);
        Some(out)
    }
}

fn fl_conv_from(from: &[u8], to: &[u8], src: &[u8]) -> Option<Vec<u8>> {
    let mut cd = fl_iconv_open(&to[..to.len() - 1], &from[..from.len() - 1])?;
    let mut out = vec![0u8; src.len() * 2 + 16];
    match fl_iconv(&mut cd, Some(src), &mut out) {
        Ok(r) => {
            out.truncate(r.out_written);
            Some(out)
        }
        Err(_) => None,
    }
}

#[test]
fn iconv_utf32_to_utf8_simd_matches_glibc() {
    let mut r = Lcg(0x5151_aaaa_3333_9999);
    let mut compared = 0u64;
    let mut divs = Vec::new();

    for _ in 0..120_000 {
        // Build a random code-point stream, biased to 2-byte / 3-byte runs.
        let mut cps: Vec<u32> = Vec::new();
        let segs = r.below(18);
        for _ in 0..segs {
            match r.below(10) {
                0..=4 => {
                    for _ in 0..(1 + r.below(12)) {
                        cps.push((0x80 + r.below(0x780)) as u32); // 2-byte
                    }
                }
                5..=7 => {
                    for _ in 0..(1 + r.below(12)) {
                        // 3-byte BMP non-surrogate
                        let c = 0x800 + r.below(0xF800);
                        if (0xD800..=0xDFFF).contains(&c) {
                            cps.push(0x4E00);
                        } else {
                            cps.push(c as u32);
                        }
                    }
                }
                8 => cps.push((1 + r.below(0x7F)) as u32), // ASCII
                _ => cps.push((0x1_0000 + r.below(0x10_0000)) as u32), // astral
            }
        }
        for (from, bytes) in [
            (
                &b"UTF-32LE\0"[..],
                cps.iter()
                    .flat_map(|c| c.to_le_bytes())
                    .collect::<Vec<u8>>(),
            ),
            (
                &b"UTF-32BE\0"[..],
                cps.iter()
                    .flat_map(|c| c.to_be_bytes())
                    .collect::<Vec<u8>>(),
            ),
            (
                // UTF-16LE: each code point as 1 (BMP) or 2 (astral surrogate
                // pair) units — exercises the SIMD BMP path + scalar pair handling.
                &b"UTF-16LE\0"[..],
                {
                    let mut u: Vec<u16> = Vec::new();
                    for &c in &cps {
                        let mut buf = [0u16; 2];
                        u.extend_from_slice(char::from_u32(c).unwrap().encode_utf16(&mut buf));
                    }
                    u.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>()
                },
            ),
            (
                &b"UTF-16BE\0"[..],
                {
                    let mut u: Vec<u16> = Vec::new();
                    for &c in &cps {
                        let mut buf = [0u16; 2];
                        u.extend_from_slice(char::from_u32(c).unwrap().encode_utf16(&mut buf));
                    }
                    u.iter().flat_map(|x| x.to_be_bytes()).collect::<Vec<u8>>()
                },
            ),
        ] {
            let fl = fl_conv_from(from, b"UTF-8\0", &bytes);
            let gl = glibc_conv_from(from, b"UTF-8\0", &bytes);
            compared += 1;
            if fl != gl && divs.len() < 20 {
                divs.push(format!(
                    "from={} ncp={} fl_ok={} gl_ok={} (fl={:?} gl={:?})",
                    String::from_utf8_lossy(&from[..from.len() - 1]),
                    cps.len(),
                    fl.is_some(),
                    gl.is_some(),
                    fl.as_ref().map(|v| v.len()),
                    gl.as_ref().map(|v| v.len())
                ));
            }
        }
    }

    assert!(
        divs.is_empty(),
        "iconv UTF-32->UTF-8 SIMD encode diverged from glibc on some of {compared} cases (up to 20):\n{}",
        divs.join("\n")
    );
}
