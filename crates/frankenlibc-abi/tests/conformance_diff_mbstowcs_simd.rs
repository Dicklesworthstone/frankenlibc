#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc mbstowcs oracle

//! Differential fuzz for the SIMD multibyte UTF-8 decode fast paths in
//! `frankenlibc_core::string::wchar::mbstowcs` (bd-w7mtzu).
//!
//! The fast path decodes runs of >= 8 well-formed 2-byte sequences (lead
//! 0xC2..=0xDF + continuation 0x80..=0xBF) 8 code points per 16-byte vector. It
//! also decodes clean 3-byte and 4-byte runs four code points per SIMD window.
//! All paths must be byte-for-byte identical to scalar decode. This fuzzes
//! 2-byte-, 3-byte-, and 4-byte-heavy inputs — interleaved with ASCII,
//! NUL, malformed bytes, and sequences straddling SIMD windows — against the
//! LIVE host glibc `mbstowcs` oracle (C.UTF-8), comparing the full wide-char
//! output and the success/error decision on every case.

use std::ffi::c_char;

unsafe extern "C" {
    fn mbstowcs(dst: *mut i32, src: *const c_char, n: usize) -> usize;
    fn setlocale(cat: i32, loc: *const c_char) -> *mut c_char;
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

/// Push a random 2-byte UTF-8 sequence (the SIMD-targeted case).
fn push_2byte(r: &mut Lcg, out: &mut Vec<u8>) {
    let lead = 0xC2 + r.below(0xDF - 0xC2 + 1) as u8; // 0xC2..=0xDF
    let cont = 0x80 + r.below(0x40) as u8; // 0x80..=0xBF
    out.push(lead);
    out.push(cont);
}

/// Push a random well-formed 3-byte UTF-8 sequence (the CJK-targeted case).
fn push_3byte(r: &mut Lcg, out: &mut Vec<u8>) {
    let wc = match r.below(6) {
        0 => 0x0800 + r.below(0x200) as u32,
        1 => 0x20AC,
        2 | 3 => 0x4E00 + r.below(0x5200) as u32,
        4 => 0xD000 + r.below(0x800) as u32,
        _ => 0xE000 + r.below(0x1000) as u32,
    };
    let ch = char::from_u32(wc).unwrap();
    let mut buf = [0u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

/// Push a random well-formed 4-byte UTF-8 sequence (the astral-targeted case).
fn push_4byte(r: &mut Lcg, out: &mut Vec<u8>) {
    let wc = match r.below(5) {
        0 => 0x1_0000,
        1 | 2 => 0x1F600 + r.below(0x80) as u32,
        3 => 0x10_FFFF,
        _ => 0x10000 + r.below(0x100000) as u32,
    };
    let ch = char::from_u32(wc).unwrap();
    let mut buf = [0u8; 4];
    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
}

fn glibc_mbstowcs(src: &[u8]) -> Option<Vec<i32>> {
    // src must be NUL-terminated for glibc.
    let mut dst = vec![0i32; src.len() + 1];
    let n = unsafe { mbstowcs(dst.as_mut_ptr(), src.as_ptr() as *const c_char, dst.len()) };
    if n == usize::MAX {
        None
    } else {
        dst.truncate(n);
        Some(dst)
    }
}

fn fl_mbstowcs(src: &[u8]) -> Option<Vec<i32>> {
    // fl core mbstowcs takes the bytes up to (not incl) the NUL; it returns the
    // count and writes the wchars. Mirror glibc's NUL-terminated contract.
    let nul = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    let mut dst = vec![0u32; src.len() + 1];
    frankenlibc_core::string::wchar::mbstowcs(&mut dst, &src[..nul])
        .map(|n| dst[..n].iter().map(|&w| w as i32).collect())
}

#[test]
fn mbstowcs_simd_2byte_matches_glibc() {
    unsafe {
        setlocale(6 /*LC_ALL*/, c"C.UTF-8".as_ptr())
    };

    let mut r = Lcg(0x1234_5678_9abc_def1);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let mut s: Vec<u8> = Vec::new();
        let segs = r.below(20);
        for _ in 0..segs {
            match r.below(12) {
                // Bias toward the SIMD multibyte paths, in runs.
                0..=3 => {
                    let run = 1 + r.below(12);
                    for _ in 0..run {
                        push_2byte(&mut r, &mut s);
                    }
                }
                4..=6 => {
                    let run = 1 + r.below(12);
                    for _ in 0..run {
                        push_3byte(&mut r, &mut s);
                    }
                }
                7 => {
                    let run = 1 + r.below(12);
                    for _ in 0..run {
                        push_4byte(&mut r, &mut s);
                    }
                }
                8 => {
                    // ASCII run (1..=10 bytes, never NUL).
                    for _ in 0..(1 + r.below(10)) {
                        s.push(1 + r.below(0x7F) as u8);
                    }
                }
                9 => {
                    // 4-byte sequence (well-formed astral): U+1F600-ish.
                    push_4byte(&mut r, &mut s);
                }
                _ => {
                    // Inject a single arbitrary byte (often malformed): stresses the
                    // SIMD mask-fail -> scalar handoff and error parity.
                    s.push(0x80u8.wrapping_add(r.below(0x80) as u8));
                }
            }
        }
        s.push(0); // NUL terminator

        let fl = fl_mbstowcs(&s);
        let gl = glibc_mbstowcs(&s);
        compared += 1;
        if fl != gl && divs.len() < 20 {
            divs.push(format!(
                "input={:02x?}\n    fl   ={:?}\n    glibc={:?}",
                &s,
                fl.as_ref().map(|v| v.len()),
                gl.as_ref().map(|v| v.len())
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "mbstowcs SIMD multibyte path diverged from glibc on some of {compared} cases (up to 20):\n{}",
        divs.join("\n")
    );
}
