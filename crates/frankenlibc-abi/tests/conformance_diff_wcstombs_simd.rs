#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcstombs oracle

//! Differential fuzz for the SIMD 2-byte and 3-byte UTF-8 *encode* fast paths in
//! `frankenlibc_core::string::wchar::wcstombs` (bd-w7mtzu).
//!
//! The fast path encodes runs of >= 8 wide chars all in 0x80..=0x7FF — each to
//! exactly two UTF-8 bytes — 8 chars per 16-byte vector. It must be byte-for-byte
//! identical to scalar `wctomb`. The 3-byte path does the same for clean BMP
//! non-surrogate runs in 0x0800..=0xFFFF, four wide chars per 12 output bytes.
//! This fuzzes 2/3-byte-heavy wide-char arrays (interleaved with ASCII, 4-byte
//! code points, surrogates, out-of-range values, and runs straddling both SIMD
//! window sizes) against the LIVE host glibc `wcstombs` oracle (C.UTF-8),
//! comparing the full byte output and the success/error decision on every case.

use std::ffi::c_char;

unsafe extern "C" {
    fn wcstombs(dst: *mut c_char, src: *const i32, n: usize) -> usize;
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

fn glibc_wcstombs(src: &[i32]) -> Option<Vec<u8>> {
    // src must be NUL-terminated (a 0 wchar) for glibc.
    let mut dst = vec![0i8; src.len() * 4 + 4];
    let n = unsafe { wcstombs(dst.as_mut_ptr(), src.as_ptr(), dst.len()) };
    if n == usize::MAX {
        None
    } else {
        Some(dst[..n].iter().map(|&b| b as u8).collect())
    }
}

fn fl_wcstombs(src: &[i32]) -> Option<Vec<u8>> {
    let nul = src.iter().position(|&w| w == 0).unwrap_or(src.len());
    let su: Vec<u32> = src[..nul].iter().map(|&w| w as u32).collect();
    let mut dst = vec![0u8; src.len() * 4 + 4];
    frankenlibc_core::string::wchar::wcstombs(&mut dst, &su).map(|n| dst[..n].to_vec())
}

fn valid_3byte_codepoint(r: &mut Lcg) -> i32 {
    match r.below(5) {
        0 => 0x0800 + r.below(0x4000) as i32,
        1 => 0x4E00 + r.below(0x1200) as i32,
        2 => 0xE000 + r.below(0x2000) as i32,
        3 => 0xD7FF,
        _ => 0xFFFF,
    }
}

#[test]
fn wcstombs_simd_2byte_and_3byte_matches_glibc() {
    unsafe {
        setlocale(6 /*LC_ALL*/, b"C.UTF-8\0".as_ptr() as *const c_char)
    };

    let mut r = Lcg(0xfeed_face_dead_beef);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;

    for _ in 0..200_000 {
        let mut s: Vec<i32> = Vec::new();
        let segs = r.below(20);
        for _ in 0..segs {
            match r.below(10) {
                // Bias toward 2-byte code points (the SIMD path), in runs.
                0..=3 => {
                    let run = 1 + r.below(12);
                    for _ in 0..run {
                        s.push((0x80 + r.below(0x780)) as i32); // 0x80..=0x7FF
                    }
                }
                // Bias toward valid 3-byte BMP code points, in runs.
                4..=7 => {
                    let run = 1 + r.below(12);
                    for _ in 0..run {
                        s.push(valid_3byte_codepoint(&mut r));
                    }
                }
                8 => {
                    for _ in 0..(1 + r.below(10)) {
                        s.push((1 + r.below(0x7F)) as i32); // ASCII
                    }
                }
                9 if r.below(2) == 0 => s.push((0x1_0000 + r.below(0x10_0000)) as i32), // 4-byte astral
                _ => {
                    // Edge values: surrogates / out-of-range (glibc & fl both error).
                    match r.below(3) {
                        0 => s.push((0xD800 + r.below(0x800)) as i32), // surrogate
                        1 => s.push(0x11_0000 + r.below(0x1000) as i32), // > U+10FFFF
                        _ => s.push((0x80 + r.below(0x780)) as i32),
                    }
                }
            }
        }
        s.push(0); // NUL terminator

        let fl = fl_wcstombs(&s);
        let gl = glibc_wcstombs(&s);
        compared += 1;
        if fl != gl && divs.len() < 20 {
            divs.push(format!(
                "input_len={} fl_ok={} glibc_ok={}",
                s.len() - 1,
                fl.is_some(),
                gl.is_some()
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "wcstombs SIMD 2-byte path diverged from glibc on some of {compared} cases (up to 20):\n{}",
        divs.join("\n")
    );
}
