//! Byte-identity gate for the ASCII -> fixed-width (UTF-16/UTF-32) iconv fast
//! path. A SIMD ASCII-widen tier was added to the convert loop (a byte < 0x80
//! widens to one UTF-16/UTF-32 code unit with zero high bytes); this pins it
//! against a scalar reference across the 16-byte window boundary, partial tails,
//! mixed ASCII/non-ASCII transitions, and output-buffer-full (E2BIG) mid-run, so
//! the fast path can never silently diverge from the per-char encode it replaces.

use std::ffi::{c_char, c_void};

use frankenlibc_abi::iconv_abi::{iconv, iconv_close, iconv_open};

/// Scalar reference: each input byte (here all in the BMP) -> one fixed-width
/// code unit. ASCII bytes are < 0x80, but the reference also covers the 2-byte
/// Cyrillic transition used in the mixed cases.
fn ref_encode(src_cps: &[u32], to: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for &cp in src_cps {
        match to {
            "UTF-16LE" => out.extend_from_slice(&(cp as u16).to_le_bytes()),
            "UTF-16BE" => out.extend_from_slice(&(cp as u16).to_be_bytes()),
            "UTF-32LE" => out.extend_from_slice(&cp.to_le_bytes()),
            "UTF-32BE" => out.extend_from_slice(&cp.to_be_bytes()),
            _ => unreachable!(),
        }
    }
    out
}

fn utf8_encode(cps: &[u32]) -> Vec<u8> {
    let mut v = Vec::new();
    for &cp in cps {
        if cp < 0x80 {
            v.push(cp as u8);
        } else if cp < 0x800 {
            v.push(0xC0 | (cp >> 6) as u8);
            v.push(0x80 | (cp & 0x3F) as u8);
        } else {
            v.push(0xE0 | (cp >> 12) as u8);
            v.push(0x80 | ((cp >> 6) & 0x3F) as u8);
            v.push(0x80 | (cp & 0x3F) as u8);
        }
    }
    v
}

/// Run fl iconv over the whole input into a generously-sized buffer.
fn fl_convert(to: &[u8], from: &[u8], src: &[u8]) -> Vec<u8> {
    let cd = unsafe { iconv_open(to.as_ptr().cast(), from.as_ptr().cast()) };
    assert!(cd as isize != -1 && !cd.is_null(), "iconv_open failed");
    let mut dst = vec![0u8; src.len() * 4 + 16];
    let mut inp = src.as_ptr() as *mut c_char;
    let mut inleft = src.len();
    let mut outp = dst.as_mut_ptr() as *mut c_char;
    let mut outleft = dst.len();
    let r = unsafe { iconv(cd, &mut inp, &mut inleft, &mut outp, &mut outleft) };
    assert_ne!(r, usize::MAX, "iconv returned error");
    assert_eq!(inleft, 0, "iconv left input unconsumed");
    let produced = dst.len() - outleft;
    dst.truncate(produced);
    unsafe { iconv_close(cd) };
    dst
}

#[test]
fn ascii_widen_matches_scalar_reference_all_lengths() {
    // Lengths span the 16-byte SIMD window and its boundaries.
    let lens = [
        0usize, 1, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 127, 128, 256, 257, 1000,
    ];
    let targets = ["UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE"];
    let target_bytes: [&[u8]; 4] = [b"UTF-16LE\0", b"UTF-16BE\0", b"UTF-32LE\0", b"UTF-32BE\0"];

    for &len in &lens {
        // Deterministic ASCII fill.
        let cps: Vec<u32> = (0..len).map(|k| 0x20 + (k as u32 * 7 % 0x5F)).collect();
        let src = utf8_encode(&cps);
        for (t, tb) in targets.iter().zip(target_bytes.iter()) {
            let got = fl_convert(tb, b"UTF-8\0", &src);
            let want = ref_encode(&cps, t);
            assert_eq!(got, want, "ascii widen mismatch len={len} to={t}");
        }
    }
}

#[test]
fn ascii_widen_mixed_with_non_ascii_transitions() {
    // ASCII run, then a 2-byte Cyrillic char, then ASCII again — the SIMD window
    // must break exactly at the non-ASCII byte and resume after it. Vary the
    // leading ASCII run length around the 16-byte boundary.
    for lead in [0usize, 1, 15, 16, 17, 32, 33] {
        for trail in [0usize, 1, 16, 17] {
            let mut cps: Vec<u32> = (0..lead).map(|k| 0x41 + (k as u32 % 26)).collect();
            cps.push(0x0410); // U+0410 (А), 2-byte UTF-8
            cps.extend((0..trail).map(|k| 0x61 + (k as u32 % 26)));
            let src = utf8_encode(&cps);
            for (t, tb) in [
                ("UTF-16LE", b"UTF-16LE\0".as_slice()),
                ("UTF-16BE", b"UTF-16BE\0".as_slice()),
            ] {
                let got = fl_convert(tb, b"UTF-8\0", &src);
                let want = ref_encode(&cps, t);
                assert_eq!(got, want, "mixed widen mismatch lead={lead} trail={trail} to={t}");
            }
        }
    }
}

#[test]
fn ascii_widen_e2big_midrun_is_exact() {
    // A 100-char ASCII run into an undersized output buffer must stop at exactly
    // floor(out_cap / 2) code units (UTF-16) and report E2BIG, consuming exactly
    // that many input bytes — byte-identical to the scalar encode.
    let cps: Vec<u32> = (0..100).map(|k| 0x41 + (k as u32 % 26)).collect();
    let src = utf8_encode(&cps);
    let cd = unsafe { iconv_open(b"UTF-16LE\0".as_ptr().cast(), b"UTF-8\0".as_ptr().cast()) };
    assert!(cd as isize != -1 && !cd.is_null());
    // Room for exactly 37 UTF-16 units (74 bytes) — mid-run, not on a 16-byte edge.
    let mut dst = vec![0u8; 74];
    let mut inp = src.as_ptr() as *mut c_char;
    let mut inleft = src.len();
    let mut outp = dst.as_mut_ptr() as *mut c_char;
    let mut outleft = dst.len();
    let r = unsafe { iconv(cd, &mut inp, &mut inleft, &mut outp, &mut outleft) };
    assert_eq!(r, usize::MAX, "expected E2BIG");
    let consumed = src.len() - inleft;
    let produced = dst.len() - outleft;
    assert_eq!(produced, 74, "should fill the buffer exactly");
    assert_eq!(consumed, 37, "should consume exactly 37 ASCII bytes");
    assert_eq!(&dst[..74], &ref_encode(&cps[..37], "UTF-16LE")[..], "partial output diverged");
    unsafe { iconv_close(cd) };
}
