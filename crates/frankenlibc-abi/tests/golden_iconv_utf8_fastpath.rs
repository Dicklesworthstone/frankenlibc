#![cfg(target_os = "linux")]
//! Golden-output gate for the UTF-8-source fast path in `frankenlibc_core::iconv`.
//!
//! The convert loop has a hot-path specialization for `UTF-8 -> {UTF-32LE/BE,
//! UTF-16LE/BE, single-byte}` that inlines the decode/encode to skip the generic
//! per-char `decode_char`/`encode_char` dispatch. It must stay byte-for-byte
//! identical to the generic path. This pins a SHA-256 over a representative
//! corpus (ASCII + 2-byte Cyrillic + 3-byte CJK + 4-byte emoji) converted to each
//! fast-path target, so any future drift in the specialization is caught here in
//! addition to the live-glibc `iconv_differential_fuzz`.

use frankenlibc_core::iconv::{iconv, iconv_open};
use sha2::{Digest, Sha256};

fn corpus() -> Vec<u8> {
    // ASCII run, Cyrillic (2-byte), CJK (3-byte), emoji (4-byte), interleaved so
    // the ASCII fast path, the multibyte decode, and surrogate-pair UTF-16
    // encoding are all exercised.
    let mut s = String::new();
    for i in 0..400 {
        s.push_str("token");
        s.push(char::from_u32(0x0410 + (i % 0x40)).unwrap()); // А..я
        s.push(char::from_u32(0x4E00 + (i % 0x100)).unwrap()); // CJK
        if i % 3 == 0 {
            s.push('😀'); // U+1F600, 4-byte UTF-8 / surrogate pair in UTF-16
        }
    }
    s.into_bytes()
}

fn koi8r_corpus() -> Vec<u8> {
    let mut s = String::new();
    for i in 0..512 {
        s.push_str("token");
        s.push(char::from_u32(0x0410 + (i % 0x40)).unwrap()); // А..я
        s.push(char::from_u32(0x0410 + ((i * 17) % 0x40)).unwrap());
    }
    s.into_bytes()
}

fn cp949_corpus() -> Vec<u8> {
    // ASCII runs interleaved with scattered Hangul syllables (U+AC00..U+D7A3, all
    // CP949-encodable as 2 bytes). The ASCII breaks the SIMD 3-byte encode window so
    // both the gather AND its scalar fall-through (ASCII, window boundaries) are
    // exercised; the diverse (non-contiguous) code points make it a cache-bound
    // encode-table access, matching the utf8_to_cp949_diverse bench.
    let mut s = String::new();
    for i in 0..600usize {
        s.push_str("ab");
        for k in 0..5usize {
            s.push(char::from_u32(0xAC00 + ((i * 7 + k * 811) % 0x2B00) as u32).unwrap());
        }
    }
    s.into_bytes()
}

fn convert(to: &[u8], src: &[u8]) -> Vec<u8> {
    let mut cd = iconv_open(to, b"UTF-8").expect("iconv_open");
    let mut out = vec![0u8; src.len() * 4 + 16];
    let r = iconv(&mut cd, Some(src), &mut out).expect("iconv");
    out.truncate(r.out_written);
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn iconv_utf8_fastpath_golden_sha256() {
    let src = corpus();
    // (target, pinned sha256 of the converted bytes).
    let pins: &[(&[u8], &str)] = &[
        (
            b"UTF-32LE",
            "9382fecee5c337ccff5db539b234eea072d55cac913068cd7b9c992d43379cb3",
        ),
        (
            b"UTF-32BE",
            "5fd675572d6cd289805314c18263fc0f1a612657bd6fe3db8648ed9799a32836",
        ),
        (
            b"UTF-16LE",
            "a894b8ad38008d8a86c591b35d4ef280758b3ccaaadabfad77b4a2e77fe81645",
        ),
        (
            b"UTF-16BE",
            "5f57cff0b2b725f9a1160cc00fee638092cb4c17bb9292f9228c304f640affa6",
        ),
    ];
    for (to, pin) in pins {
        let out = convert(to, &src);
        let got = hex(&out);
        eprintln!(
            "{}: sha256={got} ({}B)",
            String::from_utf8_lossy(to),
            out.len()
        );
        if !pin.starts_with("__P") {
            assert_eq!(
                &got,
                pin,
                "iconv UTF-8->{} golden drifted",
                String::from_utf8_lossy(to)
            );
        }
    }
}

#[test]
fn iconv_utf8_to_koi8r_golden_sha256() {
    let out = convert(b"KOI8-R", &koi8r_corpus());
    let got = hex(&out);
    eprintln!("KOI8-R: sha256={got} ({}B)", out.len());
    let pin = "05ea74b960f361549e1add14afdf2a3ba6c48df9229b0687b0a0e3c880e65fbb";
    if !pin.starts_with("__P") {
        assert_eq!(&got, pin, "iconv UTF-8->KOI8-R golden drifted");
    }
}

#[test]
fn iconv_utf8_to_cp949_golden_sha256() {
    // Guards the SIMD UTF-8 -> 2-byte-DBCS encode gather (byte-identical to the scalar
    // encode_cp949). Pinned after verifying the output matches live glibc via
    // conformance_diff_iconv.
    let out = convert(b"CP949", &cp949_corpus());
    let got = hex(&out);
    eprintln!("CP949: sha256={got} ({}B)", out.len());
    let pin = "f7d3abd0869048a769acea80b9edcb6f93bc7f0f85b3d288aa452d4f55ae4fa9";
    if !pin.starts_with("__P") {
        assert_eq!(&got, pin, "iconv UTF-8->CP949 golden drifted");
    }
}

fn cp932_corpus() -> Vec<u8> {
    // ASCII + Hiragana (U+3041.., 2-byte Shift-JIS — gather-handled) + half-width katakana
    // (U+FF71.., 1-byte in CP932 — breaks the SIMD gather's `>= 0x101` gate to the scalar path),
    // so both the 2-byte gather AND its 1-byte/scalar fall-through are exercised.
    let mut s = String::new();
    for i in 0..600usize {
        s.push_str("ab");
        for k in 0..5usize {
            s.push(char::from_u32(0x3041 + ((i * 3 + k * 7) % 0x53) as u32).unwrap());
        }
        if i % 4 == 0 {
            s.push(char::from_u32(0xFF71 + (i % 0x2D) as u32).unwrap());
        }
    }
    s.into_bytes()
}

#[test]
fn iconv_utf8_to_cp932_golden_sha256() {
    // Guards the CP932/Shift-JIS arm of the SIMD encode gather + the scalar-inline guard drift
    // fix (Cp932 was missing from the fast-path guard). Pinned after verifying vs live glibc.
    let out = convert(b"CP932", &cp932_corpus());
    let got = hex(&out);
    eprintln!("CP932: sha256={got} ({}B)", out.len());
    let pin = "47eb292c5a03e69f45bc3ef4eb43cae01645ca9f4faebd7b707ccf9f6b46f5f4";
    if !pin.starts_with("__P") {
        assert_eq!(&got, pin, "iconv UTF-8->CP932 golden drifted");
    }
}
