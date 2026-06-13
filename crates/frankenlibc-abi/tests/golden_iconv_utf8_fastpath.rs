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
        (b"UTF-32LE", "9382fecee5c337ccff5db539b234eea072d55cac913068cd7b9c992d43379cb3"),
        (b"UTF-32BE", "5fd675572d6cd289805314c18263fc0f1a612657bd6fe3db8648ed9799a32836"),
        (b"UTF-16LE", "a894b8ad38008d8a86c591b35d4ef280758b3ccaaadabfad77b4a2e77fe81645"),
        (b"UTF-16BE", "5f57cff0b2b725f9a1160cc00fee638092cb4c17bb9292f9228c304f640affa6"),
    ];
    for (to, pin) in pins {
        let out = convert(to, &src);
        let got = hex(&out);
        eprintln!("{}: sha256={got} ({}B)", String::from_utf8_lossy(to), out.len());
        if !pin.starts_with("__P") {
            assert_eq!(&got, pin, "iconv UTF-8->{} golden drifted", String::from_utf8_lossy(to));
        }
    }
}
