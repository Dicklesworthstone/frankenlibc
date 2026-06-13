#![cfg(target_os = "linux")]
//! Golden-output gate for the SIMD-re-entry restructure of `mbstowcs` / `wcstombs`
//! in `frankenlibc_core::string::wchar`.
//!
//! Those converters previously ran the SIMD ASCII fast path once, then fell to a
//! scalar `mbtowc`/`wctomb` loop for the ENTIRE remainder of the string — so a
//! single early non-ASCII character forced a long ASCII tail through the scalar
//! path (~10x slower). The loops now INTERLEAVE: after each scalar character the
//! SIMD run is re-attempted, vectorising mixed text and ASCII tails. The output
//! must stay byte-for-byte identical. This pins a SHA-256 over a corpus
//! engineered to exercise the interleaving (ASCII runs, early non-ASCII, long
//! ASCII tails, 2/3/4-byte sequences) in addition to the live-glibc
//! `conformance_diff_wchar` and the core SIMD-vs-scalar property tests.

use frankenlibc_core::string::wchar::{mbstowcs, wcstombs};
use sha2::{Digest, Sha256};

fn corpus() -> Vec<u8> {
    let mut s = String::new();
    // Early non-ASCII followed by a long ASCII tail (the re-entry case).
    s.push_str("café ");
    s.push_str(&"the quick brown fox jumps over the lazy dog ".repeat(40));
    // Mixed runs: ASCII tokens interleaved with 2/3/4-byte scalars.
    for i in 0..200 {
        s.push_str("token ");
        s.push(char::from_u32(0x0410 + (i % 0x40)).unwrap()); // Cyrillic (2-byte)
        s.push_str("word ");
        s.push(char::from_u32(0x4E00 + (i % 0x100)).unwrap()); // CJK (3-byte)
        if i % 4 == 0 {
            s.push('🚀'); // U+1F680 (4-byte)
        }
        s.push_str("tail text here ");
    }
    s.into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn mbstowcs_wcstombs_reentry_golden_sha256() {
    let src = corpus();

    // UTF-8 bytes -> wide (UTF-32 codepoints).
    let mut wide = vec![0u32; src.len() + 1];
    let n = mbstowcs(&mut wide, &src).expect("mbstowcs");
    wide.truncate(n);
    let wide_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
    let wide_hash = hex(&wide_bytes);

    // Wide -> UTF-8 bytes (round trip; must reproduce the original).
    let mut back = vec![0u8; src.len() + 4];
    let m = wcstombs(&mut back, &wide).expect("wcstombs");
    back.truncate(m);
    let back_hash = hex(&back);

    eprintln!("mbstowcs wide sha256={wide_hash} ({n} wc)");
    eprintln!("wcstombs back sha256={back_hash} ({m} B)");

    assert_eq!(
        back, src,
        "wcstombs(mbstowcs(x)) must round-trip to the original UTF-8"
    );
    assert_eq!(
        wide_hash, "e52563fe0c036cc2d97d9b14a28d8d0e3adeec307686eecf8122466ca95dab50",
        "mbstowcs golden drifted"
    );
    assert_eq!(
        back_hash, "5f71c2382d1655e56994e4022f3e88be237d22350f6af9bd744680ec108aad6e",
        "wcstombs golden drifted"
    );
}
