#![no_main]
//! Structure-aware fuzz target for FrankenLibC iconv (character set conversion).
//!
//! Exercises iconv_open, iconv, iconv_close with fuzzer-generated
//! encoding names and payload bytes. Invariants:
//! - No panics on any well-typed input
//! - iconv_close always returns 0 for valid descriptors
//! - Output never exceeds output buffer size
//! - Known codec pairs produce deterministic results
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::iconv;

#[derive(Debug, Arbitrary)]
struct IconvFuzzInput {
    tocode: Vec<u8>,
    fromcode: Vec<u8>,
    payload: Vec<u8>,
    out_size: u16,
    op: u8,
}

fuzz_target!(|input: IconvFuzzInput| {
    match input.op % 4 {
        0 => fuzz_open_close(&input),
        1 => fuzz_convert(&input),
        2 => fuzz_determinism(&input),
        _ => fuzz_known_codecs(&input),
    }
});

fn fuzz_open_close(input: &IconvFuzzInput) {
    // Limit encoding name length to avoid degenerate cases.
    let tocode = &input.tocode[..input.tocode.len().min(64)];
    let fromcode = &input.fromcode[..input.fromcode.len().min(64)];

    if let Some(cd) = iconv::iconv_open(tocode, fromcode) {
        let rc = iconv::iconv_close(cd);
        assert_eq!(rc, 0, "iconv_close should return 0 for valid descriptor");
    }
}

fn fuzz_convert(input: &IconvFuzzInput) {
    let tocode = &input.tocode[..input.tocode.len().min(64)];
    let fromcode = &input.fromcode[..input.fromcode.len().min(64)];

    if let Some(mut cd) = iconv::iconv_open(tocode, fromcode) {
        let out_size = (input.out_size as usize).max(1).min(8192);
        let mut outbuf = vec![0u8; out_size];
        let payload = &input.payload[..input.payload.len().min(4096)];

        // Should not panic regardless of input.
        let _ = iconv::iconv(&mut cd, Some(payload), &mut outbuf);
        let _ = iconv::iconv_close(cd);
    }
}

fn fuzz_determinism(input: &IconvFuzzInput) {
    let tocode = &input.tocode[..input.tocode.len().min(64)];
    let fromcode = &input.fromcode[..input.fromcode.len().min(64)];

    if let Some(mut cd1) = iconv::iconv_open(tocode, fromcode) {
        if let Some(mut cd2) = iconv::iconv_open(tocode, fromcode) {
            let payload = &input.payload[..input.payload.len().min(512)];
            let out_size = (input.out_size as usize).max(1).min(2048);
            let mut out1 = vec![0u8; out_size];
            let mut out2 = vec![0u8; out_size];

            let r1 = iconv::iconv(&mut cd1, Some(payload), &mut out1);
            let r2 = iconv::iconv(&mut cd2, Some(payload), &mut out2);
            assert_eq!(
                r1.is_ok(),
                r2.is_ok(),
                "determinism: one succeeded and one failed"
            );

            // Same input → same result.
            match (r1, r2) {
                (Ok(ref a), Ok(ref b)) => {
                    assert_eq!(a.out_written, b.out_written);
                    assert_eq!(
                        &out1[..a.out_written],
                        &out2[..b.out_written],
                        "determinism: same input should produce same output"
                    );
                }
                (Err(_), Err(_)) => {} // both failed — ok
                _ => {}
            }

            let _ = iconv::iconv_close(cd1);
            let _ = iconv::iconv_close(cd2);
        } else {
            let _ = iconv::iconv_close(cd1);
        }
    }
}

fn fuzz_known_codecs(input: &IconvFuzzInput) {
    // Use well-known codec pairs to exercise actual conversion paths.
    let pairs: &[(&[u8], &[u8])] = &[
        (b"UTF-8", b"UTF-8"),
        (b"ASCII", b"UTF-8"),
        (b"UTF-8", b"ASCII"),
        (b"ISO-8859-1", b"UTF-8"),
        (b"UTF-8", b"ISO-8859-1"),
    ];
    let idx = (input.op as usize / 4) % pairs.len();
    let (tocode, fromcode) = pairs[idx];

    if let Some(mut cd) = iconv::iconv_open(tocode, fromcode) {
        let payload = &input.payload[..input.payload.len().min(2048)];
        let mut outbuf = vec![0u8; payload.len().max(1) * 4];
        let _ = iconv::iconv(&mut cd, Some(payload), &mut outbuf);
        let _ = iconv::iconv_close(cd);
    }
}
