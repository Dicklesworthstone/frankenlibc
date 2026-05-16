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

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::iconv;

const DIRECTED_PREFIX: &[u8] = b"iconv:";
const MAX_CODE: usize = 64;
const MAX_PAYLOAD: usize = 4096;

#[derive(Debug, Arbitrary)]
struct IconvFuzzInput {
    tocode: Vec<u8>,
    fromcode: Vec<u8>,
    payload: Vec<u8>,
    out_size: u16,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if let Some(input) = directed_input(data) {
        fuzz_iconv(input);
        return;
    }

    let mut raw = Unstructured::new(data);
    let Ok(input) = IconvFuzzInput::arbitrary(&mut raw) else {
        return;
    };

    fuzz_iconv(input);
});

fn fuzz_iconv(input: IconvFuzzInput) {
    match input.op % 4 {
        0 => fuzz_open_close(&input),
        1 => fuzz_convert(&input),
        2 => fuzz_determinism(&input),
        _ => fuzz_known_codecs(&input),
    }
}

/// Decode readable directed seeds shaped as:
///
/// ```text
/// iconv:<op>
/// to=<target-codec>
/// from=<source-codec>
/// payload=<plain bytes>
/// ```
///
/// Use `payload-hex=` with spaced hexadecimal bytes when the fixture needs
/// non-UTF-8 or NUL-containing payloads.
fn directed_input(data: &[u8]) -> Option<IconvFuzzInput> {
    let rest = data.strip_prefix(DIRECTED_PREFIX)?;
    let (op_name, body) = split_once_byte(rest, b'\n')?;
    let mut tocode = None;
    let mut fromcode = None;
    let mut payload = None;

    for raw_line in body.split(|&b| b == b'\n') {
        let line = strip_single_trailing_carriage_return(raw_line);
        if let Some(value) = line.strip_prefix(b"to=") {
            tocode = Some(value.to_vec());
        } else if let Some(value) = line.strip_prefix(b"from=") {
            fromcode = Some(value.to_vec());
        } else if let Some(value) = line.strip_prefix(b"payload=") {
            payload = Some(value.to_vec());
        } else if let Some(value) = line.strip_prefix(b"payload-hex=") {
            payload = Some(decode_spaced_hex(value)?);
        }
    }

    Some(IconvFuzzInput {
        tocode: tocode?,
        fromcode: fromcode?,
        payload: payload.unwrap_or_default(),
        out_size: 8192,
        op: directed_op(op_name)?,
    })
}

fn directed_op(op_name: &[u8]) -> Option<u8> {
    match op_name {
        b"open" => Some(0),
        b"convert" => Some(1),
        b"determinism" => Some(2),
        b"known" => Some(3),
        _ => None,
    }
}

fn decode_spaced_hex(raw: &[u8]) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut high_nibble = None;

    for &b in raw {
        if matches!(b, b' ' | b'\t' | b'_' | b'-') {
            continue;
        }

        let nibble = hex_nibble(b)?;
        if let Some(high) = high_nibble.take() {
            bytes.push((high << 4) | nibble);
        } else {
            high_nibble = Some(nibble);
        }
    }

    if high_nibble.is_some() {
        return None;
    }

    Some(bytes)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn split_once_byte(data: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let split_at = data.iter().position(|&b| b == byte)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(1..)?))
}

fn strip_single_trailing_carriage_return(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\r").unwrap_or(data)
}

fn bounded(data: &[u8], max: usize) -> &[u8] {
    data.get(..data.len().min(max)).unwrap_or(data)
}

fn fuzz_open_close(input: &IconvFuzzInput) {
    // Limit encoding name length to avoid degenerate cases.
    let tocode = bounded(&input.tocode, MAX_CODE);
    let fromcode = bounded(&input.fromcode, MAX_CODE);

    if let Some(cd) = iconv::iconv_open(tocode, fromcode) {
        let rc = iconv::iconv_close(cd);
        assert_eq!(rc, 0, "iconv_close should return 0 for valid descriptor");
    }
}

fn fuzz_convert(input: &IconvFuzzInput) {
    let tocode = bounded(&input.tocode, MAX_CODE);
    let fromcode = bounded(&input.fromcode, MAX_CODE);

    if let Some(mut cd) = iconv::iconv_open(tocode, fromcode) {
        let out_size = (input.out_size as usize).clamp(1, 8192);
        let mut outbuf = vec![0u8; out_size];
        let payload = bounded(&input.payload, MAX_PAYLOAD);

        // Should not panic regardless of input.
        let _ = iconv::iconv(&mut cd, Some(payload), &mut outbuf);
        let _ = iconv::iconv_close(cd);
    }
}

fn fuzz_determinism(input: &IconvFuzzInput) {
    let tocode = bounded(&input.tocode, MAX_CODE);
    let fromcode = bounded(&input.fromcode, MAX_CODE);

    if let Some(mut cd1) = iconv::iconv_open(tocode, fromcode) {
        if let Some(mut cd2) = iconv::iconv_open(tocode, fromcode) {
            let payload = bounded(&input.payload, 512);
            let out_size = (input.out_size as usize).clamp(1, 2048);
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
                    let out1_written = out1.get(..a.out_written).unwrap_or(&out1);
                    let out2_written = out2.get(..b.out_written).unwrap_or(&out2);
                    assert_eq!(
                        out1_written, out2_written,
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
    let Some(&(tocode, fromcode)) = pairs.get(idx) else {
        return;
    };

    if let Some(mut cd) = iconv::iconv_open(tocode, fromcode) {
        let payload = bounded(&input.payload, 2048);
        let mut outbuf = vec![0u8; payload.len().max(1) * 4];
        let _ = iconv::iconv(&mut cd, Some(payload), &mut outbuf);
        let _ = iconv::iconv_close(cd);
    }
}
