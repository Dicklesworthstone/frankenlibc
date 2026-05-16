#![no_main]
//! Structure-aware fuzz target for the core RFC 3492 Punycode codec.
//!
//! This target exercises the byte-level IDNA building block used by
//! `__idna_to_dns_encoding` and `__idna_from_dns_encoding`. It mixes
//! arbitrary encoded byte streams with normalized Unicode-label inputs
//! so libFuzzer can cover malformed varints, delimiter edge cases,
//! overflow guards, and encode/decode round-trips.
//!
//! Seed files can force a specific path with `decode:`, `cycle:`, or
//! `label_hex:` prefixes. `label_hex:` accepts space/comma/plus-separated
//! hexadecimal Unicode code points, e.g. `label_hex:0062 00FC 0063`.

use libfuzzer_sys::fuzz_target;

use frankenlibc_core::idna::punycode::{decode as parse_punycode, encode as render_punycode};

const MAX_LABEL_CODEPOINTS: usize = 64;
const MAX_ENCODED_BYTES: usize = 256;
const MAX_INPUT_BYTES: usize = 1024;

struct PunycodeFuzzInput<'a> {
    code_point_bytes: &'a [u8],
    encoded: &'a [u8],
    selector: u8,
    op: u8,
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }
    if try_directive_seed(data) {
        return;
    }

    let input = PunycodeFuzzInput::from_bytes(data);
    match input.op % 4 {
        0 => fuzz_unicode_roundtrip(input),
        1 => fuzz_decode_arbitrary(input),
        2 => fuzz_decode_encode_cycle(input),
        3 => fuzz_known_edges(input),
        _ => unreachable!(),
    }
});

impl<'a> PunycodeFuzzInput<'a> {
    fn from_bytes(data: &'a [u8]) -> Self {
        let selector = data.first().copied().unwrap_or_default();
        let op = data.get(1).copied().unwrap_or_default();
        let body = data.get(2..).unwrap_or_default();
        let split = if body.is_empty() {
            0
        } else {
            usize::from(selector) % (body.len() + 1)
        };
        Self {
            code_point_bytes: &body[..split],
            encoded: &body[split..],
            selector,
            op,
        }
    }
}

fn try_directive_seed(data: &[u8]) -> bool {
    if let Some(payload) = data.strip_prefix(b"decode:") {
        fuzz_decode_bytes(trim_seed_newline(payload));
        true
    } else if let Some(payload) = data.strip_prefix(b"cycle:") {
        fuzz_decode_encode_cycle_bytes(trim_seed_newline(payload));
        true
    } else if let Some(payload) = data.strip_prefix(b"label_hex:") {
        if let Some(label) = parse_hex_label(trim_seed_newline(payload)) {
            fuzz_unicode_label_roundtrip(&label);
        }
        true
    } else {
        false
    }
}

fn fuzz_unicode_roundtrip(input: PunycodeFuzzInput<'_>) {
    let label = normalized_label(input);
    fuzz_unicode_label_roundtrip(&label);
}

fn fuzz_unicode_label_roundtrip(label: &[u32]) {
    if label.is_empty() || !label.iter().any(|&cp| cp >= 0x80) {
        return;
    }

    let Some(encoded) = render_punycode(label) else {
        return;
    };
    assert!(encoded.len() <= MAX_ENCODED_BYTES * 2);

    let decoded = parse_punycode(&encoded).expect("encoded non-basic label should parse");
    assert_eq!(decoded, label);
}

fn fuzz_decode_arbitrary(input: PunycodeFuzzInput<'_>) {
    let bytes = bounded_encoded_bytes(input);
    fuzz_decode_bytes(&bytes);
}

fn fuzz_decode_bytes(bytes: &[u8]) {
    if let Some(decoded) = parse_punycode(bytes) {
        assert!(decoded.len() <= bytes.len().saturating_add(1));
        let _ = render_punycode(&decoded);
    }
}

fn fuzz_decode_encode_cycle(input: PunycodeFuzzInput<'_>) {
    let bytes = bounded_encoded_bytes(input);
    fuzz_decode_encode_cycle_bytes(&bytes);
}

fn fuzz_decode_encode_cycle_bytes(bytes: &[u8]) {
    let Some(decoded) = parse_punycode(bytes) else {
        return;
    };
    // All-basic labels ending in '-' are ambiguous because the parser
    // treats the last hyphen as a delimiter but the encoder emits ASCII
    // labels literally.
    if !decoded.iter().any(|&cp| cp >= 0x80) {
        return;
    }
    let Some(reencoded) = render_punycode(&decoded) else {
        return;
    };
    let decoded_again = parse_punycode(&reencoded).expect("re-encoded parsed label should parse");
    assert_eq!(decoded_again, decoded);
}

fn fuzz_known_edges(input: PunycodeFuzzInput<'_>) {
    let edge_inputs: &[&[u8]] = &[
        b"",
        b"-",
        b"--",
        b"a-",
        b"xn--",
        b"bcher-kva",
        b"egbpdaj6bu4bxfgehfvwxn",
        b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];

    for &bytes in edge_inputs {
        if let Some(decoded) = parse_punycode(bytes) {
            let _ = render_punycode(&decoded);
        }
    }

    let mut label = normalized_label(input);
    label.extend_from_slice(&[0x80, 0x7ff, 0x800, 0xffff, 0x10ffff]);
    label.truncate(MAX_LABEL_CODEPOINTS);
    fuzz_unicode_label_roundtrip(&label);
}

fn bounded_encoded_bytes(input: PunycodeFuzzInput<'_>) -> Vec<u8> {
    input
        .encoded
        .iter()
        .take(MAX_ENCODED_BYTES)
        .map(|&b| match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' => b,
            _ if input.selector & 1 == 0 => b'a' + (b % 26),
            _ => b,
        })
        .collect()
}

fn normalized_label(input: PunycodeFuzzInput<'_>) -> Vec<u32> {
    input
        .code_point_bytes
        .chunks(4)
        .take(MAX_LABEL_CODEPOINTS)
        .enumerate()
        .filter_map(|(idx, chunk)| {
            normalize_code_point(chunk_to_u32(chunk), input.selector.wrapping_add(idx as u8))
        })
        .collect()
}

fn chunk_to_u32(chunk: &[u8]) -> u32 {
    let mut bytes = [0u8; 4];
    bytes[..chunk.len()].copy_from_slice(chunk);
    u32::from_le_bytes(bytes)
}

fn normalize_code_point(raw: u32, selector: u8) -> Option<u32> {
    let cp = match selector % 8 {
        0 => u32::from(b'a' + (raw as u8 % 26)),
        1 => u32::from(b'0' + (raw as u8 % 10)),
        2 => u32::from(b'-'),
        3 => 0x80 + (raw % 0x80),
        4 => 0x400 + (raw % 0x400),
        5 => 0x4e00 + (raw % 0x400),
        6 => 0x10000 + (raw % 0x1000),
        _ => raw % 0x110000,
    };

    if (0xd800..=0xdfff).contains(&cp) {
        return None;
    }
    Some(cp)
}

fn trim_seed_newline(payload: &[u8]) -> &[u8] {
    payload
        .strip_suffix(b"\r\n")
        .or_else(|| payload.strip_suffix(b"\n"))
        .unwrap_or(payload)
}

fn parse_hex_label(payload: &[u8]) -> Option<Vec<u32>> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut label = Vec::new();
    for token in text.split(|c: char| c.is_ascii_whitespace() || matches!(c, ',' | '+')) {
        if token.is_empty() {
            continue;
        }
        let token = token
            .strip_prefix("U+")
            .or_else(|| token.strip_prefix("u+"))
            .or_else(|| token.strip_prefix("0x"))
            .or_else(|| token.strip_prefix("0X"))
            .unwrap_or(token);
        let cp = u32::from_str_radix(token, 16).ok()?;
        if cp > 0x10ffff || (0xd800..=0xdfff).contains(&cp) {
            return None;
        }
        label.push(cp);
        if label.len() > MAX_LABEL_CODEPOINTS {
            return None;
        }
    }
    (!label.is_empty()).then_some(label)
}
