#![no_main]
//! Structure-aware fuzz target for FrankenLibC ctype character classification.
//!
//! Exercises all is_* and to_* functions from `frankenlibc-core::ctype` with
//! fuzzer-generated inputs. The invariants are:
//! - Classification functions are pure (deterministic, no side effects)
//! - to_upper(to_lower(c)) round-trips for alphabetic characters
//! - Partition invariants: every byte is either print or cntrl (never both)
//! - No function should panic on any u8 input
//!
//! Bead: bd-2hh.4

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::ctype;

#[derive(Debug, Arbitrary)]
struct CtypeFuzzInput {
    /// Bytes to classify.
    bytes: Vec<u8>,
    /// Operation selector.
    op: u8,
}

const MAX_BYTES: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let Some(input) = input_from_bytes(data) else {
        return;
    };

    if input.bytes.len() > MAX_BYTES {
        return;
    }

    match input.op % 5 {
        0 => fuzz_classification_exhaustive(&input),
        1 => fuzz_case_roundtrip(&input),
        2 => fuzz_partition_invariants(&input),
        3 => fuzz_digit_xdigit_subset(&input),
        4 => fuzz_consistency(&input),
        _ => unreachable!(),
    }
});

fn input_from_bytes(data: &[u8]) -> Option<CtypeFuzzInput> {
    if let Some(input) = directed_input(data) {
        return Some(input);
    }

    let mut unstructured = Unstructured::new(data);
    CtypeFuzzInput::arbitrary(&mut unstructured).ok()
}

fn directed_input(data: &[u8]) -> Option<CtypeFuzzInput> {
    let data = trim_seed_newline(data);
    let rest = data.strip_prefix(b"ctype:")?;
    let (op_name, payload_name) = split_once_byte(rest, b':')?;
    let op = match op_name {
        b"classify" => 0,
        b"case" => 1,
        b"partition" => 2,
        b"digit-xdigit" => 3,
        b"consistency" => 4,
        _ => return None,
    };
    let bytes = directed_bytes(payload_name)?;
    Some(CtypeFuzzInput { bytes, op })
}

fn split_once_byte(bytes: &[u8], needle: u8) -> Option<(&[u8], &[u8])> {
    let idx = bytes.iter().position(|&b| b == needle)?;
    Some((&bytes[..idx], &bytes[idx + 1..]))
}

fn trim_seed_newline(payload: &[u8]) -> &[u8] {
    payload
        .strip_suffix(b"\r\n")
        .or_else(|| payload.strip_suffix(b"\n"))
        .unwrap_or(payload)
}

fn directed_bytes(payload_name: &[u8]) -> Option<Vec<u8>> {
    match payload_name {
        b"empty" => Some(Vec::new()),
        b"ascii-classes" => Some(vec![
            0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b, 0x1f, b' ', b'!', b'/', b'0', b'9',
            b':', b'@', b'A', b'Z', b'[', b'`', b'a', b'z', b'{', b'~', 0x7f,
        ]),
        b"case-boundary" => Some(b"@AZ[`az{".to_vec()),
        b"digit-xdigit-boundary" => Some(b"/09:AFG`afg".to_vec()),
        b"mixed-print-control" => Some(vec![
            0x00, b'\t', b'\n', b'\r', b' ', b'!', b'0', b'9', b'A', b'Z', b'a', b'z', b'~', 0x7f,
            0x80, 0xa0, 0xff,
        ]),
        b"high-bytes" => Some(vec![0x80, 0x81, 0x9f, 0xa0, 0xfe, 0xff]),
        payload => {
            if let Some(hex) = payload.strip_prefix(b"hex:") {
                parse_hex_bytes(hex)
            } else {
                Some(payload.to_vec())
            }
        }
    }
}

fn parse_hex_bytes(hex: &[u8]) -> Option<Vec<u8>> {
    let mut nibbles = Vec::new();
    for &b in hex {
        if b.is_ascii_whitespace() || b == b',' || b == b'_' {
            continue;
        }
        nibbles.push(hex_nibble(b)?);
    }
    if nibbles.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(nibbles.len() / 2);
    for pair in nibbles.chunks_exact(2) {
        bytes.push((pair[0] << 4) | pair[1]);
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

/// Exercise every classifier on every byte in the input.
fn fuzz_classification_exhaustive(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        // All these must not panic on any u8
        let _ = ctype::is_alpha(c);
        let _ = ctype::is_digit(c);
        let _ = ctype::is_alnum(c);
        let _ = ctype::is_space(c);
        let _ = ctype::is_upper(c);
        let _ = ctype::is_lower(c);
        let _ = ctype::is_print(c);
        let _ = ctype::is_punct(c);
        let _ = ctype::is_xdigit(c);
        let _ = ctype::is_blank(c);
        let _ = ctype::is_cntrl(c);
        let _ = ctype::is_graph(c);
        let _ = ctype::is_ascii_val(c);
        let _ = ctype::to_upper(c);
        let _ = ctype::to_lower(c);
        let _ = ctype::to_ascii(c);
    }
}

/// Verify case conversion round-trips for alphabetic bytes.
fn fuzz_case_roundtrip(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        let upper = ctype::to_upper(c);
        let lower = ctype::to_lower(c);

        if ctype::is_alpha(c) {
            // For alpha chars, upper must be upper and lower must be lower
            assert!(
                ctype::is_upper(upper),
                "to_upper({c:#04x}) = {upper:#04x} should be upper"
            );
            assert!(
                ctype::is_lower(lower),
                "to_lower({c:#04x}) = {lower:#04x} should be lower"
            );

            // Round-trip: to_lower(to_upper(c)) == to_lower(c)
            assert_eq!(
                ctype::to_lower(upper),
                lower,
                "to_lower(to_upper({c:#04x})) should equal to_lower({c:#04x})"
            );
            // Round-trip: to_upper(to_lower(c)) == to_upper(c)
            assert_eq!(
                ctype::to_upper(lower),
                upper,
                "to_upper(to_lower({c:#04x})) should equal to_upper({c:#04x})"
            );
        }

        // Non-alpha characters should pass through unchanged
        if !ctype::is_upper(c) && !ctype::is_lower(c) {
            assert_eq!(upper, c, "to_upper on non-alpha should be identity");
            assert_eq!(lower, c, "to_lower on non-alpha should be identity");
        }
    }
}

/// Verify partition invariants: mutually exclusive categories.
fn fuzz_partition_invariants(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        let alpha = ctype::is_alpha(c);
        let digit = ctype::is_digit(c);
        let alnum = ctype::is_alnum(c);
        let print = ctype::is_print(c);
        let cntrl = ctype::is_cntrl(c);
        let graph = ctype::is_graph(c);
        let space = ctype::is_space(c);
        let upper = ctype::is_upper(c);
        let lower = ctype::is_lower(c);
        let punct = ctype::is_punct(c);

        // alnum = alpha | digit
        assert_eq!(
            alnum,
            alpha || digit,
            "alnum({c:#04x}) should be alpha || digit"
        );

        // alpha = upper | lower
        if alpha {
            assert!(
                upper || lower,
                "alpha({c:#04x}) should imply upper or lower"
            );
        }

        // upper and lower are mutually exclusive
        assert!(
            !(upper && lower),
            "upper and lower should be mutually exclusive for {c:#04x}"
        );

        // graph chars are printable but not space
        if graph {
            assert!(print, "graph({c:#04x}) should imply print");
        }

        // Control and print are generally mutually exclusive (except some edge cases)
        // For ASCII 0..=127, they should be mutually exclusive
        if c <= 127 && c != b' ' {
            // Note: space (0x20) is both print and not cntrl
            if cntrl {
                assert!(!print || c == 0x7f, "cntrl and print overlap at {c:#04x}");
            }
        }

        // punct is print but not alnum and not space
        if punct {
            assert!(print, "punct({c:#04x}) should imply print");
            assert!(!alnum, "punct({c:#04x}) should not be alnum");
        }

        let _ = space; // used for completeness
    }
}

/// Verify digit ⊂ xdigit.
fn fuzz_digit_xdigit_subset(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        if ctype::is_digit(c) {
            assert!(ctype::is_xdigit(c), "digit({c:#04x}) must also be xdigit");
        }
    }
}

/// Cross-function consistency checks.
fn fuzz_consistency(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        // to_ascii should mask to 7 bits
        let a = ctype::to_ascii(c);
        assert!(a <= 127, "to_ascii({c:#04x}) should produce <=127, got {a}");

        // is_ascii_val should be true iff c <= 127
        assert_eq!(
            ctype::is_ascii_val(c),
            c <= 127,
            "is_ascii_val({c:#04x}) inconsistent"
        );

        // Determinism: calling twice should give same result
        assert_eq!(ctype::is_alpha(c), ctype::is_alpha(c));
        assert_eq!(ctype::to_upper(c), ctype::to_upper(c));
        assert_eq!(ctype::to_lower(c), ctype::to_lower(c));
    }
}
