//! Metamorphic tests for `frankenlibc_core::resolv::b64` (RFC 4648 base64).
//!
//! Round-trip equality is already covered by in-module unit tests. This file
//! adds metamorphic relations that hold regardless of input value:
//!
//!   M1. Output-alphabet closure: every byte of ntop output is in
//!       `[A-Za-z0-9+/=]` — note that libresolv `__b64_ntop` *does* emit
//!       `=` padding per RFC 4648 §4 when `srclen % 3 != 0`, so `=` is
//!       part of the alphabet by design and must be permitted by the
//!       sweep.
//!   M2. Encoded length is exactly `4 * ceil(srclen / 3)` and is always a
//!       multiple of 4 (for non-empty input).
//!   M3. Concatenation monotonicity: `len(ntop(a ++ b)) >= len(ntop(a))`.
//!   M4. Idempotence on canonical encodings: `pton(ntop(x)) == x`, and
//!       re-encoding the result reproduces the original ntop bytes.
//!   M5. Whitespace invariance: pton accepts the canonical encoding with
//!       arbitrary internal whitespace and yields the same plaintext.
//!   M6. Padding-character count matches RFC 4648 §4: ntop emits exactly
//!       `(3 - srclen % 3) % 3` `=` characters — 0, 2, or 1 — and they
//!       only appear at the very end of the output. This pins both the
//!       padding count *and* its position; alphabet drift that admitted
//!       `=` mid-stream would be caught here even if M1 still passed.
//!
//! These relations are differential against the *function itself* across
//! correlated inputs, so they catch divergences (length drift, alphabet
//! drift, idempotence loss, padding drift) without needing an oracle.

use frankenlibc_core::resolv::b64;

fn ntop_to_string(src: &[u8]) -> String {
    let cap = 4 * src.len().div_ceil(3) + 1;
    let mut buf = vec![0u8; cap];
    let n = b64::ntop(src, &mut buf).expect("ntop must fit when target = 4*ceil(n/3)+1");
    // ntop writes a NUL terminator at index n; payload is buf[..n].
    assert_eq!(buf[n], 0, "ntop must NUL-terminate at returned length");
    String::from_utf8(buf[..n].to_vec()).expect("ntop output is ASCII")
}

fn pton_bytes(src: &[u8]) -> Vec<u8> {
    let cap = b64::decoded_len(src).expect("decoded_len must succeed for canonical input");
    let mut buf = vec![0u8; cap.max(1)];
    let n = b64::pton(src, &mut buf).expect("pton must succeed for canonical input");
    buf.truncate(n);
    buf
}

#[test]
fn m1_output_alphabet_closure_for_full_byte_range_inputs() {
    // Sweep the full single-byte range plus a deterministic mixed-byte set.
    for n in 0..=255usize {
        let input: Vec<u8> = (0..=n as u8).collect();
        let encoded = ntop_to_string(&input);
        for (i, ch) in encoded.bytes().enumerate() {
            let in_alphabet =
                matches!(ch, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=');
            assert!(
                in_alphabet,
                "ntop output[{i}] = 0x{ch:02x} for input len={} is outside the RFC 4648 alphabet",
                input.len()
            );
        }
    }
}

#[test]
fn m2_encoded_length_is_multiple_of_four_and_matches_formula() {
    for n in 1..=300usize {
        let input = vec![0xA5u8; n];
        let encoded = ntop_to_string(&input);
        let expected = 4 * n.div_ceil(3);
        assert_eq!(
            encoded.len(),
            expected,
            "len(ntop) drift at srclen={n}: expected {expected}, got {}",
            encoded.len()
        );
        assert_eq!(
            encoded.len() % 4,
            0,
            "ntop output length must be a multiple of 4 (got {} for srclen={n})",
            encoded.len()
        );
    }
}

#[test]
fn m3_concatenation_monotonicity_in_encoded_length() {
    let prefixes: [&[u8]; 6] = [b"", b"a", b"ab", b"abc", b"abcd", b"abcde"];
    let suffix: &[u8] = b"-suffix-payload";
    for prefix in prefixes {
        let head = ntop_to_string(prefix);
        let mut joined = prefix.to_vec();
        joined.extend_from_slice(suffix);
        let combined = ntop_to_string(&joined);
        assert!(
            combined.len() >= head.len(),
            "concatenation must not shrink encoded length: prefix.len()={} head.len()={} combined.len()={}",
            prefix.len(),
            head.len(),
            combined.len()
        );
    }
}

#[test]
fn m4_idempotence_on_canonical_encodings() {
    let inputs: &[&[u8]] = &[
        b"",
        b"f",
        b"fo",
        b"foo",
        b"foob",
        b"fooba",
        b"foobar",
        b"\x00\x01\x02\x03\x04\x05\x06\x07",
        &[0xFFu8; 17],
    ];
    for &input in inputs {
        let encoded = ntop_to_string(input);
        let decoded = pton_bytes(encoded.as_bytes());
        assert_eq!(
            decoded, input,
            "round-trip drift: input={input:?} encoded={encoded:?}"
        );
        let re_encoded = ntop_to_string(&decoded);
        assert_eq!(
            re_encoded, encoded,
            "re-encoding decoded bytes must reproduce the original ntop output (idempotence): {encoded:?} -> {decoded:?} -> {re_encoded:?}"
        );
    }
}

#[test]
fn m6_padding_count_matches_rfc4648_formula_and_only_appears_at_tail() {
    for n in 0..=300usize {
        // Use a deterministic non-trivial byte pattern so the encoder
        // exercises real bit-shuffling rather than zero-fill behavior.
        let input: Vec<u8> = (0..n).map(|i| (i * 17 + 3) as u8).collect();
        let encoded = ntop_to_string(&input);
        let pad_count = encoded.bytes().filter(|b| *b == b'=').count();
        let expected = (3 - n % 3) % 3;
        assert_eq!(
            pad_count, expected,
            "padding-count drift at srclen={n}: expected {expected} `=`, got {pad_count} (encoded={encoded:?})"
        );
        if pad_count > 0 {
            // Padding must be a contiguous suffix; equivalently, no `=`
            // may appear before the first `=`.
            let first_pad = encoded
                .find('=')
                .expect("pad_count > 0 implies `=` is present");
            assert_eq!(
                first_pad,
                encoded.len() - pad_count,
                "padding must be a contiguous suffix; encoded={encoded:?} first_pad={first_pad} pad_count={pad_count}"
            );
            for byte in encoded.bytes().take(first_pad) {
                assert_ne!(
                    byte, b'=',
                    "no `=` allowed before the first padding byte (encoded={encoded:?})"
                );
            }
        }
    }
}

#[test]
fn m5_pton_is_invariant_under_whitespace_injection() {
    let inputs: &[&[u8]] = &[
        b"foobar",
        b"the quick brown fox jumps over the lazy dog",
        &[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90],
    ];
    for &input in inputs {
        let encoded = ntop_to_string(input);
        // Insert one whitespace character between every two output bytes.
        let mut spaced = String::with_capacity(encoded.len() * 2);
        for (i, ch) in encoded.chars().enumerate() {
            if i > 0 && i.is_multiple_of(2) {
                spaced.push(' ');
            }
            spaced.push(ch);
        }
        let decoded_a = pton_bytes(encoded.as_bytes());
        let decoded_b = pton_bytes(spaced.as_bytes());
        assert_eq!(
            decoded_a, decoded_b,
            "pton must be invariant under inter-symbol whitespace: encoded={encoded:?} spaced={spaced:?}"
        );
        assert_eq!(
            decoded_a, input,
            "round-trip must hold for canonical encoding"
        );
    }
}
