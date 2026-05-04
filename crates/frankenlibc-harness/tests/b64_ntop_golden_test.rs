//! Golden artifact: `frankenlibc_core::resolv::b64::ntop` byte-exact
//! snapshot for the full 0..=255 single-byte input sweep plus the seven
//! RFC 4648 §10 test vectors.
//!
//! The artifact at `tests/conformance/b64_ntop_golden.v1.json` freezes:
//!
//!   * `alphabet_sha256` — SHA-256 of the recovered 64-byte alphabet
//!     (derived from running ntop on a 48-byte input that exercises
//!     every 6-bit code-point exactly once).
//!   * `pad_byte` — the literal padding byte (RFC 4648 `=`).
//!   * `sweep_sha256` — SHA-256 of the concatenation, in input order,
//!     of `ntop([b])` followed by a single NUL terminator for each
//!     `b` in `0..=255`.
//!   * `rfc4648_vectors` — explicit (input_hex, encoded) rows for the
//!     seven RFC 4648 §10 test inputs.
//!
//! Any change to `ALPHABET`, `PAD`, or the 6-bit extraction logic
//! immediately fails this test with a byte-level diagnosis.

use frankenlibc_core::resolv::b64;
use sha2::{Digest, Sha256};

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn ntop_concat(input: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; 4 * input.len().div_ceil(3) + 1];
    let n = b64::ntop(input, &mut buf).expect("ntop must fit when target is 4*ceil(n/3)+1");
    buf.truncate(n);
    buf
}

fn alphabet_recovered() -> Vec<u8> {
    // 48 bytes encoding all 64 code-points exactly once. The 64
    // big-endian 6-bit values [0, 1, 2, ..., 63] packed as little-
    // endian-shuffled triples make the encoder emit the 64 alphabet
    // bytes in order, with no padding (48 mod 3 == 0).
    let mut input = Vec::with_capacity(48);
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    for code in 0u8..64 {
        bits = (bits << 6) | (code as u64);
        nbits += 6;
        while nbits >= 8 {
            nbits -= 8;
            input.push(((bits >> nbits) & 0xff) as u8);
        }
    }
    assert_eq!(input.len(), 48);
    let encoded = ntop_concat(&input);
    assert_eq!(
        encoded.len(),
        64,
        "48-byte input must produce a 64-byte un-padded encoding"
    );
    encoded
}

fn sweep_sha256() -> [u8; 32] {
    let mut hasher = Sha256::new();
    for b in 0u16..=255 {
        let encoded = ntop_concat(&[b as u8]);
        hasher.update(&encoded);
        hasher.update([0u8]);
    }
    hasher.finalize().into()
}

fn alphabet_sha256() -> [u8; 32] {
    let alphabet = alphabet_recovered();
    Sha256::digest(&alphabet).into()
}

fn golden_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("tests/conformance/b64_ntop_golden.v1.json")
}

#[test]
fn alphabet_and_sweep_fingerprints_match_golden() {
    let golden_text = std::fs::read_to_string(golden_path())
        .expect("tests/conformance/b64_ntop_golden.v1.json must exist");
    let golden: serde_json::Value =
        serde_json::from_str(&golden_text).expect("golden artifact must parse as JSON");

    assert_eq!(
        golden["schema_version"].as_str(),
        Some("v1"),
        "schema_version drift"
    );
    assert_eq!(golden["bead"].as_str(), Some("bd-j9h3e"), "bead-id drift");

    let live_alphabet_hex = hex_lower(&alphabet_sha256());
    let golden_alphabet_hex = golden["alphabet_sha256"].as_str().unwrap_or_default();
    assert_eq!(
        live_alphabet_hex, golden_alphabet_hex,
        "ALPHABET drift: ntop's 64-byte alphabet recovered from a 48-byte exhaustive sweep no longer hashes to the frozen value. Update the golden artifact only if the alphabet change is intentional and RFC 4648 still holds."
    );

    let live_sweep_hex = hex_lower(&sweep_sha256());
    let golden_sweep_hex = golden["sweep_sha256"].as_str().unwrap_or_default();
    assert_eq!(
        live_sweep_hex, golden_sweep_hex,
        "ntop single-byte 0..=255 sweep drift: any change to alphabet, padding emission, or bit-extraction will land here"
    );

    assert_eq!(
        golden["pad_byte"].as_str(),
        Some("="),
        "frozen pad_byte must remain `=`"
    );
}

#[test]
fn rfc4648_vectors_match_golden_byte_for_byte() {
    let golden_text = std::fs::read_to_string(golden_path())
        .expect("tests/conformance/b64_ntop_golden.v1.json must exist");
    let golden: serde_json::Value =
        serde_json::from_str(&golden_text).expect("golden artifact must parse as JSON");
    let vectors = golden["rfc4648_vectors"]
        .as_array()
        .expect("rfc4648_vectors must be an array");

    assert!(
        !vectors.is_empty(),
        "rfc4648_vectors must contain at least one test vector"
    );

    for (i, row) in vectors.iter().enumerate() {
        let input_hex = row["input_hex"].as_str().unwrap_or_default();
        let expected_encoded = row["encoded"].as_str().unwrap_or_default();

        let mut input = Vec::with_capacity(input_hex.len() / 2);
        let bytes = input_hex.as_bytes();
        let mut idx = 0;
        while idx + 1 < bytes.len() {
            let hi = (bytes[idx] as char).to_digit(16).expect("hex digit");
            let lo = (bytes[idx + 1] as char).to_digit(16).expect("hex digit");
            input.push(((hi << 4) | lo) as u8);
            idx += 2;
        }

        let encoded = ntop_concat(&input);
        let encoded_str = std::str::from_utf8(&encoded).expect("ntop output is ASCII");
        assert_eq!(
            encoded_str, expected_encoded,
            "rfc4648_vectors[{i}]: input_hex={input_hex:?} encoded drifted from golden"
        );
    }
}
