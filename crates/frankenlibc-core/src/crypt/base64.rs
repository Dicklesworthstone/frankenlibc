//! crypt(3)-style base-64 encoding (the alphabet `./0-9A-Za-z`).
//!
//! Distinct from RFC 4648 base-64: different alphabet, no padding,
//! and the byte-packing order is little-endian (least-significant
//! 6 bits emitted first). Used by SHA-crypt ($5$, $6$) and MD5-crypt
//! ($1$) hash output formatting.

/// The 64-character crypt(3) alphabet.
pub const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Encode `input` to a `n_chars`-long crypt(3)-style base-64 string.
///
/// Bytes are accumulated into a 32-bit window with the LEAST-
/// significant bits filled first; 6-bit groups are extracted and
/// emitted as alphabet characters until either `n_chars` characters
/// have been produced or `input` is exhausted. If `input` doesn't
/// produce enough characters, the result is padded out with the
/// alphabet's first character (`'.'`).
pub fn encode(input: &[u8], n_chars: usize) -> String {
    if n_chars == 0 {
        return String::new();
    }
    let mut result = String::with_capacity(n_chars);
    let mut val: u32 = 0;
    let mut bits = 0u32;
    for &b in input {
        val |= (b as u32) << bits;
        bits += 8;
        while bits >= 6 && result.len() < n_chars {
            result.push(ALPHABET[(val & 0x3F) as usize] as char);
            val >>= 6;
            bits -= 6;
        }
        if result.len() >= n_chars {
            break;
        }
    }
    if bits > 0 && result.len() < n_chars {
        result.push(ALPHABET[(val & 0x3F) as usize] as char);
    }
    while result.len() < n_chars {
        result.push(ALPHABET[0] as char);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alphabet_has_64_chars() {
        assert_eq!(ALPHABET.len(), 64);
        // First two chars are special: . and /
        assert_eq!(ALPHABET[0], b'.');
        assert_eq!(ALPHABET[1], b'/');
        // Then 0-9, A-Z, a-z.
        assert_eq!(ALPHABET[2], b'0');
        assert_eq!(ALPHABET[12], b'A');
        assert_eq!(ALPHABET[38], b'a');
        assert_eq!(ALPHABET[63], b'z');
    }

    #[test]
    fn encode_zero_chars_returns_empty() {
        assert_eq!(encode(&[0xFF; 4], 0), "");
    }

    #[test]
    fn encode_three_bytes_to_four_chars() {
        // 24 bits in, 24 bits out (4 * 6).
        // Input 0x00, 0x00, 0x00 → all-zeros output.
        assert_eq!(encode(&[0, 0, 0], 4), "....");
        // 0xFF, 0xFF, 0xFF → all 1s in low 24 bits → 4 base-64 chars
        // each representing 0x3F. ALPHABET[63] = 'z'.
        assert_eq!(encode(&[0xFF, 0xFF, 0xFF], 4), "zzzz");
    }

    #[test]
    fn encode_packs_least_significant_first() {
        // Input [0x01, 0x00, 0x00]. After byte 0:
        //   val = 0x01, bits = 8 → emit (val & 0x3F) = 1 → '/'.
        //   val = 0x00, bits = 2.
        // After byte 1: val = 0x00, bits = 10 → emit '.', '.'.
        // After byte 2: similar.
        let s = encode(&[0x01, 0x00, 0x00], 4);
        assert_eq!(s.as_bytes()[0], b'/');
    }

    #[test]
    fn encode_pads_short_input_with_dots() {
        // 0 input bytes, but 5 chars requested.
        assert_eq!(encode(&[], 5), ".....");
        // 1 input byte (0x00) yields 2 chars then pads.
        assert_eq!(encode(&[0x00], 4), "....");
    }

    #[test]
    fn encode_truncates_when_n_chars_smaller_than_input() {
        // 4 bytes = 32 bits = 6 chars at 6 bits each, with 4 bits leftover.
        let full = encode(&[0xFF, 0xFF, 0xFF, 0xFF], 6);
        let truncated = encode(&[0xFF, 0xFF, 0xFF, 0xFF], 3);
        assert_eq!(full.len(), 6);
        assert_eq!(truncated.len(), 3);
        // The first chars of the truncated form should match the first
        // chars of the full form (LSB-first packing).
        assert_eq!(&full[..3], &truncated[..]);
    }

    #[test]
    fn encode_always_returns_n_chars() {
        for n in 0..32 {
            assert_eq!(encode(&[0x42; 8], n).len(), n);
        }
    }

    #[test]
    fn encode_one_byte_two_chars_known_values() {
        // 0x00 → val=0, then val=0 — both emit '.' = ALPHABET[0].
        assert_eq!(encode(&[0x00], 2), "..");
        // 0x01 → val=1, bits=8 → emit '/' (idx 1), val=0, bits=2 → emit '.'.
        assert_eq!(encode(&[0x01], 2), "/.");
    }
}
