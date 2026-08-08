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
/// `input` is consumed in **groups of three bytes**, each group packed
/// BIG-ENDIAN into a 24-bit word — first byte most significant — and then
/// emitted as characters least-significant 6 bits first. That is exactly
/// glibc's `b64_from_24bit(B2, B1, B0, N)` and FreeBSD's `to64(s, v, n)`
/// with `v = (B2 << 16) | (B1 << 8) | B0`. A short final group is
/// RIGHT-aligned, so its last byte is `B0`: `[x]` gives `x`, `[x, y]`
/// gives `(x << 8) | y`.
///
/// The grouping is the whole point and is why the byte-transposition tables
/// in `md5`/`sha256`/`sha512` list their indices in triples. This function
/// previously accumulated a single running LITTLE-endian bit stream across
/// the entire input, which packs each triple in the opposite order — i.e.
/// `(B0 << 16) | (B1 << 8) | B2`. Every digest it produced was therefore
/// well-formed, correct length, correct alphabet, and WRONG, for all three
/// algorithms at once, so no real `/etc/shadow` hash could ever verify.
/// bd-9n50f2.
pub fn encode(input: &[u8], n_chars: usize) -> String {
    if n_chars == 0 {
        return String::new();
    }
    let mut result = String::with_capacity(n_chars);
    for group in input.chunks(3) {
        if result.len() >= n_chars {
            break;
        }
        let mut word: u32 = 0;
        for &b in group {
            word = (word << 8) | b as u32;
        }
        // A full group yields 4 characters; the caller sizes `n_chars` so the
        // final (possibly short) group emits exactly what is left.
        let take = (n_chars - result.len()).min(4);
        for _ in 0..take {
            result.push(ALPHABET[(word & 0x3F) as usize] as char);
            word >>= 6;
        }
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
    fn encode_packs_group_big_endian_and_emits_lsb_first() {
        // This test previously asserted the first character of
        // encode([0x01, 0x00, 0x00], 4) was '/', i.e. that 0x01 landed in the
        // LOW 6 bits — the little-endian-stream behaviour that made every crypt
        // digest wrong (bd-9n50f2). It was a faithful description of the bug, so
        // it is replaced rather than adjusted.
        //
        // Reference semantics (glibc b64_from_24bit / FreeBSD to64): a 3-byte
        // group (B2, B1, B0) becomes w = (B2 << 16) | (B1 << 8) | B0, and the
        // characters come out least-significant 6 bits FIRST.
        //
        // For [0x01, 0x00, 0x00]: w = 0x010000 = 65536.
        //   65536        & 63 = 0  -> ALPHABET[0]  = '.'
        //   (65536 >> 6)  & 63 = 0  -> '.'
        //   (65536 >> 12) & 63 = 16 -> ALPHABET[16] = 'E'
        //   (65536 >> 18) & 63 = 0  -> '.'
        assert_eq!(encode(&[0x01, 0x00, 0x00], 4), "..E.");

        // And the low byte really is the last one in the group:
        // [0x00, 0x00, 0x01] -> w = 1 -> '/' then '.', '.', '.'.
        assert_eq!(encode(&[0x00, 0x00, 0x01], 4), "/...");

        // A short final group is RIGHT-aligned, so its last byte is B0. This is
        // what makes the md5 tail (`[f11]`, 2 chars) and the sha256 tail
        // (`[f31, f30]`, 3 chars) come out in glibc's order.
        assert_eq!(encode(&[0x01], 2), "/.");
        assert_eq!(encode(&[0x00, 0x01], 3), "/..");
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
