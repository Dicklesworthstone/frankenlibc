//! NSAP (Network Service Access Point) address conversion.
//!
//! Pure-safe Rust port of the byte-level logic that previously lived
//! inline in frankenlibc-abi/src/glibc_internal_abi.rs::inet_nsap_addr
//! and inet_nsap_ntoa. See ISO 8348 / RFC 1629 for the NSAP address
//! format; this module only implements the on-the-wire hex encoding
//! that glibc's `inet_nsap_addr` / `inet_nsap_ntoa` accept.
//!
//! Wire form: pairs of hex digits, optionally separated by `.`, `+`,
//! or `/` (all three are accepted on input, matching glibc).
//! Example: `47.0005+80/005a00.0000.0001.0001.eed7d4f3.00`
//! decodes to the corresponding 18 bytes. The `inet_nsap_ntoa`
//! output form is uppercase hex grouped as `XX.XXXX.XXXX...`.

/// Parse an NSAP hex address from `text` into `dst`, returning the
/// number of bytes written.
///
/// Returns `0` on any of:
///   - empty input,
///   - odd number of hex digits (truncated last byte),
///   - non-hex character outside `.` / `+` / `/` separators,
///   - input requires more than `dst.len()` bytes (truncates without
///     error otherwise — caller can detect via the returned count).
///
/// Separator characters (`.`, `+`, `/`) between hex byte pairs are
/// skipped, including leading, repeated, and trailing separators.
/// Separators inside a byte pair are rejected, matching host glibc's
/// `inet_nsap_addr` parser.
pub fn parse_nsap_addr(text: &[u8], dst: &mut [u8]) -> usize {
    let mut i = 0usize;
    let mut o = 0usize;
    while i < text.len() && o < dst.len() {
        while i < text.len() && is_separator(text[i]) {
            i += 1;
        }
        if i >= text.len() {
            break;
        }
        let hi = match hex_value(text[i]) {
            Some(v) => v,
            None => return 0,
        };
        i += 1;
        if i >= text.len() {
            return 0;
        }
        let lo = match hex_value(text[i]) {
            Some(v) => v,
            None => return 0,
        };
        i += 1;
        dst[o] = (hi << 4) | lo;
        o += 1;
    }
    o
}

/// Format `addr` bytes as the canonical NSAP hex form, matching glibc
/// `inet_nsap_ntoa`: uppercase hex, a `.` after every even-indexed
/// byte (so bytes group as `XX.XXXX.XXXX...`), and no trailing NUL.
/// glibc clamps the input length to 255 bytes; this does too.
pub fn format_nsap_addr(addr: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let addr = &addr[..addr.len().min(255)];
    let mut out = Vec::with_capacity(addr.len() * 3);
    for (i, &b) in addr.iter().enumerate() {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0F) as usize]);
        // glibc emits a separator after each even-indexed byte that is
        // not the last, producing a 1 + 2 + 2 + ... grouping.
        if i % 2 == 0 && i + 1 < addr.len() {
            out.push(b'.');
        }
    }
    out
}

#[inline]
fn is_separator(b: u8) -> bool {
    matches!(b, b'.' | b'+' | b'/')
}

#[inline]
fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_returns_zero() {
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"", &mut dst), 0);
    }

    #[test]
    fn parse_simple_pair() {
        let mut dst = [0u8; 16];
        let n = parse_nsap_addr(b"ab", &mut dst);
        assert_eq!(n, 1);
        assert_eq!(dst[0], 0xab);
    }

    #[test]
    fn parse_rejects_0x_prefix() {
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"0xab", &mut dst), 0);
        assert_eq!(parse_nsap_addr(b"0XCD", &mut dst), 0);
    }

    #[test]
    fn parse_with_dot_separators() {
        let mut dst = [0u8; 16];
        let n = parse_nsap_addr(b"01.23.45", &mut dst);
        assert_eq!(n, 3);
        assert_eq!(&dst[..3], &[0x01, 0x23, 0x45]);
    }

    #[test]
    fn parse_accepts_plus_and_slash_separators() {
        // glibc `inet_nsap_addr` skips `.`, `+`, and `/` alike.
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"ab+cd", &mut dst), 2);
        assert_eq!(&dst[..2], &[0xab, 0xcd]);

        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"ab/cd", &mut dst), 2);
        assert_eq!(&dst[..2], &[0xab, 0xcd]);

        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"47.0005+80/005a00", &mut dst), 7);
        assert_eq!(&dst[..7], &[0x47, 0x00, 0x05, 0x80, 0x00, 0x5a, 0x00]);

        // Leading and trailing `+` / `/` are skipped like `.`.
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"+ab/", &mut dst), 1);
        assert_eq!(dst[0], 0xab);
    }

    #[test]
    fn parse_rejects_space_separators() {
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"01 23 45", &mut dst), 0);
    }

    #[test]
    fn parse_rejects_mid_byte_separators() {
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"0.12345", &mut dst), 0);
        assert_eq!(parse_nsap_addr(b"01.2.3", &mut dst), 0);
        assert_eq!(parse_nsap_addr(b"012.3", &mut dst), 0);
    }

    #[test]
    fn parse_allows_dot_separators_around_complete_bytes() {
        let mut dst = [0u8; 16];
        let n = parse_nsap_addr(b"..ab..cd.", &mut dst);
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], &[0xab, 0xcd]);
    }

    #[test]
    fn parse_mixed_case_hex() {
        let mut dst = [0u8; 16];
        let n = parse_nsap_addr(b"AbCdEf", &mut dst);
        assert_eq!(n, 3);
        assert_eq!(&dst[..3], &[0xab, 0xcd, 0xef]);
    }

    #[test]
    fn parse_real_nsap_address() {
        // From RFC 1629 example.
        let text = b"47.0005.80.005a00.0000.0001.0001.eed7d4f3.00";
        let mut dst = [0u8; 32];
        let n = parse_nsap_addr(text, &mut dst);
        // 47 + 0005 + 80 + 005a00 + 0000 + 0001 + 0001 + eed7d4f3 + 00
        // = 1 + 2 + 1 + 3 + 2 + 2 + 2 + 4 + 1 = 18 bytes.
        assert_eq!(n, 18);
        assert_eq!(
            &dst[..n],
            &[
                0x47, 0x00, 0x05, 0x80, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xee,
                0xd7, 0xd4, 0xf3, 0x00,
            ]
        );
    }

    #[test]
    fn parse_rejects_odd_digit_count() {
        let mut dst = [0u8; 16];
        // "abc" — 3 hex digits, odd. After reading "ab" (1 byte), tries
        // to read "c" then needs another digit but input is exhausted.
        assert_eq!(parse_nsap_addr(b"abc", &mut dst), 0);
        assert_eq!(parse_nsap_addr(b"ab c.", &mut dst), 0);
    }

    #[test]
    fn parse_rejects_invalid_hex_char() {
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"abxz", &mut dst), 0);
        assert_eq!(parse_nsap_addr(b"!!", &mut dst), 0);
    }

    #[test]
    fn parse_rejects_invalid_lo_digit() {
        // "ab cz" — first byte ok, then 'c' as hi, 'z' as lo invalid.
        let mut dst = [0u8; 16];
        assert_eq!(parse_nsap_addr(b"ab cz", &mut dst), 0);
    }

    #[test]
    fn parse_truncates_at_dst_len() {
        let mut dst = [0u8; 2];
        let n = parse_nsap_addr(b"01020304", &mut dst);
        // Only 2 bytes fit.
        assert_eq!(n, 2);
        assert_eq!(&dst[..2], &[0x01, 0x02]);
    }

    #[test]
    fn parse_zero_dst_returns_zero() {
        let mut dst = [0u8; 0];
        assert_eq!(parse_nsap_addr(b"abcd", &mut dst), 0);
    }

    // ---- format_nsap_addr ----

    #[test]
    fn format_empty_returns_empty() {
        assert_eq!(format_nsap_addr(&[]), Vec::<u8>::new());
    }

    #[test]
    fn format_single_byte() {
        assert_eq!(format_nsap_addr(&[0xab]), b"AB".to_vec());
    }

    #[test]
    fn format_groups_bytes_one_then_pairs() {
        // glibc `inet_nsap_ntoa` emits a `.` after each even-indexed
        // byte, so 3 bytes render as `XX.XXXX`, not `XX.XX.XX`.
        assert_eq!(format_nsap_addr(&[0x01, 0x23, 0x45]), b"01.2345".to_vec());
        assert_eq!(
            format_nsap_addr(&[0x47, 0x00, 0x05, 0x80, 0x00, 0x5a]),
            b"47.0005.8000.5A".to_vec()
        );
    }

    #[test]
    fn format_uppercase_hex() {
        // glibc `inet_nsap_ntoa` emits uppercase hex digits.
        assert_eq!(format_nsap_addr(&[0xAB, 0xCD, 0xEF]), b"AB.CDEF".to_vec());
    }

    #[test]
    fn format_handles_zero_bytes() {
        assert_eq!(format_nsap_addr(&[0x00, 0x00, 0x00]), b"00.0000".to_vec());
    }

    #[test]
    fn format_byte_by_byte() {
        // Each byte produces exactly 2 hex chars.
        for b in 0u8..=255 {
            let s = format_nsap_addr(&[b]);
            assert_eq!(s.len(), 2);
            // Verify round-trip via parse.
            let mut roundtrip = [0u8; 1];
            assert_eq!(parse_nsap_addr(&s, &mut roundtrip), 1);
            assert_eq!(roundtrip[0], b);
        }
    }

    #[test]
    fn format_then_parse_round_trip() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x47, 0x00, 0x05],
            &[
                0x47, 0x00, 0x05, 0x80, 0x00, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0xee,
                0xd7, 0xd4, 0xf3,
            ],
            &[0xff; 32],
        ];
        for &input in cases {
            let formatted = format_nsap_addr(input);
            let mut parsed = vec![0u8; input.len()];
            let n = parse_nsap_addr(&formatted, &mut parsed);
            assert_eq!(n, input.len(), "round-trip length for {input:?}");
            assert_eq!(&parsed[..], input, "round-trip bytes for {input:?}");
        }
    }
}
