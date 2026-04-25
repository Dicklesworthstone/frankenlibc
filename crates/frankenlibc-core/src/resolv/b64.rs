//! BIND/libresolv `__b64_ntop` / `__b64_pton` — RFC 4648 base64.
//!
//! These are the BIND-derived MIME base64 encoder/decoder originally
//! shipped in `libresolv` and used by name servers, DNSSEC tooling,
//! and anything that links against the resolver library.
//!
//! ## Distinct from existing base64 modules in this crate
//!
//! | Module                              | Alphabet                     | Padding | Bit order |
//! |-------------------------------------|------------------------------|---------|-----------|
//! | `crypt::base64` (SHA-crypt)         | `./0-9A-Za-z`                | none    | LSB-first |
//! | `stdlib::base64` (System V a64l)    | `./0-9A-Za-z`                | none    | LSB-first |
//! | `resolv::b64` (this module)         | `A-Za-z0-9+/`                | `=`     | MSB-first |
//!
//! The algorithms are RFC 4648 §4 standard base64. We tolerate
//! whitespace and `\r\n` between groups (`b64_pton` matches the
//! libresolv quirk of permitting line breaks).

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PAD: u8 = b'=';

/// Encode `src` as RFC 4648 base64 into `target`, NUL-terminating it.
/// Returns the number of bytes written excluding the trailing NUL,
/// or `None` if `target` is too small to hold the encoded data plus
/// the terminator.
///
/// `target` must have room for `4 * ceil(srclen/3) + 1` bytes (the
/// trailing `+1` is the NUL).
pub fn ntop(src: &[u8], target: &mut [u8]) -> Option<usize> {
    let needed = encoded_len(src.len()).checked_add(1)?;
    if target.len() < needed {
        return None;
    }

    let mut o = 0usize;
    let chunks = src.chunks_exact(3);
    let remainder = chunks.remainder();
    for c in chunks {
        let v = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        target[o] = ALPHABET[((v >> 18) & 0x3f) as usize];
        target[o + 1] = ALPHABET[((v >> 12) & 0x3f) as usize];
        target[o + 2] = ALPHABET[((v >> 6) & 0x3f) as usize];
        target[o + 3] = ALPHABET[(v & 0x3f) as usize];
        o += 4;
    }

    match remainder.len() {
        0 => {}
        1 => {
            let v = (remainder[0] as u32) << 16;
            target[o] = ALPHABET[((v >> 18) & 0x3f) as usize];
            target[o + 1] = ALPHABET[((v >> 12) & 0x3f) as usize];
            target[o + 2] = PAD;
            target[o + 3] = PAD;
            o += 4;
        }
        2 => {
            let v = ((remainder[0] as u32) << 16) | ((remainder[1] as u32) << 8);
            target[o] = ALPHABET[((v >> 18) & 0x3f) as usize];
            target[o + 1] = ALPHABET[((v >> 12) & 0x3f) as usize];
            target[o + 2] = ALPHABET[((v >> 6) & 0x3f) as usize];
            target[o + 3] = PAD;
            o += 4;
        }
        _ => unreachable!(),
    }

    target[o] = 0;
    Some(o)
}

/// Decode `src` (NUL-terminated base64 ASCII string given as a byte
/// slice) into `target`, returning the number of binary bytes written
/// or `None` on:
///
/// - non-base64 character encountered before a `=` or NUL,
/// - mismatched/misplaced padding,
/// - `target` too small for the decoded output.
///
/// Whitespace (`' '`, `\t`, `\r`, `\n`) inside `src` is silently
/// skipped to match libresolv `__b64_pton`. Decoding stops at the
/// first NUL byte if one is encountered.
pub fn pton(src: &[u8], target: &mut [u8]) -> Option<usize> {
    pton_impl(src, Some(target))
}

/// Return the decoded byte length for `src` without writing output.
///
/// This follows the same validation rules as [`pton`], including whitespace,
/// padding, NUL termination, and canonical-padding checks. It exists for the
/// libresolv ABI query mode where callers pass `target == NULL`.
pub fn decoded_len(src: &[u8]) -> Option<usize> {
    pton_impl(src, None)
}

fn pton_impl(src: &[u8], mut target: Option<&mut [u8]>) -> Option<usize> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut o = 0usize;
    let mut padding = 0u32;
    let mut seen_pad = false;

    for &c in src {
        if c == 0 {
            break;
        }
        // Skip whitespace anywhere — libresolv allows wrapped base64.
        if c == b' ' || c == b'\t' || c == b'\r' || c == b'\n' {
            continue;
        }
        if c == PAD {
            seen_pad = true;
            padding += 1;
            // RFC 4648: at most two `=` per group.
            if padding > 2 {
                return None;
            }
            continue;
        }
        if seen_pad {
            // Any non-padding non-whitespace byte after padding is invalid.
            return None;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | (v as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let byte = ((acc >> bits) & 0xff) as u8;
            if let Some(out) = target.as_deref_mut() {
                if o >= out.len() {
                    return None;
                }
                out[o] = byte;
            }
            o += 1;
        }
    }

    // Validate padding: total alphabet+padding chars (excluding
    // whitespace) must be a multiple of 4. After emitting full bytes,
    // the bit-accumulator residue tells us which group shape we saw:
    //
    // - 4 alphabet chars, no padding   → 24 bits → 3 bytes, bits = 0.
    // - 3 alphabet chars + `=`         → 18 bits → 2 bytes, bits = 2.
    // - 2 alphabet chars + `==`        → 12 bits → 1 byte,  bits = 4.
    let valid_terminal = match padding {
        0 => bits == 0,
        1 => bits == 2,
        2 => bits == 4,
        _ => false,
    };
    if !valid_terminal {
        return None;
    }

    // Any leftover bits represent partial-byte garbage — they must
    // be zero (RFC 4648 §3.5 canonical encoding requirement, also
    // enforced by libresolv).
    if bits > 0 {
        let mask = (1u32 << bits) - 1;
        if (acc & mask) != 0 {
            return None;
        }
    }

    Some(o)
}

/// Encoded byte length (excluding NUL) for `srclen` raw bytes.
#[inline]
const fn encoded_len(srclen: usize) -> usize {
    srclen.div_ceil(3) * 4
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(input: &[u8]) -> String {
        // Generous buffer; the tests verify the returned length.
        let mut buf = vec![0u8; encoded_len(input.len()) + 1];
        let n = ntop(input, &mut buf).unwrap();
        String::from_utf8(buf[..n].to_vec()).unwrap()
    }

    fn dec(s: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; s.len()];
        let n = pton(s, &mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    // ---- ntop (encode) ----

    #[test]
    fn ntop_empty_yields_empty_with_nul() {
        let mut buf = [0xffu8; 8];
        let n = ntop(&[], &mut buf).unwrap();
        assert_eq!(n, 0);
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn ntop_rfc4648_basic_vectors() {
        // RFC 4648 §10 test vectors.
        assert_eq!(enc(b""), "");
        assert_eq!(enc(b"f"), "Zg==");
        assert_eq!(enc(b"fo"), "Zm8=");
        assert_eq!(enc(b"foo"), "Zm9v");
        assert_eq!(enc(b"foob"), "Zm9vYg==");
        assert_eq!(enc(b"fooba"), "Zm9vYmE=");
        assert_eq!(enc(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn ntop_writes_nul_terminator() {
        let mut buf = [0xffu8; 16];
        let n = ntop(b"hi", &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], b"aGk=");
        assert_eq!(buf[n], 0, "trailing byte must be NUL");
    }

    #[test]
    fn ntop_returns_none_when_target_too_small() {
        // "foo" → 4 chars + NUL = 5 bytes needed.
        let mut buf = [0u8; 4];
        assert_eq!(ntop(b"foo", &mut buf), None);
    }

    #[test]
    fn ntop_handles_full_byte_range() {
        // 0..=255 is 256 bytes → 344 base64 chars + NUL = 345 bytes.
        let input: Vec<u8> = (0u8..=255).collect();
        let mut buf = vec![0u8; 1024];
        let n = ntop(&input, &mut buf).unwrap();
        assert_eq!(n, 344);
        // Round-trip check: decode the encoded string back into bytes.
        let decoded = dec(&buf[..n]);
        assert_eq!(decoded, input);
    }

    // ---- pton (decode) ----

    #[test]
    fn pton_empty_yields_empty() {
        assert_eq!(dec(b""), Vec::<u8>::new());
    }

    #[test]
    fn pton_rfc4648_basic_vectors() {
        assert_eq!(dec(b"Zg=="), b"f".to_vec());
        assert_eq!(dec(b"Zm8="), b"fo".to_vec());
        assert_eq!(dec(b"Zm9v"), b"foo".to_vec());
        assert_eq!(dec(b"Zm9vYg=="), b"foob".to_vec());
        assert_eq!(dec(b"Zm9vYmE="), b"fooba".to_vec());
        assert_eq!(dec(b"Zm9vYmFy"), b"foobar".to_vec());
    }

    #[test]
    fn decoded_len_matches_pton_without_allocating_output() {
        assert_eq!(decoded_len(b""), Some(0));
        assert_eq!(decoded_len(b"Zg=="), Some(1));
        assert_eq!(decoded_len(b"Zm8="), Some(2));
        assert_eq!(decoded_len(b"Zm9v"), Some(3));
        assert_eq!(decoded_len(b"Zm9v\nYmFy\0ignored"), Some(6));
    }

    #[test]
    fn pton_skips_whitespace() {
        // Newlines / spaces / tabs inside encoded data are tolerated
        // (libresolv permits wrapped base64).
        assert_eq!(dec(b"Zm9v YmFy"), b"foobar".to_vec());
        assert_eq!(dec(b"Zm9v\nYmFy"), b"foobar".to_vec());
        assert_eq!(dec(b"Zm9v\r\nYmFy"), b"foobar".to_vec());
        assert_eq!(dec(b"  Zm9v\tYmFy  "), b"foobar".to_vec());
    }

    #[test]
    fn pton_stops_at_nul() {
        // Bytes after a NUL byte are ignored.
        let mut buf = [0u8; 32];
        let mut input = b"Zm9v\0GARBAGE-AFTER-NUL".to_vec();
        // Append a NUL terminator just to be safe.
        input.push(0);
        let n = pton(&input, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"foo");
    }

    #[test]
    fn pton_rejects_invalid_char() {
        let mut buf = [0u8; 16];
        assert_eq!(pton(b"Zm9v!Zg==", &mut buf), None);
        assert_eq!(pton(b"@@@@", &mut buf), None);
    }

    #[test]
    fn pton_rejects_too_much_padding() {
        let mut buf = [0u8; 16];
        assert_eq!(pton(b"Zg===", &mut buf), None);
    }

    #[test]
    fn pton_rejects_misplaced_padding() {
        let mut buf = [0u8; 16];
        // Non-padding char after padding.
        assert_eq!(pton(b"Zg==Zg==", &mut buf), None);
    }

    #[test]
    fn pton_rejects_unaligned_input() {
        let mut buf = [0u8; 16];
        // 1 alphabet char alone is not a valid base64 group.
        assert_eq!(pton(b"Z", &mut buf), None);
        // 5 alphabet chars (1 leftover) without padding — invalid.
        assert_eq!(pton(b"Zm9vY", &mut buf), None);
    }

    #[test]
    fn pton_rejects_target_too_small() {
        let mut buf = [0u8; 1];
        // "Zm9v" decodes to 3 bytes; only 1 fits.
        assert_eq!(pton(b"Zm9v", &mut buf), None);
    }

    #[test]
    fn pton_rejects_noncanonical_padding_bits() {
        // "Zh==" — base64 alphabet 'Z'=25, 'h'=33 → 011001 100001 →
        // first byte 0x66 ('f'), then 4 leftover bits 0001 — non-zero.
        // libresolv rejects this canonical-encoding violation.
        let mut buf = [0u8; 4];
        assert_eq!(pton(b"Zh==", &mut buf), None);
        assert_eq!(decoded_len(b"Zh=="), None);
        // "Zg==" is canonical (4 leftover bits = 0000).
        assert_eq!(pton(b"Zg==", &mut buf), Some(1));
        assert_eq!(decoded_len(b"Zg=="), Some(1));
        assert_eq!(buf[0], b'f');
    }

    // ---- round trip ----

    #[test]
    fn round_trip_arbitrary_lengths() {
        let mut input = Vec::with_capacity(513);
        for i in 0..513 {
            input.push((i * 31 + 7) as u8);
        }
        for len in 0..input.len() {
            let chunk = &input[..len];
            let mut enc_buf = vec![0u8; encoded_len(len) + 1];
            let enc_n = ntop(chunk, &mut enc_buf).unwrap();
            let mut dec_buf = vec![0u8; chunk.len()];
            let dec_n = pton(&enc_buf[..enc_n], &mut dec_buf).unwrap();
            assert_eq!(dec_n, chunk.len(), "len mismatch at {len}");
            assert_eq!(&dec_buf[..dec_n], chunk, "bytes mismatch at {len}");
        }
    }

    #[test]
    fn round_trip_zero_byte_inputs() {
        for len in 0..16 {
            let zeros = vec![0u8; len];
            let mut enc_buf = vec![0u8; encoded_len(len) + 1];
            let enc_n = ntop(&zeros, &mut enc_buf).unwrap();
            let mut dec_buf = vec![0u8; len];
            let dec_n = pton(&enc_buf[..enc_n], &mut dec_buf).unwrap();
            assert_eq!(&dec_buf[..dec_n], &zeros[..]);
        }
    }
}
