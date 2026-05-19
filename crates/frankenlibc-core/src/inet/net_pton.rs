//! BIND/libresolv `inet_net_pton` / `inet_net_ntop` — IPv4 CIDR
//! string codec.
//!
//! Pure-safe Rust port. The C ABI shim in
//! `frankenlibc-abi::glibc_internal_abi` handles raw-pointer
//! plumbing, the `af` argument (AF_INET only here), and the
//! libresolv error contract (return -1, set errno).
//!
//! ## Semantics (libresolv `inet_net_pton(3)`)
//!
//! Accepts a CIDR-like string and returns the prefix length in
//! bits along with the address bytes (left-justified):
//!
//! - `"192.168.0.1"` → bytes `[192, 168, 0, 1]`, prefix `32`.
//! - `"192.168.0/24"` → bytes `[192, 168, 0]`, prefix `24`.
//! - `"10.0/16"` → bytes `[10, 0]`, prefix `16`.
//! - `"10/8"` → bytes `[10]`, prefix `8`.
//! - `"0/0"` → supplied zero octet plus prefix `0`.
//!
//! When no `/N` suffix is given, libresolv uses classful network
//! defaults, widened by supplied octets for class A/B/C and class E
//! forms. For example, `"192"` and `"192.168"` both imply `/24`,
//! while `"10.0"` implies `/16`. Class D keeps the historical `/4`
//! network prefix even when more octets are supplied. When a suffix is
//! given, glibc still requires the destination to hold every address
//! component supplied by the input, even if the prefix would otherwise
//! need fewer bytes.
//!
//! Octets must be decimal in `[0, 255]`. The `0x...` hex form that
//! libresolv accepts is also supported: hex nibbles are packed into
//! bytes (an odd trailing nibble fills the high half) with no 4-byte
//! cap, and the same classful prefix inference and supplied-byte
//! copy rules apply as for the dotted-decimal form.

/// Reasons [`parse`] rejects an input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetPtonError {
    /// Empty input, missing octet between dots, octet > 255, prefix
    /// suffix that isn't decimal, prefix > 32, or trailing garbage.
    Invalid,
    /// Caller-supplied destination buffer is too small for the bytes
    /// implied by the prefix.
    BufferTooSmall,
}

/// Parse `input` (a CIDR-like network string) into the leading bytes
/// of `dst`. Returns the prefix length in bits on success, or the
/// matching [`NetPtonError`].
///
/// `dst` is filled left-to-right with the larger of
/// `⌈prefix_bits / 8⌉` and the supplied dotted-octet count; any
/// unused tail of `dst` is left untouched.
pub fn parse(input: &[u8], dst: &mut [u8]) -> Result<u32, NetPtonError> {
    if input.is_empty() {
        return Err(NetPtonError::Invalid);
    }

    // libresolv accepts a `0x` / `0X` hex form: "0xC0A80000/24" →
    // bytes [0xC0, 0xA8, 0x00, 0x00], prefix 24. Detect and parse
    // that branch first; the dotted-decimal grammar takes over
    // otherwise.
    if input.len() >= 2 && input[0] == b'0' && (input[1] == b'x' || input[1] == b'X') {
        return parse_hex(input, dst);
    }

    let mut octets = Vec::with_capacity(4);
    let mut i = 0usize;

    loop {
        // Parse one decimal octet. Libresolv treats leading-zero runs
        // as decimal, not octal, and accepts any digit count whose
        // final value is <= 255.
        let mut value: u32 = 0;
        let digit_start = i;
        while i < input.len() && input[i].is_ascii_digit() {
            value = value * 10 + (input[i] - b'0') as u32;
            if value > 255 {
                return Err(NetPtonError::Invalid);
            }
            i += 1;
        }
        if i == digit_start {
            // No digits where an octet was expected.
            return Err(NetPtonError::Invalid);
        }
        octets.push(value as u8);

        if i >= input.len() {
            break;
        }
        if input[i] == b'.' {
            i += 1;
            continue;
        }
        if input[i] == b'/' {
            break;
        }
        // Unrecognized byte after an octet.
        return Err(NetPtonError::Invalid);
    }

    // Optional /prefix.
    let prefix_bits: u32 = if i < input.len() && input[i] == b'/' {
        i += 1;
        let prefix_start = i;
        let mut p: u32 = 0;
        while i < input.len() && input[i].is_ascii_digit() {
            p = p * 10 + (input[i] - b'0') as u32;
            if p > 32 {
                return Err(NetPtonError::Invalid);
            }
            i += 1;
        }
        if i == prefix_start || i != input.len() {
            return Err(NetPtonError::Invalid);
        }
        p
    } else if i != input.len() {
        return Err(NetPtonError::Invalid);
    } else {
        // No /N: use libresolv's historical classful default.
        implicit_prefix_bits(octets[0], octets.len())
    };

    finalize(&octets, prefix_bits, dst)
}

/// Shared libresolv tail rule for both the decimal and hex grammars:
/// `dst` must hold the larger of `⌈prefix_bits / 8⌉` and the supplied
/// octet count, and is filled left-to-right with the octets followed
/// by zero padding. Any unused tail of `dst` is left untouched.
fn finalize(octets: &[u8], prefix_bits: u32, dst: &mut [u8]) -> Result<u32, NetPtonError> {
    let bytes_needed = prefix_bits.div_ceil(8) as usize;
    let required_capacity = bytes_needed.max(octets.len());
    if dst.len() < required_capacity {
        return Err(NetPtonError::BufferTooSmall);
    }
    for (idx, byte) in dst.iter_mut().enumerate().take(required_capacity) {
        *byte = octets.get(idx).copied().unwrap_or(0);
    }
    Ok(prefix_bits)
}

fn implicit_prefix_bits(first_octet: u8, supplied_octets: usize) -> u32 {
    let supplied_bits = (supplied_octets as u32) * 8;
    match first_octet {
        0..=127 => supplied_bits.max(8),
        128..=191 => supplied_bits.max(16),
        192..=223 => supplied_bits.max(24),
        224..=239 => 4,
        240..=255 => supplied_bits.max(32),
    }
}

/// Render `bytes[..⌈prefix_bits/8⌉]` plus the prefix suffix into a
/// CIDR string. Mirrors libresolv `inet_net_ntop(3)` for AF_INET.
///
/// Conforming to libresolv: always emit the `/prefix` suffix, mask the
/// final partial-octet to the prefix boundary, and emit the full
/// all-zero dotted quad for `prefix_bits == 0`.
pub fn format(bytes: &[u8], prefix_bits: u32) -> Result<Vec<u8>, NetPtonError> {
    if prefix_bits > 32 {
        return Err(NetPtonError::Invalid);
    }
    let bytes_needed = prefix_bits.div_ceil(8) as usize;
    if bytes.len() < bytes_needed {
        return Err(NetPtonError::BufferTooSmall);
    }

    let mut out = Vec::with_capacity(20);
    // libresolv renders a zero-width IPv4 network as the full
    // all-zero dotted quad ("0.0.0.0/0"), not as a bare "0/0".
    let emit_count = if prefix_bits == 0 {
        4
    } else {
        bytes_needed.max(1)
    };

    for i in 0..emit_count {
        if i > 0 {
            out.push(b'.');
        }
        let byte = if i < bytes.len() { bytes[i] } else { 0 };
        // Mask the final partial-octet to the prefix boundary so
        // bits beyond `prefix_bits` are emitted as zero — matches glibc.
        let masked = if (i + 1) * 8 > prefix_bits as usize && prefix_bits as usize > i * 8 {
            let kept_bits = prefix_bits as usize - i * 8;
            let mask: u8 = if kept_bits == 0 {
                0
            } else {
                (!0u8).wrapping_shl(8 - kept_bits as u32)
            };
            byte & mask
        } else if (i + 1) * 8 > prefix_bits as usize {
            // Octet entirely outside the prefix → zero.
            0
        } else {
            byte
        };
        write_decimal(&mut out, masked as u32);
    }
    out.push(b'/');
    write_decimal(&mut out, prefix_bits);
    Ok(out)
}

/// Hex form `0xHHHH...` — libresolv nibble grammar preserved for byte
/// parity. libresolv places no 4-byte cap on this form, writes every
/// parsed byte regardless of the prefix, and (when no `/N` is given)
/// infers the prefix classfully from the first octet just like the
/// dotted-decimal grammar.
fn parse_hex(input: &[u8], dst: &mut [u8]) -> Result<u32, NetPtonError> {
    let mut i = 2usize; // skip "0x"
    let mut nibbles: Vec<u8> = Vec::with_capacity(8);
    while i < input.len() && input[i] != b'/' {
        let v = match input[i] {
            b'0'..=b'9' => input[i] - b'0',
            b'a'..=b'f' => input[i] - b'a' + 10,
            b'A'..=b'F' => input[i] - b'A' + 10,
            _ => return Err(NetPtonError::Invalid),
        };
        nibbles.push(v);
        i += 1;
    }
    if nibbles.is_empty() {
        return Err(NetPtonError::Invalid);
    }
    // Each pair of nibbles becomes a byte; an odd trailing nibble is
    // shifted into the high half (libresolv parity).
    let octets: Vec<u8> = nibbles
        .chunks(2)
        .map(|chunk| {
            let hi = chunk[0];
            let lo = if chunk.len() == 2 { chunk[1] } else { 0 };
            (hi << 4) | lo
        })
        .collect();

    // Optional /prefix.
    let prefix_bits: u32 = if i < input.len() && input[i] == b'/' {
        i += 1;
        let prefix_start = i;
        let mut p: u32 = 0;
        while i < input.len() && input[i].is_ascii_digit() {
            p = p * 10 + (input[i] - b'0') as u32;
            if p > 32 {
                return Err(NetPtonError::Invalid);
            }
            i += 1;
        }
        if i == prefix_start || i != input.len() {
            return Err(NetPtonError::Invalid);
        }
        p
    } else if i != input.len() {
        return Err(NetPtonError::Invalid);
    } else {
        // No `/N`: libresolv infers a classful prefix from the first
        // octet, identically to the dotted-decimal form.
        implicit_prefix_bits(octets[0], octets.len())
    };

    finalize(&octets, prefix_bits, dst)
}

fn write_decimal(out: &mut Vec<u8>, value: u32) {
    let mut tmp = [0u8; 4];
    let mut len = 0usize;
    let mut v = value;
    if v == 0 {
        out.push(b'0');
        return;
    }
    while v > 0 {
        tmp[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
    }
    for i in 0..len {
        out.push(tmp[len - 1 - i]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse ----

    #[test]
    fn parse_full_dotted_quad() {
        let mut dst = [0u8; 4];
        let p = parse(b"192.168.0.1", &mut dst).unwrap();
        assert_eq!(p, 32);
        assert_eq!(dst, [192, 168, 0, 1]);
    }

    #[test]
    fn parse_implicit_prefix_three_octets() {
        let mut dst = [0u8; 4];
        let p = parse(b"192.168.0", &mut dst).unwrap();
        assert_eq!(p, 24);
        assert_eq!(&dst[..3], &[192, 168, 0]);
        assert_eq!(dst[3], 0, "tail of dst must remain untouched");
    }

    #[test]
    fn parse_implicit_prefix_two_octets() {
        let mut dst = [0u8; 4];
        let p = parse(b"10.0", &mut dst).unwrap();
        assert_eq!(p, 16);
        assert_eq!(&dst[..2], &[10, 0]);
    }

    #[test]
    fn parse_implicit_prefix_one_octet() {
        let mut dst = [0u8; 4];
        let p = parse(b"10", &mut dst).unwrap();
        assert_eq!(p, 8);
        assert_eq!(dst[0], 10);
    }

    #[test]
    fn parse_classful_implicit_prefixes() {
        let mut class_b = [0u8; 4];
        let p = parse(b"128.1", &mut class_b).unwrap();
        assert_eq!(p, 16);
        assert_eq!(&class_b[..2], &[128, 1]);

        let mut class_c = [0u8; 4];
        let p = parse(b"192.168", &mut class_c).unwrap();
        assert_eq!(p, 24);
        assert_eq!(&class_c[..3], &[192, 168, 0]);

        let mut class_d = [0u8; 4];
        let p = parse(b"224.1.2.3", &mut class_d).unwrap();
        assert_eq!(p, 4);
        assert_eq!(&class_d[..4], &[224, 1, 2, 3]);

        let mut class_e = [0u8; 4];
        let p = parse(b"240", &mut class_e).unwrap();
        assert_eq!(p, 32);
        assert_eq!(&class_e[..4], &[240, 0, 0, 0]);
    }

    #[test]
    fn parse_explicit_prefix() {
        let mut dst = [0u8; 4];
        let p = parse(b"192.168.0/24", &mut dst).unwrap();
        assert_eq!(p, 24);
        assert_eq!(&dst[..3], &[192, 168, 0]);
    }

    #[test]
    fn parse_explicit_prefix_zero() {
        let mut dst = [9u8; 4];
        let p = parse(b"0/0", &mut dst).unwrap();
        assert_eq!(p, 0);
        assert_eq!(dst[0], 0);
        assert_eq!(&dst[1..], &[9, 9, 9]);
    }

    #[test]
    fn parse_explicit_prefix_zero_requires_supplied_octet_capacity() {
        let mut dst = [];
        assert_eq!(parse(b"0/0", &mut dst), Err(NetPtonError::BufferTooSmall));
    }

    #[test]
    fn parse_explicit_prefix_8_with_one_octet() {
        let mut dst = [0u8; 4];
        let p = parse(b"10/8", &mut dst).unwrap();
        assert_eq!(p, 8);
        assert_eq!(dst[0], 10);
    }

    #[test]
    fn parse_leading_zero_octets_are_decimal() {
        let mut dst = [0u8; 4];
        let p = parse(b"0177/8", &mut dst).unwrap();
        assert_eq!(p, 8);
        assert_eq!(dst[0], 177);
    }

    #[test]
    fn parse_partial_octet_prefix() {
        // /20 needs ⌈20/8⌉ = 3 bytes.
        let mut dst = [0u8; 4];
        let p = parse(b"10.1.2/20", &mut dst).unwrap();
        assert_eq!(p, 20);
        assert_eq!(&dst[..3], &[10, 1, 2]);
    }

    // ---- error paths ----

    #[test]
    fn parse_empty_is_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_octet_overflow_is_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"256.0.0.1", &mut dst), Err(NetPtonError::Invalid));
        assert_eq!(parse(b"999", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_extra_octets_match_libresolv_component_copy() {
        let mut dst = [0u8; 8];
        let p = parse(b"1.2.3.4.5", &mut dst).unwrap();
        assert_eq!(p, 40);
        assert_eq!(&dst[..5], &[1, 2, 3, 4, 5]);

        let mut explicit = [0u8; 8];
        let p = parse(b"1.2.3.4.5/24", &mut explicit).unwrap();
        assert_eq!(p, 24);
        assert_eq!(&explicit[..5], &[1, 2, 3, 4, 5]);

        let mut too_small = [0u8; 4];
        assert_eq!(
            parse(b"1.2.3.4.5/24", &mut too_small),
            Err(NetPtonError::BufferTooSmall)
        );

        assert_eq!(parse(b"1.2.3.4.5/40", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_double_dot_is_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"192..168", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_trailing_dot_is_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"192.168.", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_prefix_too_large_is_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(
            parse(b"192.168.0.1/33", &mut dst),
            Err(NetPtonError::Invalid)
        );
        assert_eq!(parse(b"10/100", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_prefix_missing_after_slash() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"192.168/", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_garbage_after_prefix_is_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"10/8x", &mut dst), Err(NetPtonError::Invalid));
        assert_eq!(parse(b"10/8/16", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_buffer_too_small() {
        let mut dst = [0u8; 1];
        assert_eq!(
            parse(b"192.168.0/24", &mut dst),
            Err(NetPtonError::BufferTooSmall)
        );

        let mut explicit_four_octets = [0u8; 3];
        assert_eq!(
            parse(b"192.168.1.0/24", &mut explicit_four_octets),
            Err(NetPtonError::BufferTooSmall)
        );
    }

    // ---- hex form ----

    #[test]
    fn parse_hex_form() {
        let mut dst = [0u8; 4];
        let p = parse(b"0xC0A80001", &mut dst).unwrap();
        assert_eq!(p, 32);
        assert_eq!(dst, [0xC0, 0xA8, 0x00, 0x01]);
    }

    #[test]
    fn parse_hex_with_explicit_prefix() {
        let mut dst = [0u8; 4];
        let p = parse(b"0xC0A80000/24", &mut dst).unwrap();
        assert_eq!(p, 24);
        assert_eq!(&dst[..3], &[0xC0, 0xA8, 0x00]);
    }

    #[test]
    fn parse_hex_prefix_requires_supplied_byte_capacity() {
        let mut dst = [0u8; 3];
        assert_eq!(
            parse(b"0xC0A80000/24", &mut dst),
            Err(NetPtonError::BufferTooSmall)
        );
    }

    #[test]
    fn parse_hex_uppercase_x() {
        // 0xAB: first octet 0xAB (171) is class B, so the implicit
        // prefix is /16 and the address widens to two octets — host
        // glibc `inet_net_pton` returns 16 here, not the nibble count.
        let mut dst = [0u8; 4];
        let p = parse(b"0XAB", &mut dst).unwrap();
        assert_eq!(p, 16);
        assert_eq!(&dst[..2], &[0xAB, 0x00]);
    }

    #[test]
    fn parse_hex_implicit_prefix_is_classful() {
        // Host glibc `inet_net_pton` infers the prefix from the first
        // octet's class for the hex form, exactly as for dotted decimal.
        let mut class_a = [0u8; 4];
        assert_eq!(parse(b"0x0A", &mut class_a).unwrap(), 8);
        assert_eq!(class_a[0], 0x0A);

        let mut class_c = [0u8; 4];
        assert_eq!(parse(b"0xC0A8", &mut class_c).unwrap(), 24);
        assert_eq!(&class_c[..3], &[0xC0, 0xA8, 0x00]);

        let mut class_e = [0u8; 4];
        assert_eq!(parse(b"0xF0", &mut class_e).unwrap(), 32);
        assert_eq!(class_e, [0xF0, 0, 0, 0]);
    }

    #[test]
    fn parse_hex_explicit_prefix_writes_every_supplied_byte() {
        // A short `/N` must not discard hex octets beyond the prefix:
        // host glibc writes every parsed byte; `/N` only sets the bits.
        let mut dst = [0u8; 4];
        let p = parse(b"0xC0A80001/8", &mut dst).unwrap();
        assert_eq!(p, 8);
        assert_eq!(dst, [0xC0, 0xA8, 0x00, 0x01]);
    }

    #[test]
    fn parse_hex_accepts_more_than_four_bytes() {
        // libresolv places no 4-byte cap on the hex form.
        let mut dst = [0u8; 8];
        let p = parse(b"0x0102030405", &mut dst).unwrap();
        assert_eq!(p, 40);
        assert_eq!(&dst[..5], &[1, 2, 3, 4, 5]);

        let mut explicit = [0u8; 8];
        let p = parse(b"0x0102030405/8", &mut explicit).unwrap();
        assert_eq!(p, 8);
        assert_eq!(&explicit[..5], &[1, 2, 3, 4, 5]);

        let mut too_small = [0u8; 4];
        assert_eq!(
            parse(b"0x0102030405", &mut too_small),
            Err(NetPtonError::BufferTooSmall)
        );
    }

    #[test]
    fn parse_hex_invalid_digit() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"0xZZ", &mut dst), Err(NetPtonError::Invalid));
    }

    #[test]
    fn parse_hex_only_prefix() {
        let mut dst = [0u8; 4];
        assert_eq!(parse(b"0x", &mut dst), Err(NetPtonError::Invalid));
    }

    // ---- format ----

    #[test]
    fn format_full_host_address() {
        let bytes = [192u8, 168, 0, 1];
        let s = format(&bytes, 32).unwrap();
        // libresolv always emits the /prefix suffix — no host shorthand.
        assert_eq!(s, b"192.168.0.1/32");
    }

    #[test]
    fn format_24_bit_network() {
        let bytes = [192u8, 168, 0];
        let s = format(&bytes, 24).unwrap();
        assert_eq!(s, b"192.168.0/24");
    }

    #[test]
    fn format_16_bit_network() {
        let bytes = [10u8, 0];
        let s = format(&bytes, 16).unwrap();
        assert_eq!(s, b"10.0/16");
    }

    #[test]
    fn format_8_bit_network() {
        let bytes = [10u8];
        let s = format(&bytes, 8).unwrap();
        assert_eq!(s, b"10/8");
    }

    #[test]
    fn format_zero_prefix() {
        let bytes = [];
        let s = format(&bytes, 0).unwrap();
        assert_eq!(s, b"0.0.0.0/0");
    }

    #[test]
    fn format_partial_octet_prefix() {
        let bytes = [10u8, 1, 2];
        let s = format(&bytes, 20).unwrap();
        // /20 = 8+8+4 bits; the third octet is masked to its top 4 bits,
        // so 2 (0b00000010) becomes 0 — matches glibc.
        assert_eq!(s, b"10.1.0/20");
    }

    #[test]
    fn format_buffer_too_small() {
        let bytes = [10u8];
        // /16 needs 2 bytes; buf has 1.
        assert_eq!(format(&bytes, 16), Err(NetPtonError::BufferTooSmall));
    }

    #[test]
    fn format_prefix_above_32_is_invalid() {
        let bytes = [10u8; 4];
        assert_eq!(format(&bytes, 33), Err(NetPtonError::Invalid));
    }

    // ---- round trip ----

    #[test]
    fn round_trip_canonical_forms() {
        // After the libresolv-aligned format fix:
        //   /32 emits the suffix (no host shorthand)
        //   /20 masks partial octets to bit boundary
        let cases: &[(&[u8], &[u8])] = &[
            (b"10/8", b"10/8"),
            (b"0/0", b"0.0.0.0/0"),
            (b"10.0/16", b"10.0/16"),
            (b"192.168.0/24", b"192.168.0/24"),
            (b"10.1.2/20", b"10.1.0/20"),
            (b"192.168.0.1", b"192.168.0.1/32"),
        ];
        for &(input, expected_round) in cases {
            let mut dst = [0u8; 4];
            let p = parse(input, &mut dst).unwrap();
            let bytes_used = (p as usize).div_ceil(8);
            let formatted = format(&dst[..bytes_used], p).unwrap();
            assert_eq!(formatted, expected_round, "round trip for {:?}", input);
        }
    }
}
