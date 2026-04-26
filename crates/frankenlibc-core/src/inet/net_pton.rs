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
//! - `"0/0"` → no bytes, prefix `0`.
//!
//! When no `/N` suffix is given, the implicit prefix is the number
//! of dotted octets times 8 (i.e. `"192.168" → /16`). When a
//! suffix is given, only the first `⌈N/8⌉` bytes are written.
//!
//! Octets must be decimal in `[0, 255]`. The `0x...` hex form that
//! libresolv accepts is also supported here for byte-by-byte parity.

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
/// `dst` is filled left-to-right with `⌈prefix_bits / 8⌉` octets;
/// any unused tail of `dst` is left untouched.
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

    let mut octets = [0u8; 4];
    let mut octet_count = 0usize;
    let mut i = 0usize;

    loop {
        // Parse one decimal octet (1..=3 digits, value <= 255).
        let mut value: u32 = 0;
        let digit_start = i;
        while i < input.len() && input[i].is_ascii_digit() && i - digit_start < 3 {
            value = value * 10 + (input[i] - b'0') as u32;
            i += 1;
        }
        if i == digit_start {
            // No digits where an octet was expected.
            return Err(NetPtonError::Invalid);
        }
        if value > 255 {
            return Err(NetPtonError::Invalid);
        }
        if octet_count >= 4 {
            // More than 4 octets in the dotted form is malformed.
            return Err(NetPtonError::Invalid);
        }
        octets[octet_count] = value as u8;
        octet_count += 1;

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
        while i < input.len() && input[i].is_ascii_digit() && i - prefix_start < 3 {
            p = p * 10 + (input[i] - b'0') as u32;
            i += 1;
        }
        if i == prefix_start || i != input.len() || p > 32 {
            return Err(NetPtonError::Invalid);
        }
        p
    } else if i != input.len() {
        return Err(NetPtonError::Invalid);
    } else {
        // No /N: implicit prefix is octet_count * 8.
        (octet_count as u32) * 8
    };

    let bytes_needed = prefix_bits.div_ceil(8) as usize;
    if dst.len() < bytes_needed {
        return Err(NetPtonError::BufferTooSmall);
    }
    dst[..bytes_needed].copy_from_slice(&octets[..bytes_needed]);
    Ok(prefix_bits)
}

/// Render `bytes[..⌈prefix_bits/8⌉]` plus the prefix suffix into a
/// CIDR string. Mirrors libresolv `inet_net_ntop(3)` for AF_INET.
///
/// The output omits the `/prefix` suffix when `prefix_bits == 32`
/// AND the address is a complete 4-byte form — matching libresolv's
/// "host address" shorthand.
pub fn format(bytes: &[u8], prefix_bits: u32) -> Result<Vec<u8>, NetPtonError> {
    if prefix_bits > 32 {
        return Err(NetPtonError::Invalid);
    }
    let bytes_needed = prefix_bits.div_ceil(8) as usize;
    if bytes.len() < bytes_needed {
        return Err(NetPtonError::BufferTooSmall);
    }

    let mut out = Vec::with_capacity(20);
    for (i, &byte) in bytes.iter().enumerate().take(bytes_needed) {
        if i > 0 {
            out.push(b'.');
        }
        write_decimal(&mut out, byte as u32);
    }
    // Always emit the /prefix when the prefix is < 32 (network) or
    // when the prefix is not a multiple of 8 (partial-octet network).
    // For /32 with all 4 octets we elide it (host shorthand).
    if !(prefix_bits == 32 && bytes_needed == 4) {
        out.push(b'/');
        write_decimal(&mut out, prefix_bits);
    }
    Ok(out)
}

/// Hex form `0xHHHH...` — libresolv quirk preserved for byte parity.
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
    // padded with a low-half zero (libresolv parity).
    let bytes_in: usize = nibbles.len().div_ceil(2);
    if bytes_in > 4 {
        return Err(NetPtonError::Invalid);
    }
    let mut octets = [0u8; 4];
    for (idx, chunk) in nibbles.chunks(2).enumerate() {
        let hi = chunk[0];
        let lo = if chunk.len() == 2 { chunk[1] } else { 0 };
        octets[idx] = (hi << 4) | lo;
    }

    // Optional /prefix.
    let prefix_bits: u32 = if i < input.len() && input[i] == b'/' {
        i += 1;
        let prefix_start = i;
        let mut p: u32 = 0;
        while i < input.len() && input[i].is_ascii_digit() && i - prefix_start < 3 {
            p = p * 10 + (input[i] - b'0') as u32;
            i += 1;
        }
        if i == prefix_start || i != input.len() || p > 32 {
            return Err(NetPtonError::Invalid);
        }
        p
    } else if i != input.len() {
        return Err(NetPtonError::Invalid);
    } else {
        (bytes_in as u32) * 8
    };

    let bytes_needed = prefix_bits.div_ceil(8) as usize;
    if dst.len() < bytes_needed {
        return Err(NetPtonError::BufferTooSmall);
    }
    dst[..bytes_needed].copy_from_slice(&octets[..bytes_needed]);
    Ok(prefix_bits)
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
    fn parse_explicit_prefix() {
        let mut dst = [0u8; 4];
        let p = parse(b"192.168.0/24", &mut dst).unwrap();
        assert_eq!(p, 24);
        assert_eq!(&dst[..3], &[192, 168, 0]);
    }

    #[test]
    fn parse_explicit_prefix_zero() {
        let mut dst = [0u8; 4];
        let p = parse(b"0/0", &mut dst).unwrap();
        assert_eq!(p, 0);
        // No bytes written for prefix 0.
    }

    #[test]
    fn parse_explicit_prefix_8_with_one_octet() {
        let mut dst = [0u8; 4];
        let p = parse(b"10/8", &mut dst).unwrap();
        assert_eq!(p, 8);
        assert_eq!(dst[0], 10);
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
    fn parse_too_many_octets_is_invalid() {
        let mut dst = [0u8; 8];
        assert_eq!(parse(b"1.2.3.4.5", &mut dst), Err(NetPtonError::Invalid));
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
    fn parse_hex_uppercase_x() {
        let mut dst = [0u8; 4];
        let p = parse(b"0XAB", &mut dst).unwrap();
        assert_eq!(p, 8);
        assert_eq!(dst[0], 0xAB);
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
        // /32 with full 4 bytes elides the prefix suffix.
        assert_eq!(s, b"192.168.0.1");
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
        assert_eq!(s, b"/0");
    }

    #[test]
    fn format_partial_octet_prefix() {
        let bytes = [10u8, 1, 2];
        let s = format(&bytes, 20).unwrap();
        assert_eq!(s, b"10.1.2/20");
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
        let cases: &[&[u8]] = &[
            b"10/8",
            b"10.0/16",
            b"192.168.0/24",
            b"10.1.2/20",
            b"192.168.0.1",
        ];
        for &input in cases {
            let mut dst = [0u8; 4];
            let p = parse(input, &mut dst).unwrap();
            let bytes_used = (p as usize).div_ceil(8);
            let formatted = format(&dst[..bytes_used], p).unwrap();
            assert_eq!(formatted, input, "round trip for {:?}", input);
        }
    }
}
