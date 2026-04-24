//! `<netinet/ether.h>` / `<net/ethernet.h>` — Ethernet address parser
//! and formatter.
//!
//! Pure-safe Rust port of the byte-level logic that previously lived
//! inline in frankenlibc-abi/src/unistd_abi.rs (parse_hex_nibble +
//! parse_ether_addr + format_ether_addr + ether_line).
//!
//! Address textual form: `xx:xx:xx:xx:xx:xx` where each `xx` is one or
//! two hex digits. Per glibc/BSD `ether_aton`, single-digit octets
//! are accepted (e.g. `0:0:0:0:0:0` round-trips through `ether_ntoa`
//! to `00:00:00:00:00:00`).

/// 6-byte Ethernet (MAC) address, the layout consumed by glibc's
/// `struct ether_addr { uint8_t ether_addr_octet[6]; }`.
pub type EtherAddr = [u8; 6];

/// Length of the canonical formatted form (17 bytes, no NUL).
pub const ETHER_ADDR_TEXT_LEN: usize = 17;

/// Parse a textual Ethernet address.
///
/// Accepts `xx:xx:xx:xx:xx:xx` with one or two hex digits per octet.
/// Returns `None` if any octet is missing, malformed, or if there is
/// trailing garbage after the sixth octet. Hex digits are
/// case-insensitive.
pub fn parse_ether_addr(bytes: &[u8]) -> Option<EtherAddr> {
    let mut octets = [0u8; 6];
    let mut idx = 0usize;
    for (slot, oct) in octets.iter_mut().enumerate() {
        if idx >= bytes.len() {
            return None;
        }
        let high = parse_hex_nibble(bytes[idx])?;
        idx += 1;
        let mut value = high;
        if idx < bytes.len()
            && let Some(low) = parse_hex_nibble(bytes[idx])
        {
            value = (high << 4) | low;
            idx += 1;
        }
        *oct = value;
        if slot < 5 {
            if idx >= bytes.len() || bytes[idx] != b':' {
                return None;
            }
            idx += 1;
        }
    }
    if idx != bytes.len() {
        return None;
    }
    Some(octets)
}

/// Format an Ethernet address into the canonical 17-byte textual form
/// (`xx:xx:xx:xx:xx:xx`, lowercase hex, no NUL terminator).
pub fn format_ether_addr(addr: &EtherAddr) -> [u8; ETHER_ADDR_TEXT_LEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; ETHER_ADDR_TEXT_LEN];
    let mut pos = 0usize;
    for (slot, &value) in addr.iter().enumerate() {
        out[pos] = HEX[(value >> 4) as usize];
        pos += 1;
        out[pos] = HEX[(value & 0x0f) as usize];
        pos += 1;
        if slot < 5 {
            out[pos] = b':';
            pos += 1;
        }
    }
    out
}

/// Parse one /etc/ethers line into an address and a borrowed hostname.
///
/// Format: `<MAC> <hostname>` with leading whitespace allowed and any
/// trailing whitespace / EOL bytes stripped from the hostname. Returns
/// `None` for lines that don't have both a parseable MAC and a
/// non-empty hostname.
pub fn parse_ether_line(line: &[u8]) -> Option<(EtherAddr, &[u8])> {
    // Skip leading whitespace.
    let s = trim_leading_ws(line);
    if s.is_empty() {
        return None;
    }
    // MAC field ends at next whitespace.
    let mac_end = s
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(s.len());
    if mac_end == 0 || mac_end >= s.len() {
        return None;
    }
    let addr = parse_ether_addr(&s[..mac_end])?;
    // Skip whitespace before hostname.
    let rest = &s[mac_end..];
    let host_start = rest.iter().position(|&b| b != b' ' && b != b'\t')?;
    let host_bytes = &rest[host_start..];
    // Hostname ends at whitespace / newline / NUL.
    let host_len = host_bytes
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == 0)
        .unwrap_or(host_bytes.len());
    if host_len == 0 {
        return None;
    }
    Some((addr, &host_bytes[..host_len]))
}

#[inline]
fn parse_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn trim_leading_ws(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    &s[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_canonical_lowercase() {
        assert_eq!(
            parse_ether_addr(b"01:23:45:67:89:ab"),
            Some([0x01, 0x23, 0x45, 0x67, 0x89, 0xab])
        );
    }

    #[test]
    fn parse_canonical_uppercase() {
        assert_eq!(
            parse_ether_addr(b"AA:BB:CC:DD:EE:FF"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn parse_mixed_case() {
        assert_eq!(
            parse_ether_addr(b"aA:Bb:cC:dD:eE:Ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn parse_single_digit_octets() {
        // glibc ether_aton accepts shortened single-digit forms.
        assert_eq!(
            parse_ether_addr(b"0:0:0:0:0:0"),
            Some([0, 0, 0, 0, 0, 0])
        );
        assert_eq!(
            parse_ether_addr(b"1:2:3:4:5:6"),
            Some([1, 2, 3, 4, 5, 6])
        );
    }

    #[test]
    fn parse_mixed_short_and_long_octets() {
        assert_eq!(
            parse_ether_addr(b"0:1:23:4:56:7"),
            Some([0, 1, 0x23, 4, 0x56, 7])
        );
    }

    #[test]
    fn parse_rejects_too_few_octets() {
        assert!(parse_ether_addr(b"01:02:03:04:05").is_none());
        assert!(parse_ether_addr(b"01").is_none());
    }

    #[test]
    fn parse_rejects_too_many_octets() {
        // Trailing ":xx" after the 6th octet is garbage.
        assert!(parse_ether_addr(b"01:02:03:04:05:06:07").is_none());
    }

    #[test]
    fn parse_rejects_trailing_garbage() {
        assert!(parse_ether_addr(b"01:02:03:04:05:06x").is_none());
        assert!(parse_ether_addr(b"01:02:03:04:05:06\n").is_none());
    }

    #[test]
    fn parse_rejects_non_hex() {
        assert!(parse_ether_addr(b"0g:00:00:00:00:00").is_none());
        assert!(parse_ether_addr(b"!!:00:00:00:00:00").is_none());
    }

    #[test]
    fn parse_rejects_missing_colon() {
        assert!(parse_ether_addr(b"010203040506").is_none());
        assert!(parse_ether_addr(b"01:02-03:04:05:06").is_none());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(parse_ether_addr(b"").is_none());
    }

    #[test]
    fn format_canonical() {
        assert_eq!(
            &format_ether_addr(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
            b"01:23:45:67:89:ab"
        );
    }

    #[test]
    fn format_zero_padded_lowercase() {
        // Even single-digit-able values get padded to two hex digits.
        assert_eq!(&format_ether_addr(&[0, 0, 0, 0, 0, 0]), b"00:00:00:00:00:00");
    }

    #[test]
    fn format_high_values_lowercase() {
        assert_eq!(
            &format_ether_addr(&[0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa]),
            b"ff:fe:fd:fc:fb:fa"
        );
    }

    #[test]
    fn format_round_trip_with_parse() {
        let addr: EtherAddr = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let text = format_ether_addr(&addr);
        let parsed = parse_ether_addr(&text).expect("round-trips");
        assert_eq!(parsed, addr);
    }

    #[test]
    fn format_round_trip_extreme_values() {
        let cases: [EtherAddr; 4] = [
            [0; 6],
            [0xff; 6],
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xab],
            [0x80, 0x40, 0x20, 0x10, 0x08, 0x04],
        ];
        for addr in cases {
            let text = format_ether_addr(&addr);
            assert_eq!(parse_ether_addr(&text), Some(addr));
        }
    }

    #[test]
    fn ether_line_basic() {
        let (addr, host) = parse_ether_line(b"08:00:20:00:00:00\thost.example.com").unwrap();
        assert_eq!(addr, [0x08, 0x00, 0x20, 0x00, 0x00, 0x00]);
        assert_eq!(host, b"host.example.com");
    }

    #[test]
    fn ether_line_with_leading_whitespace() {
        let (addr, host) = parse_ether_line(b"   01:02:03:04:05:06   myhost").unwrap();
        assert_eq!(addr, [1, 2, 3, 4, 5, 6]);
        assert_eq!(host, b"myhost");
    }

    #[test]
    fn ether_line_strips_trailing_eol() {
        let (_, host) = parse_ether_line(b"01:02:03:04:05:06 host\n").unwrap();
        assert_eq!(host, b"host");
        let (_, host) = parse_ether_line(b"01:02:03:04:05:06 host\r\n").unwrap();
        assert_eq!(host, b"host");
    }

    #[test]
    fn ether_line_stops_hostname_at_trailing_whitespace() {
        let (_, host) = parse_ether_line(b"01:02:03:04:05:06 host trailing-junk").unwrap();
        // host ends at first whitespace after it
        assert_eq!(host, b"host");
    }

    #[test]
    fn ether_line_rejects_no_hostname() {
        assert!(parse_ether_line(b"01:02:03:04:05:06").is_none());
        assert!(parse_ether_line(b"01:02:03:04:05:06   ").is_none());
        assert!(parse_ether_line(b"01:02:03:04:05:06 ").is_none());
    }

    #[test]
    fn ether_line_rejects_blank_or_invalid_mac() {
        assert!(parse_ether_line(b"").is_none());
        assert!(parse_ether_line(b"   ").is_none());
        assert!(parse_ether_line(b"not-a-mac host").is_none());
    }

    #[test]
    fn ether_line_handles_nul_in_hostname_slot() {
        // /etc/ethers content NUL-terminated by ether_ntohost loop:
        // a NUL byte should also terminate the hostname.
        let (_, host) = parse_ether_line(b"01:02:03:04:05:06 host\0extra").unwrap();
        assert_eq!(host, b"host");
    }
}
