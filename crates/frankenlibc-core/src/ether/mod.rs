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
/// Accepts `xx:xx:xx:xx:xx:xx` with one or two hex digits per octet, matching
/// glibc `ether_aton_r`. glibc stops once six octets are read and does NOT
/// require the string to end there: after a two-hex-digit sixth octet any
/// trailing content is ignored (`01:02:03:04:05:06:07` -> `…:06`), and after a
/// single-digit sixth octet the next byte must be NUL or whitespace — otherwise
/// glibc would have tried to read it as the second hex digit and failed
/// (`…:6x` -> NULL, but `…:6 ` -> OK, `…:6a` -> `…:6a`). Returns `None` if any
/// octet is missing or malformed. Hex digits are case-insensitive.
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
        let mut two_digits = false;
        if idx < bytes.len()
            && let Some(low) = parse_hex_nibble(bytes[idx])
        {
            value = (high << 4) | low;
            idx += 1;
            two_digits = true;
        }
        *oct = value;
        if slot < 5 {
            if idx >= bytes.len() || bytes[idx] != b':' {
                return None;
            }
            idx += 1;
        } else if !two_digits && idx < bytes.len() && !is_glibc_space(bytes[idx]) {
            // Single-digit last octet followed by a non-whitespace byte: glibc
            // (mis)reads that byte as the second hex digit and rejects it. A
            // two-digit last octet, or a whitespace/end terminator, is accepted
            // and any further trailing bytes are ignored.
            return None;
        }
    }
    Some(octets)
}

/// glibc `isspace` set for ASCII: space plus the 0x09..=0x0D control whitespace
/// (`\t \n \v \f \r`). Rust's `is_ascii_whitespace` omits `\v` (0x0B), which
/// glibc accepts as an `ether_aton` terminator.
#[inline]
fn is_glibc_space(c: u8) -> bool {
    c == b' ' || (0x09..=0x0D).contains(&c)
}

/// Format an Ethernet address into `out` using glibc's `ether_ntoa` form —
/// `"%x:%x:%x:%x:%x:%x"`, lowercase hex with NO leading zeros (e.g.
/// `{0,1,0x0a,0x0b,0x0c,0xff}` -> `"0:1:a:b:c:ff"`). Returns the number of bytes
/// written (no NUL terminator); `out` must be at least [`ETHER_ADDR_TEXT_LEN`].
pub fn format_ether_addr(addr: &EtherAddr, out: &mut [u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut pos = 0usize;
    for (slot, &value) in addr.iter().enumerate() {
        if slot > 0 {
            out[pos] = b':';
            pos += 1;
        }
        // glibc `%x`: emit the high nibble only when the value is >= 0x10.
        if value >= 0x10 {
            out[pos] = HEX[(value >> 4) as usize];
            pos += 1;
        }
        out[pos] = HEX[(value & 0x0f) as usize];
        pos += 1;
    }
    pos
}

/// Parse one /etc/ethers line into an address and a borrowed hostname.
///
/// Format: `<MAC> <hostname>` with leading whitespace allowed and any
/// trailing whitespace / EOL bytes stripped from the hostname. Returns
/// `None` for lines that don't have both a parseable MAC and a
/// non-empty hostname.
pub fn parse_ether_line(line: &[u8]) -> Option<(EtherAddr, &[u8])> {
    // glibc's `ether_line` does NOT skip leading whitespace: the very first
    // byte must begin the address, so a line like "  01:.. host" is rejected
    // (verified against host glibc — leading-ws lines return -1).
    if line.is_empty() {
        return None;
    }
    // MAC field ends at next whitespace.
    let mac_end = line
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(line.len());
    if mac_end == 0 || mac_end >= line.len() {
        return None;
    }
    let addr = parse_ether_addr(&line[..mac_end])?;
    // Skip whitespace before hostname.
    let rest = &line[mac_end..];
    let host_start = rest.iter().position(|&b| b != b' ' && b != b'\t')?;
    let host_bytes = &rest[host_start..];
    // glibc terminates the hostname at the first '#' (inline comment),
    // whitespace, or EOL byte, and rejects a missing/comment-only hostname.
    let host_len = host_bytes
        .iter()
        .position(|&b| b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == 0 || b == b'#')
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
        assert_eq!(parse_ether_addr(b"0:0:0:0:0:0"), Some([0, 0, 0, 0, 0, 0]));
        assert_eq!(parse_ether_addr(b"1:2:3:4:5:6"), Some([1, 2, 3, 4, 5, 6]));
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
    fn parse_ignores_trailing_after_two_digit_last_octet() {
        // glibc stops after six octets; a two-digit sixth octet ignores any
        // trailing bytes, including a further ":07" or junk.
        assert_eq!(
            parse_ether_addr(b"01:02:03:04:05:06:07"),
            Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        assert_eq!(
            parse_ether_addr(b"01:02:03:04:05:06x"),
            Some([0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
        // Whitespace terminator after the last octet (incl. \v, which glibc's
        // isspace accepts but Rust's is_ascii_whitespace does not).
        assert_eq!(parse_ether_addr(b"1:2:3:4:5:6\n"), Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(
            parse_ether_addr(b"1:2:3:4:5:6\x0b"),
            Some([1, 2, 3, 4, 5, 6])
        );
        // A hex byte after a single-digit last octet is read as the 2nd digit.
        assert_eq!(
            parse_ether_addr(b"1:2:3:4:5:6a"),
            Some([1, 2, 3, 4, 5, 0x6a])
        );
    }

    #[test]
    fn parse_rejects_single_digit_last_octet_with_nonspace_junk() {
        // Single-digit last octet followed by a non-hex, non-whitespace byte:
        // glibc tries to read it as the second hex digit and fails.
        assert!(parse_ether_addr(b"1:2:3:4:5:6x").is_none());
        assert!(parse_ether_addr(b"1:2:3:4:5:6:").is_none());
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

    fn fmt(addr: &EtherAddr) -> Vec<u8> {
        let mut buf = [0u8; ETHER_ADDR_TEXT_LEN];
        let n = format_ether_addr(addr, &mut buf);
        buf[..n].to_vec()
    }

    #[test]
    fn format_canonical() {
        // glibc "%x": leading zeros are dropped (0x01 -> "1").
        assert_eq!(
            fmt(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab]),
            b"1:23:45:67:89:ab"
        );
    }

    #[test]
    fn format_no_leading_zeros_lowercase() {
        // glibc ether_ntoa prints "%x" per octet (NO zero padding).
        assert_eq!(fmt(&[0, 0, 0, 0, 0, 0]), b"0:0:0:0:0:0");
        assert_eq!(fmt(&[0, 1, 0x0a, 0x0b, 0x0c, 0xff]), b"0:1:a:b:c:ff");
    }

    #[test]
    fn format_high_values_lowercase() {
        assert_eq!(
            fmt(&[0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa]),
            b"ff:fe:fd:fc:fb:fa"
        );
    }

    #[test]
    fn format_round_trip_with_parse() {
        let addr: EtherAddr = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe];
        let parsed = parse_ether_addr(&fmt(&addr)).expect("round-trips");
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
            assert_eq!(parse_ether_addr(&fmt(&addr)), Some(addr));
        }
    }

    #[test]
    fn ether_line_basic() {
        let (addr, host) = parse_ether_line(b"08:00:20:00:00:00\thost.example.com").unwrap();
        assert_eq!(addr, [0x08, 0x00, 0x20, 0x00, 0x00, 0x00]);
        assert_eq!(host, b"host.example.com");
    }

    #[test]
    fn ether_line_rejects_leading_whitespace() {
        // glibc's ether_line does not skip leading whitespace — the first byte
        // must be a hex digit, so a leading-space line is rejected.
        assert!(parse_ether_line(b"   01:02:03:04:05:06   myhost").is_none());
        // Internal whitespace between MAC and host is still fine.
        let (addr, host) = parse_ether_line(b"01:02:03:04:05:06   myhost").unwrap();
        assert_eq!(addr, [1, 2, 3, 4, 5, 6]);
        assert_eq!(host, b"myhost");
    }

    #[test]
    fn ether_line_stops_hostname_at_comment() {
        // glibc terminates the hostname at an inline '#' comment.
        let (_, host) = parse_ether_line(b"01:02:03:04:05:06 host#comment").unwrap();
        assert_eq!(host, b"host");
        let (_, host) = parse_ether_line(b"01:02:03:04:05:06 host # spaced").unwrap();
        assert_eq!(host, b"host");
        // A comment-only "hostname" is rejected.
        assert!(parse_ether_line(b"01:02:03:04:05:06 #onlycomment").is_none());
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
