//! Internet address manipulation.
//!
//! Implements `<arpa/inet.h>` functions for converting between
//! human-readable IP addresses and binary network representations.
//! All logic is safe Rust with no syscalls.

use crate::socket::{AF_INET, AF_INET6};

/// Returned by `inet_addr` on parse failure (also `INADDR_BROADCAST`).
pub const INADDR_NONE: u32 = u32::MAX;

/// The wildcard address `0.0.0.0`.
pub const INADDR_ANY: u32 = 0;

/// The broadcast address `255.255.255.255`.
pub const INADDR_BROADCAST: u32 = u32::MAX;

// ---------------------------------------------------------------------------
// Byte-order helpers
// ---------------------------------------------------------------------------

/// Converts a 16-bit value from host byte order to network byte order (big-endian).
///
/// Equivalent to C `htons`.
#[inline]
pub fn htons(v: u16) -> u16 {
    v.to_be()
}

/// Converts a 32-bit value from host byte order to network byte order (big-endian).
///
/// Equivalent to C `htonl`.
#[inline]
pub fn htonl(v: u32) -> u32 {
    v.to_be()
}

/// Converts a 16-bit value from network byte order to host byte order.
///
/// Equivalent to C `ntohs`.
#[inline]
pub fn ntohs(v: u16) -> u16 {
    u16::from_be(v)
}

/// Converts a 32-bit value from network byte order to host byte order.
///
/// Equivalent to C `ntohl`.
#[inline]
pub fn ntohl(v: u32) -> u32 {
    u32::from_be(v)
}

// ---------------------------------------------------------------------------
// inet_addr
// ---------------------------------------------------------------------------

/// Parses a dotted-quad IPv4 address string into a `u32` in network byte order.
///
/// Equivalent to C `inet_addr`. Returns `INADDR_NONE` (`u32::MAX`) on error.
pub fn inet_addr(s: &[u8]) -> u32 {
    match parse_ipv4(s) {
        Some(octets) => u32::from_ne_bytes(octets),
        None => INADDR_NONE,
    }
}

// ---------------------------------------------------------------------------
// inet_pton
// ---------------------------------------------------------------------------

/// Converts an IP address from text to binary form.
///
/// Equivalent to C `inet_pton`. `af` is the address family (`AF_INET` or `AF_INET6`).
/// Returns 1 on success, 0 if `src` is not a valid address for the family,
/// or -1 for an unsupported address family.
pub fn inet_pton(af: i32, src: &[u8], dst: &mut [u8]) -> i32 {
    match af {
        AF_INET => {
            if dst.len() < 4 {
                return -1;
            }
            match parse_ipv4(src) {
                Some(octets) => {
                    dst[..4].copy_from_slice(&octets);
                    1
                }
                None => 0,
            }
        }
        AF_INET6 => {
            if dst.len() < 16 {
                return -1;
            }
            match parse_ipv6(src) {
                Some(octets) => {
                    dst[..16].copy_from_slice(&octets);
                    1
                }
                None => 0,
            }
        }
        _ => -1,
    }
}

// ---------------------------------------------------------------------------
// inet_ntop
// ---------------------------------------------------------------------------

/// Converts an IP address from binary to text form.
///
/// Equivalent to C `inet_ntop`. `af` is the address family.
/// Returns the formatted address string as bytes, or `None` for unsupported
/// family or wrong-sized `src`.
pub fn inet_ntop(af: i32, src: &[u8]) -> Option<Vec<u8>> {
    match af {
        AF_INET => {
            if src.len() < 4 {
                return None;
            }
            let s = format!("{}.{}.{}.{}", src[0], src[1], src[2], src[3]);
            Some(s.into_bytes())
        }
        AF_INET6 => {
            if src.len() < 16 {
                return None;
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&src[..16]);
            Some(format_ipv6_canonical(&addr).into_bytes())
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// inet_aton
// ---------------------------------------------------------------------------

/// Parses a dotted-quad IPv4 address string into a 4-byte network-order result.
///
/// Equivalent to C `inet_aton`. Returns 1 on success (and writes the address
/// into `dst`), 0 on failure. Unlike `inet_pton`, `inet_aton` is a legacy
/// function that only handles AF_INET.
pub fn inet_aton(src: &[u8], dst: &mut [u8; 4]) -> i32 {
    match parse_ipv4(src) {
        Some(octets) => {
            *dst = octets;
            1
        }
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Internal: IPv4 parsing
// ---------------------------------------------------------------------------

/// Parse a dotted-quad IPv4 text address into exactly 4 bytes.
/// Rejects leading zeros, values > 255, wrong number of parts, and trailing junk.
pub fn parse_ipv4(src: &[u8]) -> Option<[u8; 4]> {
    let s = core::str::from_utf8(src).ok()?;
    let s = s.trim_end_matches('\0');

    if s.is_empty() {
        return None;
    }

    let mut parts = s.splitn(5, '.');
    let mut octets = [0u8; 4];
    for octet in &mut octets {
        let part = parts.next()?;
        if part.is_empty() {
            return None;
        }
        // Reject leading zeros (octal ambiguity).
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        // Reject non-digit characters.
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let val: u16 = part.parse().ok()?;
        if val > 255 {
            return None;
        }
        *octet = val as u8;
    }
    // Must have consumed exactly 4 parts (no fifth part).
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

/// Formats an IPv4 address from 4 bytes to dotted-decimal into a fixed buffer.
pub fn format_ipv4(addr: &[u8; 4]) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let s = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    let bytes = s.as_bytes();
    let len = bytes.len().min(15);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Returns the length (excluding null) of a formatted IPv4 address.
pub fn format_ipv4_len(addr: &[u8; 4]) -> usize {
    let s = format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]);
    s.len()
}

// ---------------------------------------------------------------------------
// Internal: IPv6 parsing
// ---------------------------------------------------------------------------

/// Parses an IPv6 address string into 16 network-order bytes.
///
/// Supports:
/// - Full form (8 groups of hex)
/// - `::` compression
/// - Mixed IPv4 trailing notation (e.g. `::ffff:192.168.1.1`)
pub fn parse_ipv6(src: &[u8]) -> Option<[u8; 16]> {
    let s = core::str::from_utf8(src).ok()?;
    let s = s.trim_end_matches('\0');

    if s.is_empty() {
        return None;
    }

    // A single leading colon (not "::") is invalid.
    if s.starts_with(':') && !s.starts_with("::") {
        return None;
    }
    // A single trailing colon (not "::") is invalid.
    if s.ends_with(':') && !s.ends_with("::") {
        return None;
    }

    let mut result = [0u8; 16];

    // Split on "::" -- at most one occurrence allowed.
    let (front_str, back_str, has_double_colon) = if let Some(pos) = s.find("::") {
        // Make sure there isn't a second "::".
        if s[pos + 2..].contains("::") {
            return None;
        }
        let front = &s[..pos];
        let back = &s[pos + 2..];
        (front, back, true)
    } else {
        (s, "", false)
    };

    // Parse front groups.
    let mut front_groups: Vec<u16> = Vec::new();
    if !front_str.is_empty() {
        for g in front_str.split(':') {
            if g.is_empty() {
                return None;
            }
            if g.len() > 4 {
                return None;
            }
            front_groups.push(u16::from_str_radix(g, 16).ok()?);
        }
    }

    // Parse back groups -- the last group(s) might be an IPv4 suffix.
    let mut back_groups: Vec<u16> = Vec::new();
    let mut ipv4_suffix: Option<[u8; 4]> = None;

    if !back_str.is_empty() {
        // Check if the back part contains a dot (IPv4 suffix).
        if back_str.contains('.') {
            // The IPv4 part is everything from the last colon-delimited segment
            // that contains a dot. We need to find where the IPv4 starts.
            let colon_parts: Vec<&str> = back_str.split(':').collect();
            // The last colon-part should be the IPv4 address.
            // Everything before it is hex groups.
            let ipv4_part = colon_parts.last()?;
            let v4 = parse_ipv4(ipv4_part.as_bytes())?;
            ipv4_suffix = Some(v4);

            // Parse any hex groups before the IPv4 part.
            for g in &colon_parts[..colon_parts.len() - 1] {
                if g.is_empty() {
                    return None;
                }
                if g.len() > 4 {
                    return None;
                }
                back_groups.push(u16::from_str_radix(g, 16).ok()?);
            }
        } else {
            for g in back_str.split(':') {
                if g.is_empty() {
                    return None;
                }
                if g.len() > 4 {
                    return None;
                }
                back_groups.push(u16::from_str_radix(g, 16).ok()?);
            }
        }
    }

    // Also check front for IPv4 suffix when there is NO double colon.
    if !has_double_colon && front_str.contains('.') {
        // Re-parse: split front_str by ':' and check if the last segment is IPv4.
        let colon_parts: Vec<&str> = front_str.split(':').collect();
        if colon_parts.len() < 2 {
            return None;
        }
        let ipv4_part = colon_parts.last()?;
        if let Some(v4) = parse_ipv4(ipv4_part.as_bytes()) {
            ipv4_suffix = Some(v4);
            front_groups.clear();
            for g in &colon_parts[..colon_parts.len() - 1] {
                if g.is_empty() {
                    return None;
                }
                if g.len() > 4 {
                    return None;
                }
                front_groups.push(u16::from_str_radix(g, 16).ok()?);
            }
        }
    }

    // Count total groups. IPv4 suffix counts as 2.
    let ipv4_group_count: usize = if ipv4_suffix.is_some() { 2 } else { 0 };
    let total_explicit = front_groups.len() + back_groups.len() + ipv4_group_count;

    if has_double_colon {
        if total_explicit > 8 {
            return None;
        }
    } else if total_explicit != 8 {
        return None;
    }

    let zeros_needed = if has_double_colon {
        8 - total_explicit
    } else {
        0
    };

    // Build the 8 groups.
    let mut all_groups: Vec<u16> = Vec::with_capacity(8);
    all_groups.extend_from_slice(&front_groups);
    all_groups.resize(all_groups.len() + zeros_needed, 0);
    all_groups.extend_from_slice(&back_groups);
    if let Some(v4) = ipv4_suffix {
        all_groups.push(u16::from_be_bytes([v4[0], v4[1]]));
        all_groups.push(u16::from_be_bytes([v4[2], v4[3]]));
    }

    if all_groups.len() != 8 {
        return None;
    }

    for (i, &g) in all_groups.iter().enumerate() {
        let be = g.to_be_bytes();
        result[i * 2] = be[0];
        result[i * 2 + 1] = be[1];
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Internal: IPv6 formatting (canonical RFC 5952)
// ---------------------------------------------------------------------------

/// Format 16 bytes as canonical IPv6 text with `::` abbreviation for the
/// longest run of consecutive zero groups (ties broken by first occurrence).
/// Per RFC 5952, a single zero group is NOT abbreviated with `::`.
fn format_ipv6_canonical(addr: &[u8; 16]) -> String {
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
    }

    // Find the longest run of consecutive zero groups.
    let mut best_start: usize = 0;
    let mut best_len: usize = 0;
    let mut cur_start: usize = 0;
    let mut cur_len: usize = 0;

    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
        } else {
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
            cur_len = 0;
        }
    }
    if cur_len > best_len {
        best_start = cur_start;
        best_len = cur_len;
    }

    // Per RFC 5952, do not abbreviate a single zero group.
    if best_len <= 1 {
        best_len = 0;
    }

    let mut out = String::new();
    let mut i = 0usize;
    while i < 8 {
        if best_len > 0 && i == best_start {
            // Write "::" -- if we already have content, add a colon to make "X::",
            // otherwise start with "::".
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }

    out
}

/// Formats an IPv6 address from 16 bytes to colon-hex form (no `::` abbreviation)
/// into a fixed buffer. Used by the ABI layer.
pub fn format_ipv6(addr: &[u8; 16]) -> [u8; 46] {
    let mut buf = [0u8; 46];
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
    }
    let s = format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7]
    );
    let bytes = s.as_bytes();
    let len = bytes.len().min(45);
    buf[..len].copy_from_slice(&bytes[..len]);
    buf
}

/// Returns the length (excluding null) of a formatted IPv6 address.
pub fn format_ipv6_len(addr: &[u8; 16]) -> usize {
    let mut groups = [0u16; 8];
    for i in 0..8 {
        groups[i] = u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]);
    }
    let s = format!(
        "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
        groups[0], groups[1], groups[2], groups[3], groups[4], groups[5], groups[6], groups[7]
    );
    s.len()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constants --

    #[test]
    fn test_constants() {
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
        assert_eq!(INADDR_NONE, u32::MAX);
        assert_eq!(INADDR_ANY, 0);
        assert_eq!(INADDR_BROADCAST, u32::MAX);
    }

    // -- Byte-order round-trips --

    #[test]
    fn test_htons_ntohs_roundtrip() {
        for v in [0u16, 1, 0x0102, 0xFFFF, 0x8000, 0x00FF] {
            assert_eq!(ntohs(htons(v)), v);
        }
    }

    #[test]
    fn test_htonl_ntohl_roundtrip() {
        for v in [0u32, 1, 0x01020304, 0xFFFFFFFF, 0x80000000, 0x000000FF] {
            assert_eq!(ntohl(htonl(v)), v);
        }
    }

    #[test]
    fn test_htons_known_value() {
        // After htons, the in-memory (native-endian) bytes should be big-endian.
        let n = htons(0x1234);
        assert_eq!(n.to_ne_bytes(), [0x12, 0x34]);
    }

    #[test]
    fn test_htonl_known_value() {
        // After htonl, the in-memory (native-endian) bytes should be big-endian.
        let n = htonl(0x01020304);
        assert_eq!(n.to_ne_bytes(), [0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_htons_identity_values() {
        assert_eq!(htons(0), 0);
        assert_eq!(htons(0xFFFF), 0xFFFF);
        assert_eq!(htons(1), 1u16.to_be());
    }

    #[test]
    fn test_htonl_identity_values() {
        assert_eq!(htonl(0), 0);
        assert_eq!(htonl(0xFFFFFFFF), 0xFFFFFFFF);
        assert_eq!(htonl(1), 1u32.to_be());
    }

    // -- inet_addr --

    #[test]
    fn test_inet_addr_basic() {
        let addr = inet_addr(b"192.168.1.1");
        assert_eq!(addr.to_ne_bytes(), [192, 168, 1, 1]);
    }

    #[test]
    fn test_inet_addr_zero() {
        assert_eq!(inet_addr(b"0.0.0.0"), 0);
    }

    #[test]
    fn test_inet_addr_loopback() {
        let addr = inet_addr(b"127.0.0.1");
        assert_eq!(addr.to_ne_bytes(), [127, 0, 0, 1]);
    }

    #[test]
    fn test_inet_addr_broadcast() {
        // 255.255.255.255 => u32::MAX in network byte order.
        // Note: same bit pattern as INADDR_NONE (known ambiguity).
        let addr = inet_addr(b"255.255.255.255");
        assert_eq!(addr.to_ne_bytes(), [255, 255, 255, 255]);
    }

    #[test]
    fn test_inet_addr_invalid() {
        assert_eq!(inet_addr(b""), INADDR_NONE);
        assert_eq!(inet_addr(b"abc"), INADDR_NONE);
        assert_eq!(inet_addr(b"1.2.3"), INADDR_NONE);
        assert_eq!(inet_addr(b"1.2.3.4.5"), INADDR_NONE);
        assert_eq!(inet_addr(b"256.0.0.1"), INADDR_NONE);
        assert_eq!(inet_addr(b"1.2.3.999"), INADDR_NONE);
    }

    #[test]
    fn test_inet_addr_leading_zeros_rejected() {
        assert_eq!(inet_addr(b"01.02.03.04"), INADDR_NONE);
        assert_eq!(inet_addr(b"1.2.3.04"), INADDR_NONE);
    }

    #[test]
    fn test_inet_addr_nul_terminated() {
        let addr = inet_addr(b"10.0.0.1\0");
        assert_eq!(addr.to_ne_bytes(), [10, 0, 0, 1]);
    }

    // -- parse_ipv4 --

    #[test]
    fn test_parse_ipv4_valid() {
        assert_eq!(parse_ipv4(b"127.0.0.1"), Some([127, 0, 0, 1]));
        assert_eq!(parse_ipv4(b"0.0.0.0"), Some([0, 0, 0, 0]));
        assert_eq!(parse_ipv4(b"255.255.255.255"), Some([255, 255, 255, 255]));
        assert_eq!(parse_ipv4(b"192.168.1.100"), Some([192, 168, 1, 100]));
        assert_eq!(parse_ipv4(b"10.20.30.40"), Some([10, 20, 30, 40]));
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert_eq!(parse_ipv4(b""), None);
        assert_eq!(parse_ipv4(b"256.0.0.1"), None);
        assert_eq!(parse_ipv4(b"1.2.3"), None);
        assert_eq!(parse_ipv4(b"1.2.3.4.5"), None);
        assert_eq!(parse_ipv4(b"01.02.03.04"), None); // leading zeros
        assert_eq!(parse_ipv4(b"abc"), None);
        assert_eq!(parse_ipv4(b"1.2.3."), None); // trailing dot
        assert_eq!(parse_ipv4(b".1.2.3"), None); // leading dot
        assert_eq!(parse_ipv4(b"1..2.3"), None); // double dot
    }

    #[test]
    fn test_format_ipv4() {
        let addr = [192, 168, 1, 1];
        let buf = format_ipv4(&addr);
        let s = core::str::from_utf8(&buf[..format_ipv4_len(&addr)]).unwrap();
        assert_eq!(s, "192.168.1.1");

        let lo = [127, 0, 0, 1];
        let buf2 = format_ipv4(&lo);
        let s2 = core::str::from_utf8(&buf2[..format_ipv4_len(&lo)]).unwrap();
        assert_eq!(s2, "127.0.0.1");
    }

    // -- inet_pton IPv4 --

    #[test]
    fn test_pton_ipv4_basic() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"127.0.0.1", &mut buf), 1);
        assert_eq!(buf, [127, 0, 0, 1]);
    }

    #[test]
    fn test_pton_ipv4_zero() {
        let mut buf = [0xFFu8; 4];
        assert_eq!(inet_pton(AF_INET, b"0.0.0.0", &mut buf), 1);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn test_pton_ipv4_max() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"255.255.255.255", &mut buf), 1);
        assert_eq!(buf, [255, 255, 255, 255]);
    }

    #[test]
    fn test_pton_ipv4_invalid_returns_zero() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"", &mut buf), 0);
        assert_eq!(inet_pton(AF_INET, b"not_an_ip", &mut buf), 0);
        assert_eq!(inet_pton(AF_INET, b"1.2.3", &mut buf), 0);
        assert_eq!(inet_pton(AF_INET, b"1.2.3.4.5", &mut buf), 0);
        assert_eq!(inet_pton(AF_INET, b"300.1.2.3", &mut buf), 0);
    }

    #[test]
    fn test_pton_unsupported_family() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(99, b"1.2.3.4", &mut buf), -1);
    }

    #[test]
    fn test_pton_dst_larger_than_needed() {
        let mut buf = [0xFFu8; 32];
        assert_eq!(inet_pton(AF_INET, b"10.20.30.40", &mut buf), 1);
        assert_eq!(&buf[..4], &[10, 20, 30, 40]);
        // Bytes beyond 4 are untouched.
        assert_eq!(buf[4], 0xFF);
    }

    // -- inet_pton IPv6 --

    #[test]
    fn test_pton_ipv6_loopback() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::1", &mut buf), 1);
        let mut expected = [0u8; 16];
        expected[15] = 1;
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_pton_ipv6_all_zeros() {
        let mut buf = [0xFFu8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::", &mut buf), 1);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn test_pton_ipv6_full() {
        let mut buf = [0u8; 16];
        assert_eq!(
            inet_pton(AF_INET6, b"2001:db8:85a3:0:0:8a2e:370:7334", &mut buf),
            1
        );
        assert_eq!(
            buf,
            [
                0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
                0x73, 0x34
            ]
        );
    }

    #[test]
    fn test_pton_ipv6_full_with_leading_zeros() {
        let mut buf = [0u8; 16];
        assert_eq!(
            inet_pton(
                AF_INET6,
                b"2001:0db8:0000:0000:0000:0000:0000:0001",
                &mut buf
            ),
            1
        );
        assert_eq!(buf[0], 0x20);
        assert_eq!(buf[1], 0x01);
        assert_eq!(buf[2], 0x0d);
        assert_eq!(buf[3], 0xb8);
        assert_eq!(buf[14], 0x00);
        assert_eq!(buf[15], 0x01);
    }

    #[test]
    fn test_pton_ipv6_abbreviated() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"2001:db8::1", &mut buf), 1);
        assert_eq!(
            buf,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn test_pton_ipv6_mapped_ipv4() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::ffff:192.168.1.1", &mut buf), 1);
        assert_eq!(
            buf,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1]
        );
    }

    #[test]
    fn test_pton_ipv6_mapped_ipv4_loopback() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::ffff:127.0.0.1", &mut buf), 1);
        assert_eq!(
            buf,
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1]
        );
    }

    #[test]
    fn test_pton_ipv6_mapped_ipv4_1234() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::ffff:1.2.3.4", &mut buf), 1);
        assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]);
    }

    #[test]
    fn test_pton_ipv6_all_ones() {
        let mut buf = [0u8; 16];
        assert_eq!(
            inet_pton(
                AF_INET6,
                b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                &mut buf
            ),
            1
        );
        assert_eq!(buf, [0xFF; 16]);
    }

    #[test]
    fn test_pton_ipv6_trailing_double_colon() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"fe80::", &mut buf), 1);
        let mut expected = [0u8; 16];
        expected[0] = 0xfe;
        expected[1] = 0x80;
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_pton_ipv6_uppercase_hex() {
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"FE80::1", &mut buf), 1);
        assert_eq!(buf[0], 0xFE);
        assert_eq!(buf[1], 0x80);
        assert_eq!(buf[15], 1);
    }

    #[test]
    fn test_pton_ipv6_invalid() {
        let mut buf = [0u8; 16];
        // Too many groups.
        assert_eq!(inet_pton(AF_INET6, b"1:2:3:4:5:6:7:8:9", &mut buf), 0);
        // Triple colon.
        assert_eq!(inet_pton(AF_INET6, b":::", &mut buf), 0);
        // Empty.
        assert_eq!(inet_pton(AF_INET6, b"", &mut buf), 0);
        // Leading single colon (not ::).
        assert_eq!(inet_pton(AF_INET6, b":1", &mut buf), 0);
        // Double :: used twice.
        assert_eq!(inet_pton(AF_INET6, b"1::2::3", &mut buf), 0);
        // Trailing single colon.
        assert_eq!(inet_pton(AF_INET6, b"1:2:3:4:5:6:7:", &mut buf), 0);
    }

    #[test]
    fn test_pton_ipv6_dst_larger_than_needed() {
        let mut buf = [0xFFu8; 32];
        assert_eq!(inet_pton(AF_INET6, b"::1", &mut buf), 1);
        assert_eq!(buf[15], 1);
        // Bytes beyond 16 are untouched.
        assert_eq!(buf[16], 0xFF);
    }

    // -- inet_ntop IPv4 --

    #[test]
    fn test_ntop_ipv4_basic() {
        let result = inet_ntop(AF_INET, &[192, 168, 0, 1]).unwrap();
        assert_eq!(result, b"192.168.0.1");
    }

    #[test]
    fn test_ntop_ipv4_zero() {
        let result = inet_ntop(AF_INET, &[0, 0, 0, 0]).unwrap();
        assert_eq!(result, b"0.0.0.0");
    }

    #[test]
    fn test_ntop_ipv4_max() {
        let result = inet_ntop(AF_INET, &[255, 255, 255, 255]).unwrap();
        assert_eq!(result, b"255.255.255.255");
    }

    #[test]
    fn test_ntop_ipv4_too_short() {
        assert!(inet_ntop(AF_INET, &[1, 2, 3]).is_none());
    }

    #[test]
    fn test_ntop_unsupported_family() {
        assert!(inet_ntop(42, &[0; 16]).is_none());
    }

    // -- inet_ntop IPv6 --

    #[test]
    fn test_ntop_ipv6_loopback() {
        let mut src = [0u8; 16];
        src[15] = 1;
        let result = inet_ntop(AF_INET6, &src).unwrap();
        assert_eq!(result, b"::1");
    }

    #[test]
    fn test_ntop_ipv6_all_zeros() {
        let result = inet_ntop(AF_INET6, &[0u8; 16]).unwrap();
        assert_eq!(result, b"::");
    }

    #[test]
    fn test_ntop_ipv6_all_ones() {
        let result = inet_ntop(AF_INET6, &[0xFF; 16]).unwrap();
        assert_eq!(result, b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    }

    #[test]
    fn test_ntop_ipv6_fe80() {
        let mut src = [0u8; 16];
        src[0] = 0xfe;
        src[1] = 0x80;
        let result = inet_ntop(AF_INET6, &src).unwrap();
        assert_eq!(result, b"fe80::");
    }

    #[test]
    fn test_ntop_ipv6_no_abbreviation_for_single_zero() {
        // RFC 5952: do NOT use :: to abbreviate just one 16-bit group of zeros.
        // Address: 2001:db8:0:1:0:0:0:1 -> should abbreviate the run of 3 zeros.
        let src: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let result = inet_ntop(AF_INET6, &src).unwrap();
        assert_eq!(result, b"2001:db8:0:1::1");
    }

    #[test]
    fn test_ntop_ipv6_abbreviate_longest_run() {
        // 2001:0:0:0:0:0:0:1 => 2001::1 (run of 6 zeros).
        let src: [u8; 16] = [
            0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let result = inet_ntop(AF_INET6, &src).unwrap();
        assert_eq!(result, b"2001::1");
    }

    #[test]
    fn test_ntop_ipv6_too_short() {
        assert!(inet_ntop(AF_INET6, &[0u8; 15]).is_none());
    }

    #[test]
    fn test_ntop_ipv6_full_address() {
        let src: [u8; 16] = [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ];
        let result = inet_ntop(AF_INET6, &src).unwrap();
        assert_eq!(result, b"2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn test_ntop_ipv6_two_zero_runs_picks_longest() {
        // 1:0:0:2:0:0:0:3 => two runs: len=2 at pos 1, len=3 at pos 4.
        // Should abbreviate the longer run at pos 4.
        let src: [u8; 16] = [
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x03,
        ];
        let result = inet_ntop(AF_INET6, &src).unwrap();
        assert_eq!(result, b"1:0:0:2::3");
    }

    // -- Round-trip tests: pton -> ntop --

    #[test]
    fn test_roundtrip_ipv4() {
        let cases: &[&[u8]] = &[
            b"0.0.0.0",
            b"127.0.0.1",
            b"192.168.1.1",
            b"255.255.255.255",
            b"10.0.0.1",
        ];
        for &addr in cases {
            let mut bin = [0u8; 4];
            assert_eq!(
                inet_pton(AF_INET, addr, &mut bin),
                1,
                "pton failed for {:?}",
                core::str::from_utf8(addr)
            );
            let text = inet_ntop(AF_INET, &bin).unwrap();
            assert_eq!(
                text,
                addr,
                "roundtrip mismatch for {:?}",
                core::str::from_utf8(addr)
            );
        }
    }

    #[test]
    fn test_roundtrip_ipv6() {
        // After round-trip the output should be canonical form.
        let cases: &[(&[u8], &[u8])] = &[
            (b"::1", b"::1"),
            (b"::", b"::"),
            (b"2001:db8::1", b"2001:db8::1"),
            (b"fe80::", b"fe80::"),
            (
                b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                b"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            ),
        ];
        for &(input, expected) in cases {
            let mut bin = [0u8; 16];
            assert_eq!(
                inet_pton(AF_INET6, input, &mut bin),
                1,
                "pton failed for {:?}",
                core::str::from_utf8(input)
            );
            let text = inet_ntop(AF_INET6, &bin).unwrap();
            assert_eq!(
                text,
                expected,
                "roundtrip: input={:?} expected={:?} got={:?}",
                core::str::from_utf8(input),
                core::str::from_utf8(expected),
                String::from_utf8_lossy(&text)
            );
        }
    }

    // -- inet_aton --

    #[test]
    fn test_inet_aton_basic() {
        let mut dst = [0u8; 4];
        assert_eq!(inet_aton(b"192.168.1.1", &mut dst), 1);
        assert_eq!(dst, [192, 168, 1, 1]);
    }

    #[test]
    fn test_inet_aton_loopback() {
        let mut dst = [0u8; 4];
        assert_eq!(inet_aton(b"127.0.0.1", &mut dst), 1);
        assert_eq!(dst, [127, 0, 0, 1]);
    }

    #[test]
    fn test_inet_aton_zero() {
        let mut dst = [0xFFu8; 4];
        assert_eq!(inet_aton(b"0.0.0.0", &mut dst), 1);
        assert_eq!(dst, [0, 0, 0, 0]);
    }

    #[test]
    fn test_inet_aton_broadcast() {
        let mut dst = [0u8; 4];
        assert_eq!(inet_aton(b"255.255.255.255", &mut dst), 1);
        assert_eq!(dst, [255, 255, 255, 255]);
    }

    #[test]
    fn test_inet_aton_invalid() {
        let mut dst = [0u8; 4];
        assert_eq!(inet_aton(b"", &mut dst), 0);
        assert_eq!(inet_aton(b"abc", &mut dst), 0);
        assert_eq!(inet_aton(b"1.2.3", &mut dst), 0);
        assert_eq!(inet_aton(b"1.2.3.4.5", &mut dst), 0);
        assert_eq!(inet_aton(b"256.0.0.1", &mut dst), 0);
    }

    #[test]
    fn test_inet_aton_nul_terminated() {
        let mut dst = [0u8; 4];
        assert_eq!(inet_aton(b"10.0.0.1\0", &mut dst), 1);
        assert_eq!(dst, [10, 0, 0, 1]);
    }

    // -- Edge cases --

    #[test]
    fn test_ipv4_single_zero_octet() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"0.0.0.0", &mut buf), 1);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    #[test]
    fn test_ipv4_trailing_dot_invalid() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"1.2.3.4.", &mut buf), 0);
    }

    #[test]
    fn test_ipv4_leading_dot_invalid() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b".1.2.3.4", &mut buf), 0);
    }

    #[test]
    fn test_ipv4_double_dot_invalid() {
        let mut buf = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"1..2.3.4", &mut buf), 0);
    }

    #[test]
    fn test_ipv6_mapped_ipv4_via_pton_ntop() {
        // Parse ::ffff:1.2.3.4 and verify binary.
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::ffff:1.2.3.4", &mut buf), 1);
        assert_eq!(buf, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 1, 2, 3, 4]);
        // ntop produces hex form (not mapped notation).
        let text = inet_ntop(AF_INET6, &buf).unwrap();
        assert_eq!(text, b"::ffff:102:304");
    }

    #[test]
    fn test_inet_pton_dispatcher() {
        let mut dst4 = [0u8; 4];
        assert_eq!(inet_pton(AF_INET, b"10.0.0.1", &mut dst4), 1);
        assert_eq!(dst4, [10, 0, 0, 1]);

        assert_eq!(inet_pton(AF_INET, b"bad", &mut dst4), 0);
        assert_eq!(inet_pton(99, b"10.0.0.1", &mut dst4), -1);

        let mut dst6 = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"::1", &mut dst6), 1);
        assert_eq!(dst6[15], 1);
    }

    #[test]
    fn test_inet_addr_network_byte_order() {
        // Verify the result is in network (big-endian) byte order:
        // the raw memory bytes of the u32 match the IP octets directly.
        let addr = inet_addr(b"1.2.3.4");
        assert_eq!(addr.to_ne_bytes(), [1, 2, 3, 4]);
    }

    #[test]
    fn test_pton_ipv6_middle_double_colon() {
        // 1:2::7:8
        let mut buf = [0u8; 16];
        assert_eq!(inet_pton(AF_INET6, b"1:2::7:8", &mut buf), 1);
        let mut expected = [0u8; 16];
        expected[0] = 0;
        expected[1] = 1;
        expected[2] = 0;
        expected[3] = 2;
        // groups 2-5 are zero
        expected[12] = 0;
        expected[13] = 7;
        expected[14] = 0;
        expected[15] = 8;
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_pton_ipv6_link_local() {
        let mut buf = [0u8; 16];
        assert_eq!(
            inet_pton(AF_INET6, b"fe80::1ff:fe23:4567:890a", &mut buf),
            1
        );
        assert_eq!(buf[0], 0xfe);
        assert_eq!(buf[1], 0x80);
        // groups 1-3 are zero
        assert_eq!(buf[8], 0x01);
        assert_eq!(buf[9], 0xff);
        assert_eq!(buf[10], 0xfe);
        assert_eq!(buf[11], 0x23);
        assert_eq!(buf[12], 0x45);
        assert_eq!(buf[13], 0x67);
        assert_eq!(buf[14], 0x89);
        assert_eq!(buf[15], 0x0a);
    }
}
