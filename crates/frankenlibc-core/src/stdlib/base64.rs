//! POSIX base-64 encoding: `a64l` and `l64a`.
//!
//! Uses the System V base-64 alphabet: `.`, `/`, `0`-`9`, `A`-`Z`, `a`-`z`
//! (NOT the same as MIME/RFC 4648 base64).

/// The a64l/l64a alphabet (System V ordering).
/// Index 0 = '.', 1 = '/', 2-11 = '0'-'9', 12-37 = 'A'-'Z', 38-63 = 'a'-'z'
const ALPHABET: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// `a64l` — convert a base-64 ASCII string to a long.
///
/// Processes up to 6 characters (6 × 6 bits = 36 bits max, matching glibc).
/// Invalid characters terminate processing.
pub fn a64l(s: &[u8]) -> i64 {
    let mut result: u64 = 0;
    let mut shift = 0u32;

    for &c in s.iter().take(6) {
        if c == 0 {
            break;
        }
        let val = match c {
            b'.' => 0u64,
            b'/' => 1,
            b'0'..=b'9' => (c - b'0') as u64 + 2,
            b'A'..=b'Z' => (c - b'A') as u64 + 12,
            b'a'..=b'z' => (c - b'a') as u64 + 38,
            _ => break, // invalid character terminates
        };
        result |= val << shift;
        shift += 6;
    }

    result as i64
}

/// `l64a` — convert a long to a base-64 ASCII string.
///
/// Returns the encoded string as a byte vector (up to 6 chars + NUL).
/// If `value` is 0, returns an empty string (matching glibc).
pub fn l64a(value: i64) -> Vec<u8> {
    if value <= 0 {
        return Vec::new();
    }

    let mut result = Vec::with_capacity(7);
    let mut v = value as u64;

    while v > 0 {
        let idx = (v & 0x3F) as usize;
        result.push(ALPHABET[idx]);
        v >>= 6;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a64l_basic() {
        // '.' = 0, '/' = 1
        assert_eq!(a64l(b"."), 0);
        assert_eq!(a64l(b"/"), 1);
        // '0' = 2
        assert_eq!(a64l(b"0"), 2);
        // 'A' = 12
        assert_eq!(a64l(b"A"), 12);
        // 'a' = 38
        assert_eq!(a64l(b"a"), 38);
    }

    #[test]
    fn test_l64a_basic() {
        assert!(l64a(0).is_empty());
        assert_eq!(l64a(1), b"/");
        assert_eq!(l64a(2), b"0");
    }

    #[test]
    fn test_a64l_l64a_roundtrip() {
        for val in [1i64, 42, 100, 1000, 123456, 2_000_000_000] {
            let encoded = l64a(val);
            let decoded = a64l(&encoded);
            assert_eq!(decoded, val, "roundtrip failed for {val}");
        }
    }

    #[test]
    fn test_a64l_empty_string() {
        assert_eq!(a64l(b""), 0);
        assert_eq!(a64l(b"\0"), 0);
    }

    #[test]
    fn test_a64l_max_six_chars() {
        // Only first 6 characters are processed.
        let s = b"//////z"; // 7 chars, last is ignored
        let result = a64l(s);
        let s6 = b"//////";
        let result6 = a64l(s6);
        assert_eq!(result, result6);
    }
}
