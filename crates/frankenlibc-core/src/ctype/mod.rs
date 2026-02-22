//! Character classification and conversion.
//!
//! Implements `<ctype.h>` functions for classifying and transforming
//! individual bytes/characters. C locale only.

/// Returns `true` if `c` is an alphabetic character (`[A-Za-z]`).
#[inline]
pub fn is_alpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// Returns `true` if `c` is a decimal digit (`[0-9]`).
#[inline]
pub fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// Returns `true` if `c` is an alphanumeric character (`[A-Za-z0-9]`).
#[inline]
pub fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

/// Returns `true` if `c` is a whitespace character.
///
/// Whitespace: space, tab, newline, vertical tab, form feed, carriage return.
#[inline]
pub fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// Returns `true` if `c` is an uppercase letter (`[A-Z]`).
#[inline]
pub fn is_upper(c: u8) -> bool {
    c.is_ascii_uppercase()
}

/// Returns `true` if `c` is a lowercase letter (`[a-z]`).
#[inline]
pub fn is_lower(c: u8) -> bool {
    c.is_ascii_lowercase()
}

/// Returns `true` if `c` is a printable character (including space).
#[inline]
pub fn is_print(c: u8) -> bool {
    (0x20..=0x7E).contains(&c)
}

/// Returns `true` if `c` is a punctuation character.
#[inline]
pub fn is_punct(c: u8) -> bool {
    is_print(c) && !is_alnum(c) && !is_space(c)
}

/// Returns `true` if `c` is a hexadecimal digit (`[0-9A-Fa-f]`).
#[inline]
pub fn is_xdigit(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

/// Converts `c` to uppercase if it is a lowercase letter.
#[inline]
pub fn to_upper(c: u8) -> u8 {
    if is_lower(c) { c - 32 } else { c }
}

/// Converts `c` to lowercase if it is an uppercase letter.
#[inline]
pub fn to_lower(c: u8) -> u8 {
    if is_upper(c) { c + 32 } else { c }
}

/// Returns `true` if `c` is a blank character (space or tab).
#[inline]
pub fn is_blank(c: u8) -> bool {
    matches!(c, b' ' | b'\t')
}

/// Returns `true` if `c` is a control character (0x00–0x1F or 0x7F).
#[inline]
pub fn is_cntrl(c: u8) -> bool {
    c < 0x20 || c == 0x7F
}

/// Returns `true` if `c` is a visible (graphical) character — printable but not space.
#[inline]
pub fn is_graph(c: u8) -> bool {
    (0x21..=0x7E).contains(&c)
}

/// Returns `true` if `c` is a 7-bit ASCII value (0x00–0x7F).
#[inline]
pub fn is_ascii_val(c: u8) -> bool {
    c <= 0x7F
}

/// Masks `c` to 7-bit ASCII.
#[inline]
pub fn to_ascii(c: u8) -> u8 {
    c & 0x7F
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_alpha() {
        assert!(is_alpha(b'A'));
        assert!(is_alpha(b'Z'));
        assert!(is_alpha(b'a'));
        assert!(is_alpha(b'z'));
        assert!(!is_alpha(b'0'));
        assert!(!is_alpha(b' '));
        assert!(!is_alpha(0));
    }

    #[test]
    fn test_is_digit() {
        for c in b'0'..=b'9' {
            assert!(is_digit(c));
        }
        assert!(!is_digit(b'a'));
        assert!(!is_digit(b'/'));
        assert!(!is_digit(b':'));
    }

    #[test]
    fn test_is_alnum() {
        assert!(is_alnum(b'A'));
        assert!(is_alnum(b'z'));
        assert!(is_alnum(b'5'));
        assert!(!is_alnum(b'!'));
        assert!(!is_alnum(b' '));
    }

    #[test]
    fn test_is_space() {
        assert!(is_space(b' '));
        assert!(is_space(b'\t'));
        assert!(is_space(b'\n'));
        assert!(is_space(0x0B));
        assert!(is_space(0x0C));
        assert!(is_space(b'\r'));
        assert!(!is_space(b'a'));
        assert!(!is_space(0));
    }

    #[test]
    fn test_is_upper_lower() {
        for c in b'A'..=b'Z' {
            assert!(is_upper(c));
            assert!(!is_lower(c));
        }
        for c in b'a'..=b'z' {
            assert!(is_lower(c));
            assert!(!is_upper(c));
        }
    }

    #[test]
    fn test_is_print() {
        assert!(is_print(b' '));
        assert!(is_print(b'~'));
        assert!(is_print(b'A'));
        assert!(!is_print(0x1F));
        assert!(!is_print(0x7F));
        assert!(!is_print(0x80));
    }

    #[test]
    fn test_is_punct() {
        assert!(is_punct(b'!'));
        assert!(is_punct(b'.'));
        assert!(is_punct(b'@'));
        assert!(!is_punct(b'A'));
        assert!(!is_punct(b'0'));
        assert!(!is_punct(b' '));
    }

    #[test]
    fn test_is_xdigit() {
        for c in b'0'..=b'9' {
            assert!(is_xdigit(c));
        }
        for c in b'A'..=b'F' {
            assert!(is_xdigit(c));
        }
        for c in b'a'..=b'f' {
            assert!(is_xdigit(c));
        }
        assert!(!is_xdigit(b'G'));
        assert!(!is_xdigit(b'g'));
    }

    #[test]
    fn test_to_upper_lower() {
        assert_eq!(to_upper(b'a'), b'A');
        assert_eq!(to_upper(b'z'), b'Z');
        assert_eq!(to_upper(b'A'), b'A');
        assert_eq!(to_upper(b'0'), b'0');
        assert_eq!(to_lower(b'A'), b'a');
        assert_eq!(to_lower(b'Z'), b'z');
        assert_eq!(to_lower(b'a'), b'a');
        assert_eq!(to_lower(b'5'), b'5');
    }

    #[test]
    fn test_is_blank() {
        assert!(is_blank(b' '));
        assert!(is_blank(b'\t'));
        assert!(!is_blank(b'\n'));
        assert!(!is_blank(b'a'));
        assert!(!is_blank(0));
    }

    #[test]
    fn test_is_cntrl() {
        assert!(is_cntrl(0));
        assert!(is_cntrl(0x1F));
        assert!(is_cntrl(0x7F));
        assert!(!is_cntrl(b' '));
        assert!(!is_cntrl(b'A'));
        assert!(!is_cntrl(0x80));
    }

    #[test]
    fn test_is_graph() {
        assert!(is_graph(b'!'));
        assert!(is_graph(b'~'));
        assert!(is_graph(b'A'));
        assert!(is_graph(b'0'));
        assert!(!is_graph(b' '));
        assert!(!is_graph(0x1F));
        assert!(!is_graph(0x7F));
    }

    #[test]
    fn test_is_ascii_val() {
        for c in 0u8..=0x7F {
            assert!(is_ascii_val(c));
        }
        for c in 0x80u8..=0xFF {
            assert!(!is_ascii_val(c));
        }
    }

    #[test]
    fn test_to_ascii() {
        assert_eq!(to_ascii(b'A'), b'A');
        assert_eq!(to_ascii(0x80), 0);
        assert_eq!(to_ascii(0xFF), 0x7F);
        assert_eq!(to_ascii(0xC1), 0x41); // 0xC1 & 0x7F = 'A'
    }

    #[test]
    fn exhaustive_invariants() {
        for c in 0u8..=255 {
            assert_eq!(
                is_alnum(c),
                is_alpha(c) || is_digit(c),
                "alnum invariant failed for {c}"
            );
            assert_eq!(
                is_alpha(c),
                is_upper(c) || is_lower(c),
                "alpha invariant failed for {c}"
            );
            if is_punct(c) {
                assert!(is_print(c), "punct must be printable for {c}");
                assert!(!is_alnum(c), "punct must not be alnum for {c}");
                assert_ne!(c, b' ', "punct must not be space for {c}");
            }
            if is_xdigit(c) {
                assert!(
                    is_digit(c) || matches!(c, b'A'..=b'F' | b'a'..=b'f'),
                    "xdigit invariant failed for {c}"
                );
            }
            assert_eq!(
                to_lower(to_upper(c)),
                to_lower(c),
                "round-trip failed for {c}"
            );
            assert_eq!(
                to_upper(to_lower(c)),
                to_upper(c),
                "round-trip failed for {c}"
            );
            // blank ⊂ space
            if is_blank(c) {
                assert!(is_space(c), "blank must be space for {c}");
            }
            // graph = print minus space
            assert_eq!(
                is_graph(c),
                is_print(c) && c != b' ',
                "graph invariant failed for {c}"
            );
            // cntrl and print are disjoint
            assert!(
                !(is_cntrl(c) && is_print(c)),
                "cntrl and print must be disjoint for {c}"
            );
            // to_ascii idempotent
            assert_eq!(
                to_ascii(to_ascii(c)),
                to_ascii(c),
                "to_ascii idempotent failed for {c}"
            );
        }
    }
}
