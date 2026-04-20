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
    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

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

    proptest! {
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_core_classification_invariants(c in any::<u8>()) {
            prop_assert_eq!(is_alnum(c), is_alpha(c) || is_digit(c));
            prop_assert_eq!(is_alpha(c), is_upper(c) || is_lower(c));
            prop_assert_eq!(is_graph(c), is_print(c) && c != b' ');
            prop_assert_eq!(is_punct(c), is_print(c) && !is_alnum(c) && !is_space(c));
        }

        #[test]
        fn prop_case_conversion_roundtrip(c in any::<u8>()) {
            prop_assert_eq!(to_lower(to_upper(c)), to_lower(c));
            prop_assert_eq!(to_upper(to_lower(c)), to_upper(c));
        }

        #[test]
        fn prop_to_ascii_masks_to_seven_bits(c in any::<u8>()) {
            let masked = to_ascii(c);
            prop_assert_eq!(masked, c & 0x7F);
            prop_assert!(is_ascii_val(masked));
            prop_assert_eq!(to_ascii(masked), masked);
        }
    }

    // -----------------------------------------------------------------
    // POSIX.1-2017 §7.3 ctype conformance tables (bd-xkc6)
    // -----------------------------------------------------------------
    //
    // Spec source: IEEE Std 1003.1-2017 Vol 1 §7.3 (Character sets,
    // character type classification, and case mapping).
    //
    // Each case exercises a single character-class predicate with an
    // explicit POSIX clause citation. A reviewer can audit conformance
    // by cross-referencing spec_ref against the §7.3 entry.
    //
    // Scope is the POSIX "C" locale per §7.3.1 — implementations MUST
    // produce exactly the sets listed below for that locale; other
    // locales are out of scope for this module.

    #[derive(Debug)]
    struct ClassifyCase {
        id: &'static str,
        spec_ref: &'static str,
        predicate: fn(u8) -> bool,
        in_class: &'static [u8],
        out_of_class: &'static [u8],
    }

    const CTYPE_CLASSIFY_TABLE: &[ClassifyCase] = &[
        ClassifyCase {
            id: "POSIX-CTYPE-ISDIGIT-001",
            // "isdigit() shall test whether a character is a decimal-
            //  digit character, which in the C locale is '0' through '9'."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isdigit — LC_CTYPE(C) decimal digits",
            predicate: is_digit,
            in_class: b"0123456789",
            out_of_class: b"/:abcdef ABCDEF\t\n\0\x7f",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISUPPER-001",
            // "isupper() shall test whether a character is an upper-
            //  case letter, which in the C locale is 'A' through 'Z'."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isupper — LC_CTYPE(C) uppercase letters",
            predicate: is_upper,
            in_class: b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            out_of_class: b"abcdefghijklmnopqrstuvwxyz0123456789@[\\]^_`",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISLOWER-001",
            spec_ref: "IEEE 1003.1-2017 §7.3.1 islower — LC_CTYPE(C) lowercase letters",
            predicate: is_lower,
            in_class: b"abcdefghijklmnopqrstuvwxyz",
            out_of_class: b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@[\\]^_`",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISALPHA-001",
            // "isalpha() shall test whether a character is a letter,
            //  which in the C locale is any of 'A'..'Z' or 'a'..'z'."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isalpha — LC_CTYPE(C) letters",
            predicate: is_alpha,
            in_class: b"AaBbYyZz",
            out_of_class: b"0123456789 \t\n!@#",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISXDIGIT-001",
            // "isxdigit() shall test for any hexadecimal-digit
            //  character, in the C locale '0'..'9', 'A'..'F', 'a'..'f'."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isxdigit — LC_CTYPE(C) hex digits",
            predicate: is_xdigit,
            in_class: b"0123456789abcdefABCDEF",
            out_of_class: b"gGhHxXyYzZ!@ ",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISSPACE-001",
            // "isspace() shall test for any character that is a
            //  standard white-space character: space, form-feed ('\f'),
            //  newline ('\n'), carriage return ('\r'), horizontal tab
            //  ('\t'), vertical tab ('\v')."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isspace — standard whitespace (C locale)",
            predicate: is_space,
            in_class: b" \t\n\r\x0b\x0c",
            out_of_class: b"aA0!.:/,\x00\x7f",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISBLANK-001",
            // "isblank() shall test for any character that is a
            //  standard blank character. The C locale standard blanks
            //  are space and horizontal tab."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isblank — space and tab only (C locale)",
            predicate: is_blank,
            in_class: b" \t",
            out_of_class: b"\n\r\x0b\x0c0aA!",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISCNTRL-001",
            // "iscntrl() shall test for any control character (a
            //  non-printing character). In the C locale these are the
            //  characters in <0x00..0x1f> plus <0x7f> (DEL)."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 iscntrl — control chars (C locale)",
            predicate: is_cntrl,
            in_class: b"\x00\x01\x07\x1f\x7f",
            out_of_class: b" !@0AaZz~",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISPRINT-001",
            // "isprint() shall test for any printing character
            //  including space. In the C locale these are the
            //  characters in <0x20..0x7e>."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 isprint — printing chars including space",
            predicate: is_print,
            in_class: b" !0@AaZz~",
            out_of_class: b"\x00\x01\x1f\x7f\x80",
        },
        ClassifyCase {
            id: "POSIX-CTYPE-ISPUNCT-001",
            // "ispunct() shall test for any printing character that
            //  is one of a locale-specific set of punctuation
            //  characters for which neither isalnum() nor isspace() is
            //  true."
            spec_ref: "IEEE 1003.1-2017 §7.3.1 ispunct — printing non-alnum non-space",
            predicate: is_punct,
            in_class: b"!#$%&()*+,-./:;<=>?@[]^_`{|}~",
            out_of_class: b"0Aa \t\x00\x7f",
        },
    ];

    #[test]
    fn posix_ctype_classification_conformance_table() {
        let mut fails = Vec::new();
        for case in CTYPE_CLASSIFY_TABLE {
            for &c in case.in_class {
                if !(case.predicate)(c) {
                    fails.push(format!(
                        "{} [{}]: predicate rejected required member 0x{:02x}",
                        case.id, case.spec_ref, c
                    ));
                }
            }
            for &c in case.out_of_class {
                if (case.predicate)(c) {
                    fails.push(format!(
                        "{} [{}]: predicate accepted non-member 0x{:02x}",
                        case.id, case.spec_ref, c
                    ));
                }
            }
        }
        assert!(
            fails.is_empty(),
            "POSIX §7.3.1 ctype classification failures:\n  {}",
            fails.join("\n  ")
        );
    }

    // ---- Case mapping (POSIX §7.3.2) ----

    #[test]
    fn posix_ctype_case_mapping_conformance_table() {
        // POSIX.1-2017 §7.3.2 — tolower(): "If the argument is a
        // character for which isupper() is true, it shall return the
        // corresponding lowercase letter. All other arguments shall be
        // returned unchanged."
        for upper in b'A'..=b'Z' {
            let expected_lower = upper + (b'a' - b'A');
            assert_eq!(
                to_lower(upper),
                expected_lower,
                "POSIX §7.3.2 tolower('{}') must yield '{}'",
                upper as char,
                expected_lower as char,
            );
        }

        // Symmetric: toupper() on lowercase letters.
        for lower in b'a'..=b'z' {
            let expected_upper = lower - (b'a' - b'A');
            assert_eq!(
                to_upper(lower),
                expected_upper,
                "POSIX §7.3.2 toupper('{}') must yield '{}'",
                lower as char,
                expected_upper as char,
            );
        }

        // "All other arguments shall be returned unchanged." — sweep
        // every byte outside the alpha ranges and assert identity.
        for c in 0u8..=255u8 {
            if !is_upper(c) {
                assert_eq!(
                    to_lower(c), c,
                    "POSIX §7.3.2 tolower(0x{c:02x}) must be identity on non-upper"
                );
            }
            if !is_lower(c) {
                assert_eq!(
                    to_upper(c), c,
                    "POSIX §7.3.2 toupper(0x{c:02x}) must be identity on non-lower"
                );
            }
        }
    }
}
