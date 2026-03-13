#![no_main]
//! Structure-aware fuzz target for FrankenLibC ctype character classification.
//!
//! Exercises all is_* and to_* functions from `frankenlibc-core::ctype` with
//! fuzzer-generated inputs. The invariants are:
//! - Classification functions are pure (deterministic, no side effects)
//! - to_upper(to_lower(c)) round-trips for alphabetic characters
//! - Partition invariants: every byte is either print or cntrl (never both)
//! - No function should panic on any u8 input
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::ctype;

#[derive(Debug, Arbitrary)]
struct CtypeFuzzInput {
    /// Bytes to classify.
    bytes: Vec<u8>,
    /// Operation selector.
    op: u8,
}

const MAX_BYTES: usize = 4096;

fuzz_target!(|input: CtypeFuzzInput| {
    if input.bytes.len() > MAX_BYTES {
        return;
    }

    match input.op % 5 {
        0 => fuzz_classification_exhaustive(&input),
        1 => fuzz_case_roundtrip(&input),
        2 => fuzz_partition_invariants(&input),
        3 => fuzz_digit_xdigit_subset(&input),
        4 => fuzz_consistency(&input),
        _ => unreachable!(),
    }
});

/// Exercise every classifier on every byte in the input.
fn fuzz_classification_exhaustive(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        // All these must not panic on any u8
        let _ = ctype::is_alpha(c);
        let _ = ctype::is_digit(c);
        let _ = ctype::is_alnum(c);
        let _ = ctype::is_space(c);
        let _ = ctype::is_upper(c);
        let _ = ctype::is_lower(c);
        let _ = ctype::is_print(c);
        let _ = ctype::is_punct(c);
        let _ = ctype::is_xdigit(c);
        let _ = ctype::is_blank(c);
        let _ = ctype::is_cntrl(c);
        let _ = ctype::is_graph(c);
        let _ = ctype::is_ascii_val(c);
        let _ = ctype::to_upper(c);
        let _ = ctype::to_lower(c);
        let _ = ctype::to_ascii(c);
    }
}

/// Verify case conversion round-trips for alphabetic bytes.
fn fuzz_case_roundtrip(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        let upper = ctype::to_upper(c);
        let lower = ctype::to_lower(c);

        if ctype::is_alpha(c) {
            // For alpha chars, upper must be upper and lower must be lower
            assert!(
                ctype::is_upper(upper),
                "to_upper({c:#04x}) = {upper:#04x} should be upper"
            );
            assert!(
                ctype::is_lower(lower),
                "to_lower({c:#04x}) = {lower:#04x} should be lower"
            );

            // Round-trip: to_lower(to_upper(c)) == to_lower(c)
            assert_eq!(
                ctype::to_lower(upper),
                lower,
                "to_lower(to_upper({c:#04x})) should equal to_lower({c:#04x})"
            );
            // Round-trip: to_upper(to_lower(c)) == to_upper(c)
            assert_eq!(
                ctype::to_upper(lower),
                upper,
                "to_upper(to_lower({c:#04x})) should equal to_upper({c:#04x})"
            );
        }

        // Non-alpha characters should pass through unchanged
        if !ctype::is_upper(c) && !ctype::is_lower(c) {
            assert_eq!(upper, c, "to_upper on non-alpha should be identity");
            assert_eq!(lower, c, "to_lower on non-alpha should be identity");
        }
    }
}

/// Verify partition invariants: mutually exclusive categories.
fn fuzz_partition_invariants(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        let alpha = ctype::is_alpha(c);
        let digit = ctype::is_digit(c);
        let alnum = ctype::is_alnum(c);
        let print = ctype::is_print(c);
        let cntrl = ctype::is_cntrl(c);
        let graph = ctype::is_graph(c);
        let space = ctype::is_space(c);
        let upper = ctype::is_upper(c);
        let lower = ctype::is_lower(c);
        let punct = ctype::is_punct(c);

        // alnum = alpha | digit
        assert_eq!(
            alnum,
            alpha || digit,
            "alnum({c:#04x}) should be alpha || digit"
        );

        // alpha = upper | lower
        if alpha {
            assert!(
                upper || lower,
                "alpha({c:#04x}) should imply upper or lower"
            );
        }

        // upper and lower are mutually exclusive
        assert!(
            !(upper && lower),
            "upper and lower should be mutually exclusive for {c:#04x}"
        );

        // graph chars are printable but not space
        if graph {
            assert!(print, "graph({c:#04x}) should imply print");
        }

        // Control and print are generally mutually exclusive (except some edge cases)
        // For ASCII 0..=127, they should be mutually exclusive
        if c <= 127 && c != b' ' {
            // Note: space (0x20) is both print and not cntrl
            if cntrl {
                assert!(!print || c == 0x7f, "cntrl and print overlap at {c:#04x}");
            }
        }

        // punct is print but not alnum and not space
        if punct {
            assert!(print, "punct({c:#04x}) should imply print");
            assert!(!alnum, "punct({c:#04x}) should not be alnum");
        }

        let _ = space; // used for completeness
    }
}

/// Verify digit ⊂ xdigit.
fn fuzz_digit_xdigit_subset(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        if ctype::is_digit(c) {
            assert!(
                ctype::is_xdigit(c),
                "digit({c:#04x}) must also be xdigit"
            );
        }
    }
}

/// Cross-function consistency checks.
fn fuzz_consistency(input: &CtypeFuzzInput) {
    for &c in &input.bytes {
        // to_ascii should mask to 7 bits
        let a = ctype::to_ascii(c);
        assert!(a <= 127, "to_ascii({c:#04x}) should produce <=127, got {a}");

        // is_ascii_val should be true iff c <= 127
        assert_eq!(
            ctype::is_ascii_val(c),
            c <= 127,
            "is_ascii_val({c:#04x}) inconsistent"
        );

        // Determinism: calling twice should give same result
        assert_eq!(ctype::is_alpha(c), ctype::is_alpha(c));
        assert_eq!(ctype::to_upper(c), ctype::to_upper(c));
        assert_eq!(ctype::to_lower(c), ctype::to_lower(c));
    }
}
