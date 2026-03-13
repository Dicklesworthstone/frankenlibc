#![no_main]
//! Structure-aware fuzz target for FrankenLibC POSIX regex engine.
//!
//! Exercises Thompson NFA compilation and execution with arbitrary patterns
//! and input strings. The invariant: no combination of pattern, input, and
//! flags should panic, produce unbounded output, or corrupt state.
//!
//! Coverage goals:
//! - regex_compile: all flag combinations (BRE/ERE, ICASE, NEWLINE, NOSUB)
//! - regex_exec: matching, submatches, eflags (NOTBOL, NOTEOL)
//! - regex_error: all error codes
//! - Parser: character classes, anchors, groups, quantifiers, alternation
//! - NFA: epsilon transitions, tagged saves, Pike VM simulation
//! - Edge cases: empty patterns, deeply nested groups, catastrophic patterns
//!
//! Bead: bd-1oz.7

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::string::regex::{
    regex_compile, regex_error, regex_exec, RegMatch, REG_EXTENDED, REG_ICASE, REG_NEWLINE,
    REG_NOMATCH, REG_NOSUB, REG_NOTBOL, REG_NOTEOL,
};

/// Maximum pattern length to prevent NFA explosion.
const MAX_PATTERN: usize = 256;

/// Maximum input length for matching.
const MAX_INPUT: usize = 1024;

/// Maximum number of submatch slots.
const MAX_MATCHES: usize = 16;

/// A structured fuzz input for the regex engine.
#[derive(Debug, Arbitrary)]
struct RegexFuzzInput {
    /// Pattern bytes.
    pattern: Vec<u8>,
    /// Input string to match against.
    input: Vec<u8>,
    /// Compilation flags bitmap.
    cflags: u8,
    /// Execution flags bitmap.
    eflags: u8,
    /// Operation selector.
    op: u8,
}

/// Build cflags from fuzz input.
fn make_cflags(raw: u8) -> i32 {
    let mut flags = 0i32;
    if raw & 1 != 0 {
        flags |= REG_EXTENDED;
    }
    if raw & 2 != 0 {
        flags |= REG_ICASE;
    }
    if raw & 4 != 0 {
        flags |= REG_NEWLINE;
    }
    if raw & 8 != 0 {
        flags |= REG_NOSUB;
    }
    flags
}

/// Build eflags from fuzz input.
fn make_eflags(raw: u8) -> i32 {
    let mut flags = 0i32;
    if raw & 1 != 0 {
        flags |= REG_NOTBOL;
    }
    if raw & 2 != 0 {
        flags |= REG_NOTEOL;
    }
    flags
}

fuzz_target!(|input: RegexFuzzInput| {
    if input.pattern.len() > MAX_PATTERN || input.input.len() > MAX_INPUT {
        return;
    }

    match input.op % 4 {
        0 => fuzz_compile_exec(&input),
        1 => fuzz_compile_only(&input),
        2 => fuzz_known_patterns(&input),
        3 => fuzz_error_codes(&input),
        _ => unreachable!(),
    }
});

/// Fuzz compile + exec with arbitrary patterns and inputs.
fn fuzz_compile_exec(input: &RegexFuzzInput) {
    let cflags = make_cflags(input.cflags);
    let eflags = make_eflags(input.eflags);

    // Compile — may fail with an error code, but should never panic
    match regex_compile(&input.pattern, cflags) {
        Ok(compiled) => {
            // Execute against the fuzz-provided input
            let mut matches = vec![RegMatch::default(); MAX_MATCHES];
            let result = regex_exec(&compiled, &input.input, &mut matches, eflags);

            // Result should be 0 (match) or REG_NOMATCH
            assert!(
                result == 0 || result == REG_NOMATCH,
                "regex_exec returned unexpected code: {result}"
            );

            // If matched and not NOSUB, verify submatch offsets are sane
            if result == 0 && cflags & REG_NOSUB == 0 {
                let input_len = input
                    .input
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(input.input.len())
                    as i32;

                for m in &matches {
                    if m.rm_so >= 0 {
                        assert!(
                            m.rm_so <= m.rm_eo,
                            "submatch start ({}) > end ({})",
                            m.rm_so,
                            m.rm_eo
                        );
                        assert!(
                            m.rm_eo <= input_len,
                            "submatch end ({}) > input length ({input_len})",
                            m.rm_eo
                        );
                    }
                }
            }

            // Also try with empty input
            let mut empty_matches = vec![RegMatch::default(); MAX_MATCHES];
            let _ = regex_exec(&compiled, b"", &mut empty_matches, eflags);

            // Try with no match slots
            let _ = regex_exec(&compiled, &input.input, &mut [], eflags);
        }
        Err(errcode) => {
            // Error code should map to a known error string
            let msg = regex_error(errcode);
            assert!(!msg.is_empty(), "error message should not be empty");
        }
    }
}

/// Fuzz compilation only — focus on parser edge cases.
fn fuzz_compile_only(input: &RegexFuzzInput) {
    // Try all flag combinations
    for cflags_raw in 0..16u8 {
        let cflags = make_cflags(cflags_raw);
        match regex_compile(&input.pattern, cflags) {
            Ok(_) => {}
            Err(errcode) => {
                let _ = regex_error(errcode);
            }
        }
    }
}

/// Test known patterns that exercise specific parser paths.
fn fuzz_known_patterns(input: &RegexFuzzInput) {
    let cflags = make_cflags(input.cflags);
    let eflags = make_eflags(input.eflags);
    let test_input = if input.input.is_empty() {
        b"hello world 123".as_slice()
    } else {
        &input.input[..input.input.len().min(MAX_INPUT)]
    };

    // Patterns that exercise specific features
    let patterns: &[&[u8]] = &[
        // Basic literals
        b"hello",
        b"",
        // Character classes
        b"[a-z]",
        b"[^0-9]",
        b"[[:alpha:]]",
        b"[[:digit:][:space:]]",
        // Anchors
        b"^start",
        b"end$",
        b"^exact$",
        // Quantifiers (ERE)
        b"a*",
        b"a+",
        b"a?",
        b"a{2,5}",
        // Groups
        b"(abc)",
        b"(a|b|c)",
        b"((a)(b))",
        // Combined
        b"[a-z]+@[a-z]+\\.[a-z]+",
        b"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$",
        // Edge cases
        b".",
        b".*",
        b".+",
        b"\\.",
        b"\\\\",
    ];

    for &pat in patterns {
        match regex_compile(pat, cflags) {
            Ok(compiled) => {
                let mut matches = vec![RegMatch::default(); MAX_MATCHES];
                let _ = regex_exec(&compiled, test_input, &mut matches, eflags);
            }
            Err(_) => {
                // Some patterns may be invalid in BRE mode
            }
        }
    }
}

/// Fuzz regex_error for all possible error codes.
fn fuzz_error_codes(input: &RegexFuzzInput) {
    // Test all defined error codes
    for code in 0..=14 {
        let msg = regex_error(code);
        assert!(!msg.is_empty());
    }

    // Test with arbitrary error code from fuzz input
    let arbitrary_code = input.cflags as i32;
    let _ = regex_error(arbitrary_code);

    // Test with negative codes
    let _ = regex_error(-1);
    let _ = regex_error(i32::MIN);
    let _ = regex_error(i32::MAX);
}
