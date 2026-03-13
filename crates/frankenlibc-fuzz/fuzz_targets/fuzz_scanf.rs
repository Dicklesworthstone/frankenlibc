#![no_main]
//! Structure-aware fuzz target for FrankenLibC scanf format parsing and scanning.
//!
//! Exercises scanf format string parsing and input scanning with arbitrary
//! format strings and input data. The invariant: no combination of format
//! and input should panic, produce unbounded output, or corrupt state.
//!
//! Coverage goals:
//! - parse_scanf_format: all directive types, scansets, length modifiers
//! - scan_input: integer/float/string/char/pointer scanning, width limits
//! - ScanSet: character ranges, negation, special characters
//! - Whitespace handling: skip directives, trailing whitespace
//! - Error handling: input exhaustion, format mismatch, invalid specifiers
//!
//! Bead: bd-1oz.7

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::stdio::scanf::{parse_scanf_format, scan_input, ScanDirective, ScanValue};

/// Maximum format string length to bound parsing.
const MAX_FORMAT: usize = 1024;

/// Maximum input length for scanning.
const MAX_INPUT: usize = 4096;

/// A structured fuzz input for the scanf engine.
#[derive(Debug, Arbitrary)]
struct ScanfFuzzInput {
    /// Format string bytes.
    format_bytes: Vec<u8>,
    /// Input bytes to scan.
    input_bytes: Vec<u8>,
    /// Operation selector.
    op: u8,
}

fuzz_target!(|input: ScanfFuzzInput| {
    if input.format_bytes.len() > MAX_FORMAT || input.input_bytes.len() > MAX_INPUT {
        return;
    }

    match input.op % 4 {
        0 => fuzz_parse_format(&input),
        1 => fuzz_scan_input(&input),
        2 => fuzz_known_formats(&input),
        3 => fuzz_scanset_edge_cases(&input),
        _ => unreachable!(),
    }
});

/// Fuzz parse_scanf_format with arbitrary format strings.
fn fuzz_parse_format(input: &ScanfFuzzInput) {
    let fmt = &input.format_bytes;

    // Should never panic regardless of format string content
    let directives = parse_scanf_format(fmt);

    // Verify directive structure
    for d in &directives {
        match d {
            ScanDirective::Literal(b) => {
                let _ = b;
            }
            ScanDirective::Whitespace => {}
            ScanDirective::Spec(spec) => {
                let _ = spec.suppress;
                let _ = spec.width;
                let _ = spec.length;
                let _ = spec.conversion;
                if let Some(ref scanset) = spec.scanset {
                    let _ = scanset.negated;
                    // Verify the bitmap is valid (256 entries)
                    assert_eq!(scanset.chars.len(), 256);
                }
            }
        }
    }
}

/// Fuzz scan_input with arbitrary format + input combinations.
fn fuzz_scan_input(input: &ScanfFuzzInput) {
    let fmt = &input.format_bytes;
    let data = &input.input_bytes;

    // Parse format first
    let directives = parse_scanf_format(fmt);

    if directives.is_empty() {
        return;
    }

    // Scan input — should never panic
    let result = scan_input(data, &directives);

    // Verify result structure
    assert!(result.count >= 0, "scan count should be non-negative");
    assert!(
        result.consumed <= data.len(),
        "consumed ({}) > input length ({})",
        result.consumed,
        data.len()
    );

    // Verify value types
    for val in &result.values {
        match val {
            ScanValue::SignedInt(_) => {}
            ScanValue::UnsignedInt(_) => {}
            ScanValue::Float(f) => {
                // Float should be a valid f64 (not uninitialized)
                let _ = f.is_nan();
                let _ = f.is_infinite();
            }
            ScanValue::Char(bytes) => {
                assert!(!bytes.is_empty(), "scanned char should not be empty");
            }
            ScanValue::String(bytes) => {
                let _ = bytes.len();
            }
            ScanValue::CharsConsumed(n) => {
                assert!(
                    *n <= data.len(),
                    "chars consumed ({n}) > input length ({})",
                    data.len()
                );
            }
            ScanValue::Pointer(_) => {}
        }
    }
}

/// Test known format strings that exercise specific parsing paths.
fn fuzz_known_formats(input: &ScanfFuzzInput) {
    let data = if input.input_bytes.is_empty() {
        b"42 -17 3.14 hello 0xDEAD".as_slice()
    } else {
        &input.input_bytes[..input.input_bytes.len().min(MAX_INPUT)]
    };

    let formats: &[&[u8]] = &[
        // Integer conversions
        b"%d",
        b"%i",
        b"%u",
        b"%o",
        b"%x",
        b"%X",
        // Float conversions
        b"%f",
        b"%e",
        b"%g",
        b"%a",
        // String/char conversions
        b"%s",
        b"%c",
        b"%p",
        b"%n",
        // Width specifiers
        b"%5d",
        b"%10s",
        b"%3c",
        // Suppression
        b"%*d",
        b"%*s",
        // Length modifiers
        b"%ld",
        b"%lld",
        b"%hd",
        b"%hhd",
        b"%zu",
        // Multiple conversions
        b"%d %d %d",
        b"%s %d %f",
        // Literals
        b"val=%d",
        b"%d,%d",
        // Percent literal
        b"%%",
        b"%% %d",
        // Empty
        b"",
        // Scansets
        b"%[a-z]",
        b"%[^a-z]",
        b"%[abc]",
        b"%[^abc]",
        b"%[]abc]",
        b"%[^]abc]",
        // Whitespace
        b" %d",
        b"%d %d",
        b"\t%d",
    ];

    for &fmt in formats {
        let directives = parse_scanf_format(fmt);
        if !directives.is_empty() {
            let result = scan_input(data, &directives);
            let _ = result.count;
            let _ = result.consumed;
        }
    }
}

/// Test scanset edge cases with various character range patterns.
fn fuzz_scanset_edge_cases(input: &ScanfFuzzInput) {
    let data = &input.input_bytes;
    if data.is_empty() {
        return;
    }

    // Build format strings with scansets from fuzz input
    let scanset_formats: Vec<Vec<u8>> = vec![
        // Simple scanset from first few bytes
        {
            let mut fmt = b"%[".to_vec();
            for &b in input.format_bytes.iter().take(10) {
                if b != b']' && b != 0 {
                    fmt.push(b);
                }
            }
            fmt.extend_from_slice(b"]");
            fmt
        },
        // Negated scanset
        {
            let mut fmt = b"%[^".to_vec();
            for &b in input.format_bytes.iter().take(10) {
                if b != b']' && b != 0 {
                    fmt.push(b);
                }
            }
            fmt.extend_from_slice(b"]");
            fmt
        },
        // Range scanset
        b"%[a-zA-Z0-9]".to_vec(),
        b"%[^\\n]".to_vec(),
        // Edge: ] as first character
        b"%[]a]".to_vec(),
        b"%[^]a]".to_vec(),
    ];

    for fmt in &scanset_formats {
        let directives = parse_scanf_format(fmt);
        if !directives.is_empty() {
            let result = scan_input(data, &directives);
            let _ = result.count;
        }
    }
}
