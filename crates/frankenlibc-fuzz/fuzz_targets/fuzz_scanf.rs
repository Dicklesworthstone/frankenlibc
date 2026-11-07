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

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::stdio::scanf::{
    ScanDirective, ScanValue, WideScanEvent, WideScanInput, WideScanProgress, WideScanSession,
    WideScanWriteError, parse_scanf_format, parse_scanf_format_wide, scan_input,
};

/// Maximum format string length to bound parsing.
const MAX_FORMAT: usize = 1024;

/// Maximum input length for scanning.
const MAX_INPUT: usize = 4096;

/// Human-readable directed seed prefix.
const DIRECTED_PREFIX: &[u8] = b"scan:";

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

fuzz_target!(|data: &[u8]| {
    if let Some(input) = directed_input(data) {
        fuzz_scanf(input);
        return;
    }

    let mut raw = Unstructured::new(data);
    let Ok(input) = ScanfFuzzInput::arbitrary(&mut raw) else {
        return;
    };

    fuzz_scanf(input);
});

fn fuzz_scanf(input: ScanfFuzzInput) {
    if input.format_bytes.len() > MAX_FORMAT || input.input_bytes.len() > MAX_INPUT {
        return;
    }

    match input.op % 5 {
        0 => fuzz_parse_format(&input),
        1 => fuzz_scan_input(&input),
        2 => fuzz_known_formats(&input),
        3 => fuzz_scanset_edge_cases(&input),
        _ => fuzz_wide_stream(&input),
    }
}

/// Decode text seeds shaped as:
///
/// ```text
/// scan:<op>
/// <format>
/// ---
/// <input>
/// ```
///
/// The op is one of `parse`, `scan`, `known`, `scanset`, or `wide`.
fn directed_input(data: &[u8]) -> Option<ScanfFuzzInput> {
    let rest = data.strip_prefix(DIRECTED_PREFIX)?;
    let (op_name, payload) = split_once_byte(rest, b'\n')?;
    let (format_bytes, input_bytes) = split_once_marker(payload, b"\n---\n")?;
    let input_bytes = strip_single_trailing_newline(input_bytes);

    Some(ScanfFuzzInput {
        format_bytes: format_bytes.to_vec(),
        input_bytes: input_bytes.to_vec(),
        op: directed_op(op_name)?,
    })
}

fn directed_op(op_name: &[u8]) -> Option<u8> {
    match op_name {
        b"parse" => Some(0),
        b"scan" => Some(1),
        b"known" => Some(2),
        b"scanset" => Some(3),
        b"wide" => Some(4),
        _ => None,
    }
}

fn split_once_byte(data: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    let split_at = data.iter().position(|&b| b == byte)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(1..)?))
}

fn split_once_marker<'a>(data: &'a [u8], marker: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    if marker.is_empty() {
        return None;
    }

    let split_at = data
        .windows(marker.len())
        .position(|window| window == marker)?;
    let (head, tail) = data.split_at(split_at);
    Some((head, tail.get(marker.len()..)?))
}

fn strip_single_trailing_newline(data: &[u8]) -> &[u8] {
    data.strip_suffix(b"\n").unwrap_or(data)
}

/// Fuzz parse_scanf_format with arbitrary format strings.
fn fuzz_parse_format(input: &ScanfFuzzInput) {
    let fmt = &input.format_bytes;

    // Should never panic regardless of format string content
    let directives = parse_scanf_format(fmt);

    // Verify directive structure
    for d in directives.iter() {
        match d {
            ScanDirective::Literal(b) => {
                let _ = b;
            }
            ScanDirective::WideLiteral(_) => {
                panic!("narrow format parser produced a wide literal");
            }
            ScanDirective::Whitespace | ScanDirective::Malformed => {}
            ScanDirective::Spec(spec) => {
                let _ = spec.suppress;
                let _ = spec.width;
                let _ = spec.length;
                let _ = spec.conversion;
                if let Some(ref scanset) = spec.scanset {
                    // Exercise the complete byte domain through the public
                    // membership API. Negation is applied by the scanner, so
                    // it must not change the set's raw membership.
                    let mut inverted = scanset.as_ref().clone();
                    inverted.negated = !scanset.negated;
                    for byte in u8::MIN..=u8::MAX {
                        assert_eq!(
                            scanset.contains(byte),
                            inverted.contains(byte),
                            "raw scanset membership must not depend on negation"
                        );
                    }
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
    for val in result.values.iter() {
        match val {
            ScanValue::Unset => panic!("scanner exposed an unused inline value"),
            ScanValue::SignedInt(_) => {}
            ScanValue::UnsignedInt(_) => {}
            ScanValue::Float(f) => {
                // Float should be a valid f64 (not uninitialized)
                let _ = f.is_nan();
                let _ = f.is_infinite();
            }
            ScanValue::LongDouble(_) => {}
            ScanValue::Char(bytes) => {
                // Empty bytes is a valid outcome for crafted format
                // specs like "%0c" (width=0). Harness can't assume
                // width>0 on fuzzer-generated formats.
                let _ = bytes.len();
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
        &input.input_bytes
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


/// Exercise scalar demand, incremental destination failure, and exact rollback.
fn fuzz_wide_stream(input: &ScanfFuzzInput) {
    let format = String::from_utf8_lossy(&input.format_bytes);
    let characters: Vec<u32> = String::from_utf8_lossy(&input.input_bytes)
        .chars()
        .map(u32::from)
        .collect();
    let directives = parse_scanf_format_wide(format.as_bytes());
    let mut session = WideScanSession::new(directives.as_slice(), u32::from(b'.'));
    let mut supplied = 0usize;
    let mut next = None;
    let mut terminal = false;
    let mut pending_text = false;
    let mut assignments = 0i32;
    let mut failed_writer = false;
    loop {
        let progress = session.resume(
            next.take(),
            &mut |spec, event, context| {
                assert!(!spec.suppress, "suppressed fields must not reach a writer");
                assert!(!failed_writer, "a failed writer must stop later events");
                assert!(context.consumed <= supplied);
                match event {
                    WideScanEvent::BeginText => {
                        assert!(!pending_text, "text fields cannot overlap");
                        pending_text = true;
                    }
                    WideScanEvent::Character(wc) => {
                        assert!(pending_text);
                        if input.op & 8 != 0 && wc >= 0x80 {
                            pending_text = false;
                            failed_writer = true;
                            return Err(WideScanWriteError {
                                input_failure: spec.writes_char_buffer(),
                            });
                        }
                    }
                    WideScanEvent::EndText => {
                        assert!(pending_text);
                        pending_text = false;
                        assignments += 1;
                    }
                    WideScanEvent::AbortText => {
                        assert!(pending_text);
                        pending_text = false;
                    }
                    WideScanEvent::Value(value) => {
                        assert!(!pending_text);
                        assert!(!matches!(value, ScanValue::Unset));
                        if !matches!(value, ScanValue::CharsConsumed(_)) {
                            assignments += 1;
                        }
                    }
                }
                Ok(())
            },
            &frankenlibc_core::string::wchar::iswspace,
        );
        match progress {
            WideScanProgress::NeedInput(_) => {
                assert!(!failed_writer);
                assert!(!terminal, "a terminal source cannot be read again");
                if let Some(&wc) = characters.get(supplied) {
                    supplied += 1;
                    next = Some(WideScanInput::Character(wc));
                } else {
                    terminal = true;
                    next = Some(if input.op & 16 == 0 {
                        WideScanInput::Eof
                    } else {
                        WideScanInput::Error
                    });
                }
            }
            WideScanProgress::Complete(summary) => {
                assert!(!pending_text, "completion must finish or abandon text");
                assert_eq!(summary.count, assignments);
                assert!(summary.consumed <= supplied);
                assert_eq!(
                    session.unread().collect::<Vec<_>>(),
                    characters[summary.consumed..supplied],
                    "lookahead must preserve the exact remaining scalar suffix"
                );
                return;
            }
        }
    }
}
