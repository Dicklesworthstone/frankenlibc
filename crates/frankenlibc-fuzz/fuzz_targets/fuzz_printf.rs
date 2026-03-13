#![no_main]
//! Structure-aware fuzz target for FrankenLibC printf formatting engine.
//!
//! Exercises format string parsing and rendering with arbitrary format
//! specifiers, values, widths, and precisions. The invariant: no combination
//! of format string and arguments should panic, produce unbounded output,
//! or corrupt state.
//!
//! Coverage goals:
//! - parse_format_spec: all flag combinations, width/precision modes, length modifiers
//! - parse_format_string: multi-segment format strings with mixed literals and specs
//! - format_signed/format_unsigned: boundary values, all bases (d,i,o,u,x,X)
//! - format_float: NaN, Inf, denormals, all modes (f,e,g,a)
//! - format_str: empty, long, with precision truncation
//! - format_char: all byte values
//! - format_pointer: NULL and arbitrary addresses
//!
//! Bead: bd-1oz.3

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::stdio::printf::{
    format_char, format_float, format_pointer, format_signed, format_str, format_unsigned,
    parse_format_spec, parse_format_string, FormatFlags, FormatSpec, LengthMod, Precision, Width,
};

/// Maximum output buffer size to prevent OOM.
const MAX_OUTPUT: usize = 65536;

/// A structured fuzz input for the printf engine.
#[derive(Debug, Arbitrary)]
struct PrintfFuzzInput {
    /// Raw format string bytes (may contain % specifiers).
    format_bytes: Vec<u8>,
    /// Signed integer value for %d/%i.
    signed_val: i64,
    /// Unsigned integer value for %u/%o/%x.
    unsigned_val: u64,
    /// Float value for %f/%e/%g/%a.
    float_val: f64,
    /// Char value for %c.
    char_val: u8,
    /// Pointer value for %p.
    ptr_val: usize,
    /// String bytes for %s.
    str_val: Vec<u8>,
    /// Width parameter (for fixed or * widths).
    width: u16,
    /// Precision parameter.
    precision: u16,
    /// Flags bitmap.
    flags: u8,
    /// Conversion character selector.
    conversion: u8,
    /// Operation selector.
    op: u8,
}

/// Build a FormatSpec from fuzz input components.
fn make_spec(input: &PrintfFuzzInput) -> FormatSpec {
    let flags = FormatFlags {
        left_justify: input.flags & 1 != 0,
        force_sign: input.flags & 2 != 0,
        space_sign: input.flags & 4 != 0,
        alt_form: input.flags & 8 != 0,
        zero_pad: input.flags & 16 != 0,
    };

    let width = match input.width % 3 {
        0 => Width::None,
        1 => Width::Fixed((input.width as usize / 3).min(1024)),
        _ => Width::Fixed(0),
    };

    let precision = match input.precision % 3 {
        0 => Precision::None,
        1 => Precision::Fixed((input.precision as usize / 3).min(1024)),
        _ => Precision::Fixed(0),
    };

    let conversions = [
        b'd', b'i', b'o', b'u', b'x', b'X', b'f', b'F', b'e', b'E', b'g', b'G', b'a', b'A',
        b'c', b's', b'p', b'n',
    ];
    let conversion = conversions[(input.conversion as usize) % conversions.len()];

    let lengths = [
        LengthMod::None,
        LengthMod::Hh,
        LengthMod::H,
        LengthMod::L,
        LengthMod::Ll,
        LengthMod::Z,
        LengthMod::T,
        LengthMod::J,
        LengthMod::BigL,
    ];
    let length = lengths[(input.flags as usize >> 5) % lengths.len()];

    FormatSpec {
        flags,
        width,
        precision,
        length,
        conversion,
    }
}

fuzz_target!(|input: PrintfFuzzInput| {
    if input.format_bytes.len() > MAX_OUTPUT || input.str_val.len() > MAX_OUTPUT {
        return;
    }

    match input.op % 8 {
        0 => fuzz_parse_spec(&input),
        1 => fuzz_parse_string(&input),
        2 => fuzz_format_signed(&input),
        3 => fuzz_format_unsigned(&input),
        4 => fuzz_format_float(&input),
        5 => fuzz_format_str(&input),
        6 => fuzz_format_char(&input),
        7 => fuzz_format_pointer(&input),
        _ => unreachable!(),
    }
});

/// Fuzz parse_format_spec with arbitrary byte sequences.
fn fuzz_parse_spec(input: &PrintfFuzzInput) {
    let bytes = &input.format_bytes;
    if bytes.is_empty() {
        return;
    }
    // parse_format_spec expects bytes after '%'
    let result = parse_format_spec(bytes);
    if let Some((spec, consumed)) = result {
        assert!(consumed <= bytes.len());
        // Conversion should be a recognized character
        let _ = spec.conversion;
        let _ = spec.flags;
        let _ = spec.width;
        let _ = spec.precision;
    }
}

/// Fuzz parse_format_string with arbitrary format strings.
fn fuzz_parse_string(input: &PrintfFuzzInput) {
    let bytes = &input.format_bytes;
    let segments = parse_format_string(bytes);
    // Should never panic; segments should cover all input bytes
    let _ = segments.len();
}

/// Fuzz format_signed with boundary values and all flag combinations.
fn fuzz_format_signed(input: &PrintfFuzzInput) {
    let spec = make_spec(input);
    let mut buf = Vec::new();

    // Test with the fuzz-provided value
    format_signed(input.signed_val, &spec, &mut buf);
    assert!(buf.len() < MAX_OUTPUT);

    // Also test boundary values
    buf.clear();
    format_signed(0, &spec, &mut buf);

    buf.clear();
    format_signed(i64::MIN, &spec, &mut buf);

    buf.clear();
    format_signed(i64::MAX, &spec, &mut buf);

    buf.clear();
    format_signed(-1, &spec, &mut buf);
}

/// Fuzz format_unsigned with all bases and flag combinations.
fn fuzz_format_unsigned(input: &PrintfFuzzInput) {
    let spec = make_spec(input);
    let mut buf = Vec::new();

    format_unsigned(input.unsigned_val, &spec, &mut buf);
    assert!(buf.len() < MAX_OUTPUT);

    buf.clear();
    format_unsigned(0, &spec, &mut buf);

    buf.clear();
    format_unsigned(u64::MAX, &spec, &mut buf);
}

/// Fuzz format_float with special values and all modes.
fn fuzz_format_float(input: &PrintfFuzzInput) {
    let spec = make_spec(input);
    let mut buf = Vec::new();

    // Fuzz-provided value
    format_float(input.float_val, &spec, &mut buf);
    assert!(buf.len() < MAX_OUTPUT);

    // Special values: NaN, Inf, -Inf, 0, -0, denormals
    for &val in &[
        0.0_f64,
        -0.0,
        1.0,
        -1.0,
        f64::INFINITY,
        f64::NEG_INFINITY,
        f64::NAN,
        f64::MIN_POSITIVE, // smallest normal
        5e-324,            // smallest denormal
        f64::MAX,
        f64::MIN,
    ] {
        buf.clear();
        format_float(val, &spec, &mut buf);
    }
}

/// Fuzz format_str with various precision truncation scenarios.
fn fuzz_format_str(input: &PrintfFuzzInput) {
    let spec = make_spec(input);
    let mut buf = Vec::new();

    // Use the fuzz-provided string
    let s = &input.str_val;
    format_str(s, &spec, &mut buf);
    assert!(buf.len() < MAX_OUTPUT);

    // Empty string
    buf.clear();
    format_str(&[], &spec, &mut buf);

    // Single byte
    buf.clear();
    format_str(&[input.char_val], &spec, &mut buf);
}

/// Fuzz format_char with all byte values.
fn fuzz_format_char(input: &PrintfFuzzInput) {
    let spec = make_spec(input);
    let mut buf = Vec::new();

    format_char(input.char_val, &spec, &mut buf);
    assert!(buf.len() < MAX_OUTPUT);

    // Test NUL character
    buf.clear();
    format_char(0, &spec, &mut buf);
}

/// Fuzz format_pointer with various address patterns.
fn fuzz_format_pointer(input: &PrintfFuzzInput) {
    let spec = make_spec(input);
    let mut buf = Vec::new();

    format_pointer(input.ptr_val, &spec, &mut buf);
    assert!(buf.len() < MAX_OUTPUT);

    // NULL pointer
    buf.clear();
    format_pointer(0, &spec, &mut buf);

    // Max address
    buf.clear();
    format_pointer(usize::MAX, &spec, &mut buf);
}
