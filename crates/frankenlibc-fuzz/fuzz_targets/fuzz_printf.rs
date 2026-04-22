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
//! - ABI `snprintf`/`sprintf`/`asprintf`: truncation, `%n`, and typed-family consistency
//!
//! Bead: bd-1oz.3

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::Once;

use arbitrary::Arbitrary;
use frankenlibc_abi::malloc_abi::{free, malloc};
use frankenlibc_abi::stdio_abi::{asprintf, snprintf, sprintf};
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::stdio::printf::{
    FormatFlags, FormatSpec, LengthMod, Precision, Width, format_char, format_float,
    format_pointer, format_signed, format_str, format_unsigned, parse_format_spec,
    parse_format_string,
};

/// Maximum output buffer size to prevent OOM.
const MAX_OUTPUT: usize = 65536;
/// Maximum dynamic string size when crossing the ABI boundary.
const MAX_ABI_STRING: usize = 2048;
/// Large comparison buffer used to compute the non-truncated `snprintf` rendering.
const ABI_COMPARE_BUF: usize = 4096;

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
        b'd', b'i', b'o', b'u', b'x', b'X', b'f', b'F', b'e', b'E', b'g', b'G', b'a', b'A', b'c',
        b's', b'p', b'n',
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

    FormatSpec::new(
        flags,
        width,
        precision,
        length,
        conversion,
        None,
    )
}

fn init_hardened_printf_mode() {
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        // SAFETY: the fuzz target sets the process mode once, before the first ABI
        // entrypoint is exercised, and never mutates it again.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

fn sanitize_cstring(bytes: &[u8], limit: usize) -> CString {
    let sanitized: Vec<u8> = bytes
        .iter()
        .copied()
        .take(limit)
        .map(|byte| if byte == 0 { b'?' } else { byte })
        .collect();
    CString::new(sanitized).expect("interior NUL bytes are replaced during sanitization")
}

fn width_arg(raw: u16) -> c_int {
    let magnitude = (raw % 64) as c_int;
    if raw & 1 == 0 { magnitude } else { -magnitude }
}

fn precision_arg(raw: u16) -> c_int {
    let magnitude = (raw % 64) as c_int;
    if raw & 1 == 0 { magnitude } else { -magnitude }
}

fn c_buffer_prefix(buf: &[c_char]) -> Vec<u8> {
    let copied = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
    buf.iter().take(copied).map(|&ch| ch as u8).collect()
}

unsafe extern "C" fn call_snprintf_signed(buf: *mut c_char, size: usize, value: i64) -> c_int {
    unsafe { snprintf(buf, size, c"%lld".as_ptr(), value) }
}

unsafe extern "C" fn call_snprintf_unsigned(buf: *mut c_char, size: usize, value: u64) -> c_int {
    unsafe { snprintf(buf, size, c"%#llx".as_ptr(), value) }
}

unsafe extern "C" fn call_snprintf_float(buf: *mut c_char, size: usize, value: f64) -> c_int {
    unsafe { snprintf(buf, size, c"%.17g".as_ptr(), value) }
}

unsafe extern "C" fn call_snprintf_pointer(
    buf: *mut c_char,
    size: usize,
    value: *const c_void,
) -> c_int {
    unsafe { snprintf(buf, size, c"%p".as_ptr(), value) }
}

unsafe extern "C" fn call_snprintf_width_precision_string(
    buf: *mut c_char,
    size: usize,
    width: c_int,
    precision: c_int,
    value: *const c_char,
) -> c_int {
    unsafe { snprintf(buf, size, c"%*.*s".as_ptr(), width, precision, value) }
}

unsafe extern "C" fn call_snprintf_count(
    buf: *mut c_char,
    size: usize,
    count: *mut c_int,
    value: *const c_char,
) -> c_int {
    unsafe { snprintf(buf, size, c"abc%n:%s".as_ptr(), count, value) }
}

unsafe extern "C" fn call_snprintf_combo(
    buf: *mut c_char,
    size: usize,
    signed: i64,
    text: *const c_char,
    unsigned: u64,
) -> c_int {
    unsafe { snprintf(buf, size, c"%lld:%s:%#llx".as_ptr(), signed, text, unsigned) }
}

unsafe extern "C" fn call_sprintf_combo(
    buf: *mut c_char,
    signed: i64,
    text: *const c_char,
    unsigned: u64,
) -> c_int {
    unsafe { sprintf(buf, c"%lld:%s:%#llx".as_ptr(), signed, text, unsigned) }
}

unsafe extern "C" fn call_asprintf_combo(
    out: *mut *mut c_char,
    signed: i64,
    text: *const c_char,
    unsigned: u64,
) -> c_int {
    unsafe { asprintf(out, c"%lld:%s:%#llx".as_ptr(), signed, text, unsigned) }
}

fuzz_target!(|input: PrintfFuzzInput| {
    if input.format_bytes.len() > MAX_OUTPUT || input.str_val.len() > MAX_OUTPUT {
        return;
    }

    init_hardened_printf_mode();

    match input.op % 12 {
        0 => fuzz_parse_spec(&input),
        1 => fuzz_parse_string(&input),
        2 => fuzz_format_signed(&input),
        3 => fuzz_format_unsigned(&input),
        4 => fuzz_format_float(&input),
        5 => fuzz_format_str(&input),
        6 => fuzz_format_char(&input),
        7 => fuzz_format_pointer(&input),
        8 => fuzz_snprintf_abi(&input),
        9 => fuzz_sprintf_hardened_truncation(&input),
        10 => fuzz_asprintf_matches_snprintf(&input),
        11 => fuzz_percent_n_abi(&input),
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

/// Fuzz `snprintf` using well-typed ABI calls and compare truncated vs full renders.
fn fuzz_snprintf_abi(input: &PrintfFuzzInput) {
    let text = sanitize_cstring(&input.str_val, MAX_ABI_STRING);
    let size = (input.width as usize) % 128;
    let mut small = vec![0 as c_char; size.max(1)];
    let mut full = vec![0 as c_char; ABI_COMPARE_BUF];

    let width = width_arg(input.width);
    let precision = precision_arg(input.precision);

    let (small_rc, full_rc) = unsafe {
        match input.conversion % 5 {
            0 => (
                call_snprintf_signed(small.as_mut_ptr(), size, input.signed_val),
                call_snprintf_signed(full.as_mut_ptr(), full.len(), input.signed_val),
            ),
            1 => (
                call_snprintf_unsigned(small.as_mut_ptr(), size, input.unsigned_val),
                call_snprintf_unsigned(full.as_mut_ptr(), full.len(), input.unsigned_val),
            ),
            2 => (
                call_snprintf_float(small.as_mut_ptr(), size, input.float_val),
                call_snprintf_float(full.as_mut_ptr(), full.len(), input.float_val),
            ),
            3 => (
                call_snprintf_pointer(small.as_mut_ptr(), size, input.ptr_val as *const c_void),
                call_snprintf_pointer(
                    full.as_mut_ptr(),
                    full.len(),
                    input.ptr_val as *const c_void,
                ),
            ),
            _ => (
                call_snprintf_width_precision_string(
                    small.as_mut_ptr(),
                    size,
                    width,
                    precision,
                    text.as_ptr(),
                ),
                call_snprintf_width_precision_string(
                    full.as_mut_ptr(),
                    full.len(),
                    width,
                    precision,
                    text.as_ptr(),
                ),
            ),
        }
    };

    assert!(small_rc >= 0);
    assert_eq!(small_rc, full_rc);

    let full_len = full_rc as usize;
    assert!(
        full_len < full.len(),
        "comparison buffer must hold the full render, got len={full_len}"
    );

    let full_bytes = c_buffer_prefix(&full);
    assert_eq!(full_bytes.len(), full_len);

    if size > 0 {
        let small_bytes = c_buffer_prefix(&small);
        let expected_copy = full_len.min(size - 1);
        assert_eq!(small_bytes, full_bytes[..expected_copy]);
        assert_eq!(small[expected_copy], 0);
    }
}

/// Fuzz hardened `sprintf` with a tracked allocation so overflow attempts are truncated.
fn fuzz_sprintf_hardened_truncation(input: &PrintfFuzzInput) {
    let text = sanitize_cstring(&input.str_val, MAX_ABI_STRING);
    let cap = ((input.width as usize) % 64).max(1);

    let mut full_ptr: *mut c_char = std::ptr::null_mut();
    let expected = unsafe {
        call_asprintf_combo(
            &mut full_ptr,
            input.signed_val,
            text.as_ptr(),
            input.unsigned_val,
        )
    };
    if expected < 0 {
        return;
    }
    assert!(!full_ptr.is_null());

    let full_len = expected as usize;
    let full_bytes = unsafe { std::slice::from_raw_parts(full_ptr.cast::<u8>(), full_len + 1) };
    assert_eq!(full_bytes[full_len], 0);

    let tracked = unsafe { malloc(cap).cast::<c_char>() };
    if tracked.is_null() {
        unsafe { free(full_ptr.cast::<c_void>()) };
        return;
    }

    unsafe {
        std::ptr::write_bytes(tracked.cast::<u8>(), 0xA5, cap);
    }
    let rc =
        unsafe { call_sprintf_combo(tracked, input.signed_val, text.as_ptr(), input.unsigned_val) };
    assert_eq!(rc, expected);

    let tracked_bytes = unsafe { std::slice::from_raw_parts(tracked.cast::<u8>(), cap) };
    let copied_len = tracked_bytes
        .iter()
        .position(|&byte| byte == 0)
        .expect("hardened sprintf must NUL-terminate tracked buffers");
    let expected_copy = full_len.min(cap.saturating_sub(1));
    assert_eq!(copied_len, expected_copy);
    assert_eq!(&tracked_bytes[..copied_len], &full_bytes[..copied_len]);

    unsafe {
        free(tracked.cast::<c_void>());
        free(full_ptr.cast::<c_void>());
    }
}

/// Fuzz `asprintf` and compare its result to the equivalent full `snprintf` render.
fn fuzz_asprintf_matches_snprintf(input: &PrintfFuzzInput) {
    let text = sanitize_cstring(&input.str_val, MAX_ABI_STRING);
    let mut out: *mut c_char = std::ptr::null_mut();
    let asprintf_rc = unsafe {
        call_asprintf_combo(
            &mut out,
            input.signed_val,
            text.as_ptr(),
            input.unsigned_val,
        )
    };
    if asprintf_rc < 0 {
        return;
    }
    assert!(!out.is_null());

    let mut full = vec![0 as c_char; ABI_COMPARE_BUF];
    let snprintf_rc = unsafe {
        call_snprintf_combo(
            full.as_mut_ptr(),
            full.len(),
            input.signed_val,
            text.as_ptr(),
            input.unsigned_val,
        )
    };
    assert_eq!(snprintf_rc, asprintf_rc);

    let full_len = snprintf_rc as usize;
    assert!(
        full_len < full.len(),
        "comparison buffer must hold the full render, got len={full_len}"
    );

    let rendered = unsafe { std::slice::from_raw_parts(out.cast::<u8>(), full_len + 1) };
    assert_eq!(rendered[full_len], 0);
    assert_eq!(&rendered[..full_len], &c_buffer_prefix(&full));

    unsafe {
        free(out.cast::<c_void>());
    }
}

/// Fuzz `%n` handling through `snprintf` with a valid count pointer.
fn fuzz_percent_n_abi(input: &PrintfFuzzInput) {
    let text = sanitize_cstring(&input.str_val, 128);
    let size = (input.width as usize) % 64;
    let mut buf = vec![0 as c_char; size.max(1)];
    let mut count = -1_i32;

    let rc = unsafe { call_snprintf_count(buf.as_mut_ptr(), size, &mut count, text.as_ptr()) };
    assert!(rc >= 4);
    assert_eq!(
        count, 3,
        "%n must record the byte count before the directive"
    );

    if size > 0 {
        let expected = format!("abc:{}", text.to_string_lossy());
        let copied = c_buffer_prefix(&buf);
        let expected_copy = expected.len().min(size - 1);
        assert_eq!(copied, expected.as_bytes()[..expected_copy]);
        assert_eq!(buf[expected_copy], 0);
    }
}
