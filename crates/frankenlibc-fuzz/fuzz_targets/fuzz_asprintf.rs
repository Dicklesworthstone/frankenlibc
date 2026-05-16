#![no_main]
//! Crash-detector / invariant fuzz target for FrankenLibC's asprintf.
//!
//! asprintf is a printf-family entry that allocates the output buffer
//! based on the format expansion. The pure-Rust formatter (used by
//! both asprintf and snprintf) is exercised against arbitrary format
//! strings + arg vectors. We don't diff against host glibc here —
//! that's the job of `tests/conformance_diff_asprintf.rs` — instead
//! we look for crashes, double-frees, and buffer-bound violations.
//!
//! ## Input layout
//!
//! The fuzzer fills five i32 args from the 24-byte legacy corpus header
//! plus a sanitized format string from the back of the buffer. Format
//! strings are constrained to safe specifiers so we don't trip undefined
//! behavior in the C-style variadic ABI.
//!
//! Filed under [bd-xn6p8] follow-up — fuzz coverage extension paired
//! with conformance_diff_asprintf.rs.

use std::ffi::{CString, c_char, c_int};

use frankenlibc_abi::stdio_abi::asprintf;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 256;
const MAX_FORMAT: usize = 128;
const MAX_ARGS: usize = 5;
const FMT_PREFIX: &[u8] = b"fmt:";

#[derive(Clone, Copy)]
struct FuzzArgs {
    a: i32,
    b: i32,
    c: i32,
    d: i32,
    e: i32,
}

struct SanitizedDirective {
    next: usize,
    bytes: Vec<u8>,
    arg_slots: usize,
}

fn sanitize_format(input: &[u8]) -> Vec<u8> {
    // Keep only printable ASCII excluding NUL. Rewrite directives that would
    // require pointer or floating-point variadic arguments to integer forms so
    // the harness can still explore width, precision, flags, and boundaries.
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    let mut used_args = 0;
    while i < input.len() && out.len() < MAX_FORMAT {
        let b = input[i];
        if !(0x20..=0x7E).contains(&b) {
            i += 1;
            continue;
        }
        if b == b'%' {
            let directive = sanitize_directive(input, i);
            let bytes = if used_args + directive.arg_slots <= MAX_ARGS {
                used_args += directive.arg_slots;
                directive.bytes.as_slice()
            } else {
                b"%%"
            };
            if out.len() + bytes.len() > MAX_FORMAT {
                break;
            }
            out.extend_from_slice(bytes);
            i = directive.next;
            continue;
        }
        out.push(b);
        i += 1;
    }
    out
}

fn sanitize_directive(input: &[u8], mut i: usize) -> SanitizedDirective {
    let mut bytes = vec![b'%'];
    let mut arg_slots = 0;
    i += 1;
    if i >= input.len() {
        return literal_percent(i);
    }
    if input[i] == b'%' {
        bytes.push(b'%');
        return SanitizedDirective {
            next: i + 1,
            bytes,
            arg_slots,
        };
    }

    while i < input.len() && is_printf_flag(input[i]) {
        bytes.push(input[i]);
        i += 1;
    }
    let width = copy_width_or_precision_number(input, i, &mut bytes);
    i = width.next;
    arg_slots += width.arg_slots;
    if i < input.len() && input[i] == b'.' {
        bytes.push(b'.');
        let precision = copy_width_or_precision_number(input, i + 1, &mut bytes);
        i = precision.next;
        arg_slots += precision.arg_slots;
    }
    i = skip_length_modifier(input, i);

    if i >= input.len() {
        return literal_percent(i);
    }
    let conv = input[i];
    bytes.push(safe_conversion(conv));
    arg_slots += 1;
    SanitizedDirective {
        next: i + 1,
        bytes,
        arg_slots,
    }
}

fn literal_percent(next: usize) -> SanitizedDirective {
    SanitizedDirective {
        next,
        bytes: b"%%".to_vec(),
        arg_slots: 0,
    }
}

struct WidthOrPrecision {
    next: usize,
    arg_slots: usize,
}

fn copy_width_or_precision_number(
    input: &[u8],
    mut i: usize,
    out: &mut Vec<u8>,
) -> WidthOrPrecision {
    if i < input.len() && input[i] == b'*' {
        out.push(b'*');
        return WidthOrPrecision {
            next: i + 1,
            arg_slots: 1,
        };
    }
    while i < input.len() && input[i].is_ascii_digit() {
        out.push(input[i]);
        i += 1;
    }
    WidthOrPrecision {
        next: i,
        arg_slots: 0,
    }
}

fn skip_length_modifier(input: &[u8], mut i: usize) -> usize {
    while i < input.len() {
        match input[i] {
            b'h' | b'l' | b'j' | b'z' | b't' | b'L' | b'q' => i += 1,
            _ => break,
        }
    }
    i
}

fn safe_conversion(conv: u8) -> u8 {
    match conv {
        b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'c' => conv,
        _ => b'd',
    }
}

fn is_printf_flag(byte: u8) -> bool {
    matches!(byte, b'#' | b'0' | b'-' | b' ' | b'+' | b'\'')
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }

    if let Some(format) = directed_format_seed(data) {
        fuzz_format(format, directed_args());
        return;
    }

    if data.len() < 24 {
        return;
    }
    let args = args_from_header(data);
    fuzz_format(&data[24..], args);
});

fn directed_format_seed(data: &[u8]) -> Option<&[u8]> {
    let payload = data.strip_prefix(FMT_PREFIX)?;
    Some(payload.strip_suffix(b"\n").unwrap_or(payload))
}

fn directed_args() -> FuzzArgs {
    FuzzArgs {
        a: 12,
        b: -34,
        c: 0,
        d: i32::MIN,
        e: 0x5eed_1234,
    }
}

fn args_from_header(data: &[u8]) -> FuzzArgs {
    FuzzArgs {
        a: i32::from_le_bytes([data[0], data[1], data[2], data[3]]),
        b: i32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        c: i32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        d: i32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        e: i32::from_le_bytes([data[16], data[17], data[18], data[19]]),
    }
}

fn fuzz_format(input: &[u8], args: FuzzArgs) {
    let fmt_bytes = sanitize_format(input);
    let Ok(fmt) = CString::new(fmt_bytes) else {
        return;
    };

    let mut p: *mut c_char = std::ptr::null_mut();
    let n = unsafe { asprintf(&mut p, fmt.as_ptr(), args.a, args.b, args.c, args.d, args.e) };

    // Invariants:
    //   - n >= -1 always
    //   - if n >= 0, p must be non-NULL and the strlen of p must equal n
    //   - if n < 0, p stays NULL (or points to a buffer we still need to free)
    assert!(n >= -1, "asprintf returned out-of-range value {n}");
    if n >= 0 {
        assert!(!p.is_null(), "asprintf returned {n} with NULL ptr");
        let written = unsafe { libc::strlen(p) };
        assert_eq!(
            written as c_int, n,
            "asprintf: strlen={} but returned {n}",
            written
        );
    }
    if !p.is_null() {
        unsafe { libc::free(p as *mut libc::c_void) };
    }
}
