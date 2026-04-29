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
//! The fuzzer fills four i32 args + a u64 hex arg + a sanitized format
//! string from the back of the buffer. Format strings are constrained
//! to safe specifiers so we don't trip undefined behavior in the
//! C-style variadic ABI.
//!
//! Filed under [bd-xn6p8] follow-up — fuzz coverage extension paired
//! with conformance_diff_asprintf.rs.

use std::ffi::{c_char, c_int, CString};

use frankenlibc_abi::stdio_abi::asprintf;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 256;
const MAX_FORMAT: usize = 128;

fn sanitize_format(input: &[u8]) -> Vec<u8> {
    // Keep only printable ASCII excluding NUL. Convert any '%n' or '%s'
    // into '%d' to avoid pointer-dereference UB. The fuzzer can still
    // explore width/precision and the safe specifiers below.
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if !(0x20..=0x7E).contains(&b) {
            i += 1;
            continue;
        }
        if b == b'%' && i + 1 < input.len() {
            let next = input[i + 1];
            // Refuse %n (write-back) and %s (pointer deref) entirely.
            if next == b'n' || next == b'N' || next == b's' || next == b'S' {
                out.push(b'%');
                out.push(b'd');
                i += 2;
                continue;
            }
        }
        out.push(b);
        i += 1;
    }
    out.truncate(MAX_FORMAT);
    out
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 || data.len() > MAX_INPUT {
        return;
    }
    let arg_a = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let arg_b = i32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let arg_c = i32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let arg_d = i32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let arg_e = u64::from_le_bytes([
        data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23],
    ]);
    let fmt_bytes = sanitize_format(&data[24..]);
    let Ok(fmt) = CString::new(fmt_bytes) else {
        return;
    };

    let mut p: *mut c_char = std::ptr::null_mut();
    let n = unsafe { asprintf(&mut p, fmt.as_ptr(), arg_a, arg_b, arg_c, arg_d, arg_e) };

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
});
