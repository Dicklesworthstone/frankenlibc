#![no_main]
//! Crash-detector + invariant fuzz target for FrankenLibC strftime.
//!
//! strftime is a format-string parser like printf — ~50 conversion
//! specifiers, flags (`-`, `_`, `0`, `^`, `#`), width digits, length
//! modifiers (`E`, `O`), and locale-sensitive output. The pure-Rust
//! engine `frankenlibc_core::time::format_strftime` accepts arbitrary
//! bytes and writes into a caller-provided buffer.
//!
//! Differential against libc::strftime is brittle (locale state), so
//! we fuzz crash-detector + buffer-bound invariants instead. A future
//! pass can add a host-parity differential when locale handling is
//! pinned.
//!
//! Bead: bd-7rxtm

use arbitrary::Arbitrary;
use frankenlibc_core::time::{BrokenDownTime, format_strftime};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct StrftimeFuzzInput {
    fmt: Vec<u8>,
    buf_size: u16,
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
}

fuzz_target!(|input: StrftimeFuzzInput| {
    // Cap inputs — strftime is O(n) on the format string but
    // pathological format sequences can stress the parser. 4 KiB
    // exercises every state, and the buffer cap keeps allocations
    // cheap.
    if input.fmt.len() > 4096 {
        return;
    }
    let buf_size = (input.buf_size as usize).min(8192).max(1);

    let bd = BrokenDownTime {
        tm_sec: input.tm_sec,
        tm_min: input.tm_min,
        tm_hour: input.tm_hour,
        tm_mday: input.tm_mday,
        tm_mon: input.tm_mon,
        tm_year: input.tm_year,
        tm_wday: input.tm_wday,
        tm_yday: input.tm_yday,
        tm_isdst: input.tm_isdst,
    };

    let mut buf = vec![0u8; buf_size];
    let written = format_strftime(&input.fmt, &bd, &mut buf);

    // Buffer-bound invariant: must never report writing more bytes
    // than the buffer holds (a leaked overrun would corrupt the
    // caller's stack/heap).
    assert!(
        written <= buf_size,
        "format_strftime returned {written} bytes for {buf_size}-byte buffer"
    );

    // Determinism: a second call with the same input must produce the
    // same output. Catches state leakage (TLS, statics) and races in
    // shared resources.
    let mut buf2 = vec![0u8; buf_size];
    let written2 = format_strftime(&input.fmt, &bd, &mut buf2);
    assert_eq!(
        written, written2,
        "format_strftime is non-deterministic on bytes count"
    );
    assert_eq!(
        buf[..written],
        buf2[..written],
        "format_strftime is non-deterministic on output bytes"
    );
});
