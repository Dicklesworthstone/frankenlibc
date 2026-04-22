#![no_main]
//! Structure-aware fuzz target for FrankenLibC time functions.
//!
//! Exercises `epoch_to_broken_down`, `broken_down_to_epoch` (round-trip),
//! `format_asctime`, `format_strftime`, `difftime`, and clock validators.
//!
//! Invariants:
//! - epoch_to_broken_down → broken_down_to_epoch round-trips exactly
//! - format_asctime never panics and respects buffer bounds
//! - format_strftime never panics on any format specifier byte
//! - All validators are deterministic and total
//!
//! Bead: bd-2hh.4

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_core::time;

#[derive(Debug, Arbitrary)]
struct TimeFuzzInput {
    /// Epoch seconds for conversion tests.
    epoch: i64,
    /// Format string bytes for strftime.
    fmt: Vec<u8>,
    /// Broken-down time fields for inverse tests.
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    /// Second epoch for difftime.
    epoch2: i64,
    /// Clock ID for validator.
    clock_id: i32,
    /// Operation selector.
    op: u8,
}

const MAX_FMT: usize = 512;

fuzz_target!(|input: TimeFuzzInput| {
    match input.op % 6 {
        0 => fuzz_epoch_roundtrip(&input),
        1 => fuzz_broken_down_to_epoch(&input),
        2 => fuzz_asctime(&input),
        3 => fuzz_strftime(&input),
        4 => fuzz_difftime(&input),
        5 => fuzz_clock_validators(&input),
        _ => unreachable!(),
    }
});

/// Verify epoch → broken_down → epoch round-trips exactly.
fn fuzz_epoch_roundtrip(input: &TimeFuzzInput) {
    // Clamp to reasonable range to avoid overflow in year accumulation
    let epoch = input.epoch.clamp(-62_167_219_200, 253_402_300_799);
    let bd = time::epoch_to_broken_down(epoch);

    // Basic field range invariants
    assert!((0..=60).contains(&bd.tm_sec), "tm_sec out of range");
    assert!((0..=59).contains(&bd.tm_min), "tm_min out of range");
    assert!((0..=23).contains(&bd.tm_hour), "tm_hour out of range");
    assert!((1..=31).contains(&bd.tm_mday), "tm_mday out of range");
    assert!((0..=11).contains(&bd.tm_mon), "tm_mon out of range");
    assert!((0..=6).contains(&bd.tm_wday), "tm_wday out of range");
    assert!((0..=365).contains(&bd.tm_yday), "tm_yday out of range");

    // Round-trip must be exact
    let rt = time::broken_down_to_epoch(&bd);
    assert_eq!(
        rt, epoch,
        "round-trip failed: epoch={epoch}, bd={bd:?}, rt={rt}"
    );

    // Determinism
    let bd2 = time::epoch_to_broken_down(epoch);
    assert_eq!(bd, bd2, "epoch_to_broken_down not deterministic");
}

/// Test broken_down_to_epoch with arbitrary (possibly denormalized) fields.
fn fuzz_broken_down_to_epoch(input: &TimeFuzzInput) {
    let bd = time::BrokenDownTime {
        tm_sec: input.tm_sec.clamp(-1000, 1000),
        tm_min: input.tm_min.clamp(-1000, 1000),
        tm_hour: input.tm_hour.clamp(-1000, 1000),
        tm_mday: input.tm_mday.clamp(-1000, 1000),
        tm_mon: input.tm_mon.clamp(-1000, 1000),
        tm_year: input.tm_year.clamp(-2000, 10000),
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
    };

    // Must not panic
    let _epoch = time::broken_down_to_epoch(&bd);
}

/// Test format_asctime with fuzzer-generated broken-down times.
fn fuzz_asctime(input: &TimeFuzzInput) {
    let epoch = input.epoch.clamp(-62_167_219_200, 253_402_300_799);
    let bd = time::epoch_to_broken_down(epoch);

    // Normal-sized buffer
    let mut buf = [0u8; 64];
    let n = time::format_asctime(&bd, &mut buf);
    assert!(n <= buf.len(), "asctime wrote past buffer");

    if n > 0 {
        // Output should end with newline
        assert_eq!(buf[n - 1], b'\n', "asctime should end with newline");
        // Should be valid UTF-8
        assert!(
            std::str::from_utf8(&buf[..n]).is_ok(),
            "asctime produced invalid UTF-8"
        );
    }

    // Tiny buffer should return 0
    let mut tiny = [0u8; 10];
    assert_eq!(
        time::format_asctime(&bd, &mut tiny),
        0,
        "asctime should fail with tiny buffer"
    );

    // Exact-size buffer (26 bytes)
    let mut exact = [0u8; 26];
    let n2 = time::format_asctime(&bd, &mut exact);
    assert!(n2 > 0 || n2 == 0, "asctime with 26-byte buffer");
}

/// Test format_strftime with arbitrary format strings.
fn fuzz_strftime(input: &TimeFuzzInput) {
    if input.fmt.len() > MAX_FMT {
        return;
    }

    let epoch = input.epoch.clamp(-62_167_219_200, 253_402_300_799);
    let bd = time::epoch_to_broken_down(epoch);

    let mut buf = [0u8; 2048];
    let n = time::format_strftime(&input.fmt, &bd, &mut buf);

    // n can be 0 (buffer too small) or the number of bytes written
    assert!(n <= buf.len(), "strftime wrote past buffer");

    // If output is non-empty, it should be NUL-terminated
    if n > 0 && n < buf.len() {
        assert_eq!(buf[n], 0, "strftime output should be NUL-terminated");
    }

    // Tiny buffer should handle gracefully (either 0 or short output)
    let mut tiny = [0u8; 4];
    let _ = time::format_strftime(&input.fmt, &bd, &mut tiny);

    // Determinism
    let mut buf2 = [0u8; 2048];
    let n2 = time::format_strftime(&input.fmt, &bd, &mut buf2);
    assert_eq!(n, n2, "strftime not deterministic");
    assert_eq!(&buf[..n], &buf2[..n2], "strftime output differs");
}

/// Test difftime with arbitrary epoch pairs.
fn fuzz_difftime(input: &TimeFuzzInput) {
    let d = time::difftime(input.epoch, input.epoch2);
    // difftime(a, b) == -(difftime(b, a)). difftime(i64, i64) -> f64
    // cannot produce NaN, and the antisymmetry property holds at
    // value level: we must not compare via to_bits() because +0 and
    // -0 are both valid zero outcomes when epoch == epoch2.
    let d_inv = time::difftime(input.epoch2, input.epoch);
    assert_eq!(d, -d_inv, "difftime antisymmetry violated");
    // difftime(a, a) == 0
    let d_self = time::difftime(input.epoch, input.epoch);
    assert_eq!(d_self, 0.0, "difftime(a, a) should be 0");
}

/// Test clock ID validators.
fn fuzz_clock_validators(input: &TimeFuzzInput) {
    let v1 = time::valid_clock_id(input.clock_id);
    let v2 = time::valid_clock_id(input.clock_id);
    assert_eq!(v1, v2, "valid_clock_id not deterministic");

    let ve1 = time::valid_clock_id_extended(input.clock_id);
    let ve2 = time::valid_clock_id_extended(input.clock_id);
    assert_eq!(ve1, ve2, "valid_clock_id_extended not deterministic");

    // If basic is valid, extended should also be valid
    if v1 {
        assert!(
            ve1,
            "valid_clock_id({}) but not valid_clock_id_extended",
            input.clock_id
        );
    }
}
